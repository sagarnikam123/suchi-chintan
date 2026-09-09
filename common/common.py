"""
Common utilities for AWS inventory scripts.
Handles account loading, session creation, region discovery, and output management.
"""

import os
import sys
import json
import time
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

import yaml
import boto3
import botocore.exceptions
from botocore.config import Config

# Boto3 client config with timeouts
BOTO_CONFIG = Config(
    connect_timeout=5,
    read_timeout=30,
    retries={'max_attempts': 1}
)

# Paths
ROOT_DIR = Path(__file__).parent.parent
ACCOUNTS_FILE = ROOT_DIR / "conf" / "accounts.yaml"
OUTPUT_DIR = ROOT_DIR / "output"

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
# Silence internal third-party logs (credential discovery, connection pooling)
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

logger = logging.getLogger(__name__)


def load_accounts(accounts_file: Path = ACCOUNTS_FILE) -> Dict[str, Any]:
    """Load account registry from YAML."""
    if not accounts_file.exists():
        logger.error(f"Accounts file not found: {accounts_file}")
        sys.exit(1)

    with open(accounts_file) as f:
        config = yaml.safe_load(f)

    return config


def get_accounts(filter_account: Optional[str] = None) -> List[Dict[str, str]]:
    """Get account list, optionally filtered by account_id or name."""
    config = load_accounts()
    accounts = config.get("accounts", [])

    if filter_account:
        accounts = [
            a for a in accounts
            if filter_account in (a["account_id"], a["name"], a["profile"])
        ]
        if not accounts:
            logger.error(f"Account '{filter_account}' not found in accounts.yaml")
            sys.exit(1)

    return accounts


_ENABLED_REGIONS = None


def get_enabled_regions(session: Optional[boto3.Session] = None) -> List[str]:
    """Get list of active/enabled AWS regions for the current environment."""
    global _ENABLED_REGIONS
    if _ENABLED_REGIONS is not None and not session:
        return _ENABLED_REGIONS

    sess = session or boto3.Session()

    try:
        ec2 = sess.client('ec2', region_name='us-east-1', config=BOTO_CONFIG)
        response = ec2.describe_regions(AllRegions=False)
        regions = [r['RegionName'] for r in response.get('Regions', [])]
        if regions:
            if not session:
                _ENABLED_REGIONS = regions
            return regions
    except Exception:
        pass

    # Fallback to accounts.yaml static list if present
    try:
        config = load_accounts()
        cfg_regions = config.get("regions")
        if cfg_regions:
            _ENABLED_REGIONS = cfg_regions
            return _ENABLED_REGIONS
    except Exception:
        pass

    # Fallback to all standard AWS commercial regions via boto3 data model (offline, no auth needed)
    try:
        available = sess.get_available_regions('ec2')
        if available:
            _ENABLED_REGIONS = available
            return available
    except Exception:
        pass

    _ENABLED_REGIONS = ["us-east-1"]
    return _ENABLED_REGIONS


def get_regions(service: str = None, session: Optional[boto3.Session] = None) -> List[str]:
    """Get regions to scan.
    If service is provided, returns available regions where that service is supported.
    Otherwise returns all active AWS regions."""
    sess = session or boto3.Session()

    if service:
        try:
            available = sess.get_available_regions(service)
            if available:
                return available
        except Exception:
            pass

    return get_enabled_regions(sess)


def _validate_profile_exists(profile: str) -> bool:
    """Check if AWS profile exists in ~/.aws/credentials or ~/.aws/config."""
    # ponytail: let boto3 handle profile resolution — it checks both files,
    # supports SSO profiles, and raises ProfileNotFound with a clear message.
    # Manual configparser parsing breaks on SSO config format in Python 3.14+.
    return True


def create_session(profile: str) -> Optional[boto3.Session]:
    """Create a boto3 session for the given profile.
    Validates profile exists in ~/.aws/credentials first — stops if not found."""
    if not _validate_profile_exists(profile):
        return None

    try:
        session = boto3.Session(profile_name=profile)
        # Validate credentials via STS
        sts = session.client('sts', config=BOTO_CONFIG)
        identity = sts.get_caller_identity()
        logger.info(f"✅ Authenticated as {identity['Arn']} (Account: {identity['Account']})")
        return session
    except botocore.exceptions.ProfileNotFound:
        logger.error(f"❌ Profile '{profile}' not found in ~/.aws/config")
        return None
    except botocore.exceptions.ClientError as e:
        logger.error(f"❌ Auth failed for profile '{profile}': {e}")
        return None
    except Exception as e:
        logger.error(f"❌ Session creation failed for '{profile}': {e}")
        return None


def get_output_dir(account_id: str, service: str) -> Path:
    """Get output directory for a specific account and service. Creates if needed."""
    output_path = OUTPUT_DIR / account_id / service
    output_path.mkdir(parents=True, exist_ok=True)
    return output_path


def make_output_filename(service: str, account_id: str, timestamp: str) -> str:
    """Build a standard output filename with account ID embedded.
    Example: cost-inventory-111111111111-20260827-160839.json"""
    return f"{service}-inventory-{account_id}-{timestamp}.json"


def save_json(data: Any, output_path: Path, filename: str) -> Path:
    """Save data as JSON file. Returns the file path."""
    filepath = output_path / filename
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2, default=str)
    logger.info(f"📄 Saved: {filepath}")
    return filepath


class IncrementalWriter:
    """Writes inventory data incrementally — per region or per account — so nothing is lost on crash."""

    def __init__(self, output_path: Path, filename: str):
        self.filepath = output_path / filename
        output_path.mkdir(parents=True, exist_ok=True)
        self.data = {}

    def update(self, data: dict):
        """Merge new data into the inventory and flush to disk immediately."""
        self._deep_merge(self.data, data)
        self._flush()

    def set(self, key: str, value: Any):
        """Set a top-level key and flush."""
        self.data[key] = value
        self._flush()

    def set_nested(self, *keys, value: Any):
        """Set a nested key path and flush. E.g. set_nested('accounts', '12345', 'regions', 'us-east-1', value=[...])"""
        d = self.data
        for key in keys[:-1]:
            if key not in d:
                d[key] = {}
            d = d[key]
        d[keys[-1]] = value
        self._flush()

    def get_data(self) -> dict:
        """Return current accumulated data."""
        return self.data

    def _flush(self):
        """Write current state to disk."""
        with open(self.filepath, 'w') as f:
            json.dump(self.data, f, indent=2, default=str)

    def _deep_merge(self, base: dict, override: dict):
        """Recursively merge override into base."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value


def get_timestamp() -> str:
    """Get current timestamp for filenames."""
    return time.strftime("%Y%m%d-%H%M%S")


def get_disabled_regions(session: boto3.Session) -> List[str]:
    """Get regions that are disabled for the account."""
    try:
        account_client = session.client('account', config=BOTO_CONFIG)
        response = account_client.list_regions()
        disabled = [
            r['RegionName'] for r in response['Regions']
            if r['RegionOptStatus'] == 'DISABLED'
        ]
        return disabled
    except Exception as e:
        logger.warning(f"Could not check region status: {e}")
        return []


def create_session_with_identity(profile: str) -> tuple:
    """Create a session from a raw profile and return (session, account_id, arn).
    Auto-detects account ID via STS — no accounts.yaml lookup needed.
    Validates profile exists in ~/.aws/credentials first — stops if not found."""
    if not _validate_profile_exists(profile):
        return None, None, None

    try:
        session = boto3.Session(profile_name=profile)
        sts = session.client('sts', config=BOTO_CONFIG)
        identity = sts.get_caller_identity()
        account_id = identity['Account']
        arn = identity['Arn']
        logger.info(f"✅ Authenticated as {arn} (Account: {account_id})")
        return session, account_id, arn
    except Exception as e:
        logger.error(f"❌ Auth failed for profile '{profile}': {e}")
        return None, None, None


def add_common_args(parser):
    """Add common CLI arguments and default standalone scans to AWS [default]."""
    parser.add_argument(
        '--account', '-a',
        help='Filter to specific account (ID, name, or profile) from accounts.yaml. Omit to scan all.',
        default=None
    )
    parser.add_argument(
        '--profile', '-p',
        help='Use a specific AWS profile directly (bypasses accounts.yaml). Account ID auto-detected via STS.',
        default=None
    )
    parser.add_argument(
        '--region', '-r',
        help='Filter to specific region. Omit to scan all available regions for the service.',
        default=None
    )
    parser.add_argument(
        '--output-dir', '-o',
        help='Custom output directory (default: ./output/<account_id>/<service>)',
        default=None
    )

    # ponytail: one shared parse hook avoids 73 duplicate defaulting blocks;
    # --account remains the explicit accounts.yaml/multi-account path.
    original_parse_args = parser.parse_args

    def parse_args(args=None, namespace=None):
        parsed = original_parse_args(args, namespace)
        if parsed.profile is None and parsed.account is None:
            parsed.profile = os.environ.get('AWS_PROFILE') or 'default'
        return parsed

    parser.parse_args = parse_args
    return parser


def is_region_unsupported_error(error) -> bool:
    """Check if an AWS error indicates the region doesn't support the service."""
    error_str = str(error)
    unsupported_indicators = [
        "UnrecognizedClientException",
        "InvalidClientTokenId",
        "AuthFailure",
        "OptInRequired",
        "not available in this region",
        "Could not connect to the endpoint URL",
        "EndpointConnectionError",
        "Connect timeout on endpoint URL",
        "ConnectTimeoutError",
        "Unrecognized engine name",
        "UnknownOperationException",
        "SubscriptionRequiredException",
        "FeatureNotSupportedException",
    ]
    return any(indicator in error_str for indicator in unsupported_indicators)


def log_region_skip(region: str, service: str, error: str = None):
    """Log that a region is being skipped for a service."""
    if error:
        logger.debug(f"  ⏭️  {region}: {service} not supported — {error[:80]}")
    else:
        logger.debug(f"  ⏭️  {region}: {service} not supported")


def scan_regions_parallel(session, regions, writer, scan_region_fn,
                          log_fn=None, max_workers=8):
    """Run scan_region_fn(session, region) across regions in parallel.

    scan_region_fn must return (region_data: dict|list, counts: dict).
    Empty region_data (falsy) is skipped. Per-region results are flushed
    to writer.set_nested('regions', region, ...) as each future completes
    (crash-safe). Returns aggregated totals dict summed across all counts.

    log_fn(region, counts) -> optional custom per-region log line.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    totals = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_region_fn, session, r): r for r in regions}
        for future in as_completed(futures):
            region = futures[future]
            try:
                region_data, counts = future.result()
            except Exception as e:
                logger.warning(f"  {region}: worker error — {e}")
                continue

            for k, v in (counts or {}).items():
                totals[k] = totals.get(k, 0) + v

            if region_data:
                writer.set_nested('regions', region, value=region_data)
                if log_fn:
                    log_fn(region, counts)
                else:
                    summary = ", ".join(f"{v} {k}" for k, v in counts.items() if v)
                    if summary:
                        logger.info(f"  {region}: {summary}")
    return totals


def format_elapsed(seconds: float) -> str:
    """Format elapsed seconds into a human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        m, s = divmod(int(seconds), 60)
        return f"{m}m {s}s"
    else:
        h, rem = divmod(int(seconds), 3600)
        m, s = divmod(rem, 60)
        return f"{h}h {m}m {s}s"


# ============================================================
# AWS Pricing API — live list prices (cached)
# ============================================================

# Pricing API only has endpoints in us-east-1 and ap-south-1
_PRICING_ENDPOINT_REGION = "us-east-1"
# Module-level cache: {(service_code, cache_key): price_float}
_PRICE_CACHE = {}
_pricing_client = None


def _get_pricing_client(session: boto3.Session):
    """Lazily create a shared pricing client (cached per process)."""
    global _pricing_client
    if _pricing_client is None:
        _pricing_client = session.client('pricing', region_name=_PRICING_ENDPOINT_REGION, config=BOTO_CONFIG)
    return _pricing_client


def _extract_price(price_list_item: str) -> Optional[float]:
    """Pull the USD OnDemand price from a Pricing API PriceList JSON string."""
    try:
        data = json.loads(price_list_item)
        on_demand = data.get("terms", {}).get("OnDemand", {})
        for term in on_demand.values():
            for dim in term.get("priceDimensions", {}).values():
                usd = dim.get("pricePerUnit", {}).get("USD")
                if usd is not None:
                    return float(usd)
    except Exception:
        pass
    return None


def get_price(session: boto3.Session, service_code: str, filters: List[Dict[str, str]],
              cache_key: str = None) -> Optional[float]:
    """Query the AWS Pricing API for the OnDemand USD price of a resource.

    Returns price per unit (e.g. per GB-month, per hour) or None if unavailable.
    Results are cached per process to avoid repeat calls.

    filters: list of {"Field": ..., "Value": ...} — combined as TERM_MATCH.
    cache_key: optional explicit cache key; defaults to service+filter values.
    """
    if cache_key is None:
        cache_key = service_code + "|" + "|".join(f"{f['Field']}={f['Value']}" for f in filters)

    if cache_key in _PRICE_CACHE:
        return _PRICE_CACHE[cache_key]

    try:
        client = _get_pricing_client(session)
        api_filters = [{"Type": "TERM_MATCH", "Field": f["Field"], "Value": f["Value"]} for f in filters]
        resp = client.get_products(ServiceCode=service_code, Filters=api_filters, MaxResults=1)
        price_list = resp.get("PriceList", [])
        price = _extract_price(price_list[0]) if price_list else None
    except Exception:
        price = None

    _PRICE_CACHE[cache_key] = price
    return price


def get_ebs_gb_month_price(session, region: str, volume_type: str = "gp3") -> Optional[float]:
    """Price per GB-month for an EBS volume type in a region."""
    return get_price(session, "AmazonEC2", [
        {"Field": "productFamily", "Value": "Storage"},
        {"Field": "volumeApiName", "Value": volume_type},
        {"Field": "regionCode", "Value": region},
    ])


def get_ec2_hourly_price(session, region: str, instance_type: str,
                         os: str = "Linux") -> Optional[float]:
    """On-Demand hourly price for an EC2 instance type in a region (shared tenancy)."""
    return get_price(session, "AmazonEC2", [
        {"Field": "instanceType", "Value": instance_type},
        {"Field": "regionCode", "Value": region},
        {"Field": "operatingSystem", "Value": os},
        {"Field": "tenancy", "Value": "Shared"},
        {"Field": "preInstalledSw", "Value": "NA"},
        {"Field": "capacitystatus", "Value": "Used"},
    ])


def run_with_timer(main_func):
    """Wrap a main() function with elapsed time logging."""
    start = time.time()
    success = False
    skip_log = False
    try:
        main_func()
        success = True
    except SystemExit as e:
        if e.code is None or e.code == 0:
            skip_log = True
        raise
    finally:
        if not skip_log:
            elapsed = time.time() - start
            script_name = Path(sys.argv[0]).name
            status = "completed" if success else "failed after"
            logger.info(f"⏱️  {script_name} {status} {format_elapsed(elapsed)}")
