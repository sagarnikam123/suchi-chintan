#!/usr/bin/env python3
"""
AWS Resource Audit Tool — Security, Cost, Reliability & Drift
Reads inventory JSONs and produces a comprehensive findings report.

Categories:
  🔒 SECURITY      — Exposed resources, missing encryption, stale credentials
  💰 COST          — Waste, idle resources, over-provisioning
  ⚙️ RELIABILITY   — Single points of failure, missing backups, outdated versions
  🧹 DRIFT/HYGIENE — Untagged resources, disabled rules, misconfiguration

Usage:
    python tools/audit_aws_resources.py                                 # audit all accounts in output/
    python tools/audit_aws_resources.py -a 111111111111                 # specific account
    python tools/audit_aws_resources.py --days 90                       # staleness threshold
    python tools/audit_aws_resources.py --category security             # filter by category
    python tools/audit_aws_resources.py --json                          # JSON to stdout
    python tools/audit_aws_resources.py -a 111111111111 --live-pricing -p myprofile
                                                                        # real Pricing API cost rates
"""

import sys
import re
import csv
import json
import glob
import argparse
from pathlib import Path
from datetime import datetime, timezone, timedelta

ROOT_DIR = Path(__file__).parent.parent
OUTPUT_DIR = ROOT_DIR / "output"

# Make `common` importable whether run as a script or imported as a library.
sys.path.insert(0, str(ROOT_DIR))

# Lambda runtimes that are deprecated/EOL
DEPRECATED_RUNTIMES = {
    "python2.7", "python3.6", "python3.7", "python3.8", "python3.9",
    "nodejs10.x", "nodejs12.x", "nodejs14.x", "nodejs16.x", "nodejs18.x",
    "dotnetcore2.1", "dotnetcore3.1", "dotnet5.0", "dotnet6",
    "ruby2.5", "ruby2.7", "ruby3.1",
    "java8", "java8.al2", "go1.x",
}

# EKS versions considered outdated. ponytail: hardcoded floor — AWS drops
# ~3 versions/yr. Upgrade path: bump this as older versions leave standard support.
EKS_MIN_SUPPORTED = "1.30"

# AWS opt-in (disabled-by-default) regions. A regional security service being
# "not enabled" here is expected, not a finding — the account never opted in.
# ponytail: static list; AWS adds ~1-2/yr. Upgrade path: append new opt-in
# regions, or switch to account.describe_regions(AllRegions filter) if this drifts.
OPT_IN_REGIONS = {
    "af-south-1", "ap-east-1", "ap-east-2", "ap-south-2",
    "ap-southeast-3", "ap-southeast-4", "ap-southeast-5", "ap-southeast-6", "ap-southeast-7",
    "ca-west-1", "eu-central-2", "eu-south-1", "eu-south-2",
    "il-central-1", "me-central-1", "me-south-1", "mx-central-1",
}


def find_latest_inventory(account_dir, service):
    """Find the most recent inventory JSON for a service, resilient to directory naming."""
    patterns = [
        account_dir / service / f"{service}-inventory-*.json",
        account_dir / f"{service}s" / f"{service}-inventory-*.json",
        account_dir / service.rstrip('s') / f"{service.rstrip('s')}-inventory-*.json",
        account_dir / f"{service}s" / f"{service.rstrip('s')}-inventory-*.json",
        account_dir / service / f"{service}-*.json",
        account_dir / service / "*.json",
        account_dir / f"{service}s" / "*.json",
    ]
    for p in patterns:
        files = sorted(glob.glob(str(p)), key=lambda f: Path(f).stat().st_mtime, reverse=True)
        if files:
            return files[0]
    return None


def load_json(path):
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception as error:
        print(f"WARNING: could not load inventory {path}: {error}", file=sys.stderr)
        return None
    if not isinstance(data, dict):
        print(f"WARNING: ignoring inventory {path}: top-level JSON must be an object", file=sys.stderr)
        return None
    return data


def parse_timestamp(ts):
    if not ts:
        return None
    if isinstance(ts, (int, float)):
        if ts > 1e12:
            ts = ts / 1000
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except (OverflowError, OSError, TypeError, ValueError):
            return None
    if isinstance(ts, str):
        # fromisoformat handles both 'T' and space separators, microseconds,
        # and colon tz offsets (+05:30) — covers most boto3 str timestamps.
        try:
            dt = datetime.fromisoformat(ts)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
        for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S%z",
                    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(ts, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue
    return None


def _as_number(value, default=0):
    """Normalize numeric inventory fields without aborting an account audit."""
    try:
        return float(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def is_stale(ts, days_threshold):
    dt = parse_timestamp(ts)
    if not dt:
        return False
    return (datetime.now(timezone.utc) - dt) > timedelta(days=days_threshold)


def days_ago(ts):
    dt = parse_timestamp(ts)
    if not dt:
        return None
    return (datetime.now(timezone.utc) - dt).days


def days_until(ts):
    dt = parse_timestamp(ts)
    if not dt:
        return None
    return (dt - datetime.now(timezone.utc)).days


def _derive_default_action(category: str, service: str, issue: str) -> str:
    """Intelligently suggest a concrete remediation action based on issue context."""
    issue_lower = issue.lower()

    if category == "security":
        if "public ip" in issue_lower:
            return "Remove public IP or migrate instance to private subnet behind ALB/NAT"
        if "rotation" in issue_lower or service == "Secrets Manager":
            return "Enable automatic secret rotation (30-90 days) or rotate credential immediately"
        if "plaintext" in issue_lower or "securestring" in issue_lower or service == "SSM":
            return "Delete plaintext parameter and recreate as SecureString encrypted with KMS"
        if "unencrypted" in issue_lower or "encryption" in issue_lower:
            return "Enable AWS KMS encryption at rest using a Customer Managed Key (CMK)"
        if "public" in issue_lower:
            return "Enable S3 Block Public Access / remove public resource policies"
        if "mfa" in issue_lower:
            return "Enforce MFA for user in IAM policy"
        if "access key" in issue_lower or "stale" in issue_lower:
            return "Deactivate and delete inactive/unused IAM access keys"
        if "waf" in issue_lower:
            return "Associate an AWS WAF WebACL to protect against Layer 7 exploits"
        if "tls" in issue_lower:
            return "Update TLS security policy to TLSv1.2 or higher"
        return "Review IAM / resource policies and apply least-privilege configuration"

    elif category == "cost":
        if "eip" in issue_lower or service == "Elastic IP" or "unassociated" in issue_lower:
            return "Release unassociated Elastic IP in VPC console (saves $3.65/mo per IP immediately)"
        if "mwaa" in service.lower() or "airflow" in issue_lower:
            return "Verify DAG activity and delete idle Airflow environment if unused (saves ~$360/mo each)"
        if "elasticache" in service.lower() or "redis" in issue_lower:
            return "Decommission old/unused ElastiCache cluster or right-size node type (saves ~$50/mo each)"
        if "nat gateway" in service.lower() or "nat gateway" in issue_lower:
            return "Consolidate into shared VPC NAT or replace with Gateway VPC Endpoints for S3/DynamoDB (saves $32/mo each)"
        if "unattached" in issue_lower or "available" in issue_lower:
            return "Snapshot if needed and delete unattached EBS volume (zero risk / instant savings)"
        if "stopped" in issue_lower:
            return "Terminate stopped EC2 instance or snapshot and delete attached EBS volumes"
        if "idle" in issue_lower or "unused" in issue_lower or "0 items" in issue_lower or "0 tasks" in issue_lower:
            return "Verify application necessity and decommission/delete idle resource"
        if "overprovisioned" in issue_lower or "scale" in issue_lower or "scaled to zero" in issue_lower:
            return "Downscale capacity or switch to On-Demand (PAY_PER_REQUEST) / auto-scaling"
        if "lifecycle" in issue_lower or "s3" in service.lower():
            return "Add S3 Lifecycle rule to transition old objects to Glacier / abort incomplete multipart uploads"
        if "retention" in issue_lower or "log" in issue_lower:
            return "Set CloudWatch log group retention policy (e.g. 14 to 90 days)"
        return "Evaluate resource necessity and decommission or right-size"

    elif category == "reliability":
        if "single point of failure" in issue_lower or "multi-az" in issue_lower or "no ha" in issue_lower:
            return "Enable Multi-AZ replication / multi-node cluster deployment for high availability"
        if "deprecated" in issue_lower or "eol" in issue_lower:
            return "Upgrade runtime/engine version to currently supported LTS release"
        if "backup" in issue_lower or "recovery points" in issue_lower:
            return "Assign AWS Backup plan with scheduled automated snapshots and retention"
        if "deletion protection" in issue_lower:
            return "Enable deletion protection in resource configuration"
        if "alarm" in issue_lower or "insufficient_data" in issue_lower:
            return "Update CloudWatch metric dimension or reconfigure alarm threshold"
        return "Configure automated failover, health checks, and backup redundancy"

    elif category == "drift":
        if "disabled" in issue_lower:
            return "Enable rule/automation or delete if no longer required"
        if "not recording" in issue_lower:
            return "Turn on AWS Config recorder for compliance monitoring"
        if "untagged" in issue_lower:
            return "Apply mandatory tagging (Environment, CostCenter, Owner)"
        if "stale" in issue_lower or "no logging" in issue_lower:
            return "Enable logging / update configuration to align with infrastructure baseline"
        return "Align resource configuration with standard baseline"

    return "Review and remediate according to best practices"


def _derive_default_effort(category: str, service: str, issue: str) -> str:
    """Categorize remediation effort: low (quick win), medium (validation), high (architectural)."""
    issue_lower = issue.lower()

    if any(k in issue_lower for k in [
        "unattached", "unassociated", "disabled", "empty", "0 records",
        "0 recovery points", "retention", "deletion protection", "untagged",
        "no waf", "enforce config", "bytes_scanned", "eip", "elastic ip"
    ]) or service in ["Elastic IP", "Route53", "Global Accelerator"]:
        return "low"

    if any(k in issue_lower for k in [
        "multi-az", "single node", "engine version", "runtime", "single point of failure",
        "migration", "cross-region"
    ]):
        return "high"

    return "medium"


def finding(category, service, region, resource, issue, severity, est_monthly_cost=None, action=None, effort=None):
    """Create a standardized finding dict with remediation action and effort."""
    f = {
        "category": category,
        "service": service,
        "region": region,
        "resource": resource,
        "issue": issue,
        "severity": severity,
        "action": action or _derive_default_action(category, service, issue),
        "effort": effort or _derive_default_effort(category, service, issue),
    }
    if est_monthly_cost is not None:
        f["est_monthly_waste_usd"] = est_monthly_cost
    return f


def _version_tuple(v):
    """Parse a version like '1.28' / '1.9.3' into an int tuple for correct
    numeric comparison ('1.9' < '1.28' is True as tuples, False as strings)."""
    parts = []
    for p in str(v).split("."):
        num = "".join(c for c in p if c.isdigit())
        parts.append(int(num) if num else 0)
    return tuple(parts)


# ============================================================
# Live pricing (optional) — filled by main() when --live-pricing is set.
# When off, checks fall back to the hardcoded rates below.
# ============================================================

_SESSION = None  # boto3 session when live pricing enabled, else None

# Fallback per-GB-month EBS rates (us-east-1 list prices)
EBS_FALLBACK_RATE = {"gp3": 0.08, "gp2": 0.10, "io1": 0.125, "io2": 0.125, "st1": 0.045, "sc1": 0.015}


def ebs_rate(region, volume_type):
    """Per-GB-month price for an EBS volume type — live if available, else fallback."""
    vt = volume_type or "gp3"
    if _SESSION is not None:
        from common import get_ebs_gb_month_price
        price = get_ebs_gb_month_price(_SESSION, region, vt)
        if price is not None:
            return price
    return EBS_FALLBACK_RATE.get(vt, 0.08)


# ============================================================
# 🔒 SECURITY CHECKS
# ============================================================

def check_security_ec2_public_ips(account_dir, days_threshold):
    """EC2 instances with public IPs — potential exposure."""
    findings = []
    path = find_latest_inventory(account_dir, "ec2")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, instances in data.get("regions", {}).items():
        if not isinstance(instances, list):
            continue
        for inst in instances:
            if inst.get("public_ip") and inst["public_ip"] != "N/A" and inst.get("state") == "running":
                findings.append(finding(
                    "security", "EC2", region,
                    f"{inst.get('instance_id')} ({inst.get('name', 'N/A')})",
                    f"Public IP {inst['public_ip']} — verify intentional",
                    "medium"
                ))
    return findings


def check_security_rds(account_dir, days_threshold):
    """RDS instances and clusters that are publicly accessible or use expired CA certificates."""
    findings = []
    path = find_latest_inventory(account_dir, "rds")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for inst in region_data.get("instances", []):
            ident = inst.get("identifier", "unknown")
            if inst.get("publicly_accessible"):
                findings.append(finding(
                    "security", "RDS", region, ident,
                    "Publicly accessible — database exposed to internet",
                    "critical",
                    action="Modify instance PubliclyAccessible setting to False and place in private subnets",
                    effort="medium"
                ))
            ca_id = inst.get("ca_certificate_identifier", "")
            if ca_id and "rds-ca-2019" in ca_id:
                findings.append(finding(
                    "security", "RDS", region, ident,
                    f"Legacy CA certificate '{ca_id}' expired — database SSL/TLS connections at risk",
                    "high",
                    action="Modify RDS CA certificate to rds-ca-rsa2048-g1 or newer in AWS Console",
                    effort="low"
                ))
        for cluster in region_data.get("clusters", []):
            if cluster.get("publicly_accessible"):
                findings.append(finding(
                    "security", "RDS", region, cluster.get("identifier", "unknown"),
                    "Cluster is publicly accessible — database exposed to internet",
                    "critical",
                    action="Disable public accessibility on DB cluster and update security groups",
                    effort="medium"
                ))
    return findings


def check_security_redshift(account_dir, days_threshold):
    """Redshift clusters that are publicly accessible."""
    findings = []
    path = find_latest_inventory(account_dir, "redshift")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for cluster in region_data.get("clusters", []):
            if cluster.get("publicly_accessible"):
                findings.append(finding(
                    "security", "Redshift", region,
                    cluster.get("cluster_id", "unknown"),
                    "Publicly accessible — data warehouse exposed",
                    "critical"
                ))
    return findings


def check_security_cloudtrail(account_dir, days_threshold):
    """CloudTrail trails not logging or without log validation."""
    findings = []
    path = find_latest_inventory(account_dir, "cloudtrail")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for trail in region_data.get("trails", []):
            if not trail.get("is_logging", True):
                findings.append(finding(
                    "security", "CloudTrail", region,
                    trail.get("name", "unknown"),
                    "Trail is NOT logging — no audit trail",
                    "critical"
                ))
            if not trail.get("log_file_validation", True):
                findings.append(finding(
                    "security", "CloudTrail", region,
                    trail.get("name", "unknown"),
                    "Log file validation disabled — tampering undetectable",
                    "high"
                ))
    return findings


def check_security_kms(account_dir, days_threshold):
    """KMS keys pending deletion."""
    findings = []
    path = find_latest_inventory(account_dir, "kms")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        keys = region_data if isinstance(region_data, list) else region_data.get("keys", [])
        for key in keys:
            state = key.get("state", key.get("key_state", ""))
            if state == "PendingDeletion":
                findings.append(finding(
                    "security", "KMS", region,
                    key.get("key_id", key.get("alias", "unknown")),
                    "Key pending deletion — encrypted data will become inaccessible",
                    "critical"
                ))
    return findings


def check_security_secrets(account_dir, days_threshold):
    """Secrets never rotated or not accessed in a long time."""
    findings = []
    path = find_latest_inventory(account_dir, "secrets-manager")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, secrets in data.get("regions", {}).items():
        if not isinstance(secrets, list):
            continue
        for secret in secrets:
            if not secret.get("rotation_enabled", False):
                age = days_ago(secret.get("last_accessed"))
                if age and age > days_threshold:
                    findings.append(finding(
                        "security", "Secrets Manager", region,
                        secret.get("name", "unknown"),
                        f"No rotation, last accessed {age} days ago — stale credential risk",
                        "high"
                    ))
                else:
                    findings.append(finding(
                        "security", "Secrets Manager", region,
                        secret.get("name", "unknown"),
                        "Rotation disabled — credential compromise risk",
                        "medium"
                    ))
    return findings


def check_security_iam(account_dir, days_threshold):
    """IAM users with old password use or no recent activity."""
    findings = []
    path = find_latest_inventory(account_dir, "iam")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for user in data.get("users", []):
        last_used = user.get("password_last_used", "")
        if last_used and is_stale(last_used, days_threshold):
            age = days_ago(last_used)
            findings.append(finding(
                "security", "IAM", "global",
                user.get("user_name", "unknown"),
                f"Password last used {age} days ago — dormant account",
                "high"
            ))
        elif not last_used and is_stale(user.get("created_at"), days_threshold):
            findings.append(finding(
                "security", "IAM", "global",
                user.get("user_name", "unknown"),
                "Never logged in — unused account",
                "medium"
            ))
    return findings


def check_security_guardduty(account_dir, days_threshold):
    """GuardDuty not enabled."""
    findings = []
    path = find_latest_inventory(account_dir, "guardduty")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if region in OPT_IN_REGIONS:
            continue
        detectors = region_data if isinstance(region_data, list) else region_data.get("detectors", [])
        if not detectors:
            findings.append(finding(
                "security", "GuardDuty", region,
                "N/A",
                "No GuardDuty detector — no threat detection",
                "high"
            ))
    return findings


def check_security_inspector(account_dir, days_threshold):
    """Inspector not enabled."""
    findings = []
    path = find_latest_inventory(account_dir, "inspector")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if region in OPT_IN_REGIONS:
            continue
        if not isinstance(region_data, dict):
            continue
        if not region_data.get("enabled", False):
            findings.append(finding(
                "security", "Inspector", region,
                "N/A",
                "Inspector not enabled — no vulnerability scanning",
                "medium"
            ))
    return findings


def check_security_hub(account_dir, days_threshold):
    """Security Hub not enabled, or enabled with no standards subscribed."""
    findings = []
    path = find_latest_inventory(account_dir, "security-hub")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if region in OPT_IN_REGIONS:
            continue
        if not isinstance(region_data, dict):
            continue
        if not region_data.get("enabled", False):
            findings.append(finding(
                "security", "Security Hub", region,
                "N/A",
                "Security Hub not enabled — no aggregated findings / posture score",
                "medium"
            ))
        elif not region_data.get("standards"):
            # Enabled but no benchmark subscribed = paying for ingestion with
            # no compliance checks running against it.
            findings.append(finding(
                "security", "Security Hub", region,
                "N/A",
                "Enabled but 0 standards subscribed — no compliance checks running",
                "low"
            ))
    return findings


def check_security_documentdb(account_dir, days_threshold):
    """DocumentDB clusters without encryption."""
    findings = []
    path = find_latest_inventory(account_dir, "documentdb")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for cluster in region_data.get("clusters", []):
            if not cluster.get("storage_encrypted", True):
                findings.append(finding(
                    "security", "DocumentDB", region,
                    cluster.get("cluster_id", "unknown"),
                    "Storage NOT encrypted — compliance risk",
                    "high"
                ))
    return findings


# ============================================================
# 💰 COST CHECKS
# ============================================================

def check_cost_ec2_stopped(account_dir, days_threshold):
    """EC2 stopped instances — EBS still billed."""
    findings = []
    path = find_latest_inventory(account_dir, "ec2")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, instances in data.get("regions", {}).items():
        if not isinstance(instances, list):
            continue
        for inst in instances:
            if inst.get("state") == "stopped":
                findings.append(finding(
                    "cost", "EC2", region,
                    f"{inst.get('instance_id')} ({inst.get('name', 'N/A')})",
                    f"Stopped — EBS still billed ({inst.get('type', '?')})",
                    "medium",
                    est_monthly_cost=10  # conservative estimate per stopped instance EBS
                ))
    return findings


def check_cost_nat_gateways(account_dir, days_threshold):
    """NAT Gateways — ~$32/mo each."""
    findings = []
    path = find_latest_inventory(account_dir, "nat-gateway")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, gateways in data.get("regions", {}).items():
        if not isinstance(gateways, list):
            continue
        for gw in gateways:
            findings.append(finding(
                "cost", "NAT Gateway", region,
                f"{gw.get('nat_gateway_id')} ({gw.get('name', 'N/A')})",
                f"~$32/mo + data transfer — verify needed (VPC: {gw.get('vpc_id', '?')})",
                "info",
                est_monthly_cost=32
            ))
    return findings


def check_cost_vpc_endpoints(account_dir, days_threshold):
    """VPC Interface endpoints — ~$7/mo each."""
    findings = []
    path = find_latest_inventory(account_dir, "vpc-endpoints")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, endpoints in data.get("regions", {}).items():
        if not isinstance(endpoints, list):
            continue
        interface_eps = [e for e in endpoints if e.get("endpoint_type") == "Interface"]
        if interface_eps:
            cost = len(interface_eps) * 7
            findings.append(finding(
                "cost", "VPC Endpoints", region,
                f"{len(interface_eps)} interface endpoints",
                f"~${cost}/mo total — verify all in use",
                "info",
                est_monthly_cost=cost
            ))
    return findings


def check_cost_sns_unused(account_dir, days_threshold):
    """SNS topics with 0 subscriptions."""
    findings = []
    path = find_latest_inventory(account_dir, "sns")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, topics in data.get("regions", {}).items():
        if not isinstance(topics, dict):
            continue
        for topic in topics.get("topics", []):
            if topic.get("subscriptions_confirmed", 0) == 0:
                findings.append(finding(
                    "cost", "SNS", region,
                    topic.get("topic_name", topic.get("arn", "unknown")),
                    "0 subscriptions — nobody listening",
                    "low"
                ))
    return findings


def check_cost_sqs_dead(account_dir, days_threshold):
    """SQS queues with 0 messages and old timestamps."""
    findings = []
    path = find_latest_inventory(account_dir, "sqs")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, queues in data.get("regions", {}).items():
        if not isinstance(queues, list):
            continue
        for q in queues:
            total_msgs = (
                _as_number(q.get("approximate_messages"))
                + _as_number(q.get("approximate_messages_delayed"))
                + _as_number(q.get("approximate_messages_not_visible"))
            )
            if total_msgs == 0 and is_stale(q.get("last_modified_timestamp"), days_threshold):
                age = days_ago(q.get("last_modified_timestamp"))
                findings.append(finding(
                    "cost", "SQS", region,
                    q.get("queue_name", "unknown"),
                    f"Empty queue, last modified {age} days ago",
                    "low"
                ))
    return findings


def check_cost_lambda_stale(account_dir, days_threshold):
    """Lambda functions not invoked or modified in N+ days."""
    findings = []
    path = find_latest_inventory(account_dir, "lambda")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        functions = region_data if isinstance(region_data, list) else region_data.get("functions", [])
        for fn in functions:
            fn_name = fn.get("name", fn.get("function_name", "unknown"))
            last_invoked = fn.get("last_invocation_time")
            invocations = fn.get("invocations_last_30d", None)

            # Best signal: 0 invocations in last 30 days
            if invocations is not None and invocations == 0:
                last_mod = fn.get("last_modified", "")
                age = days_ago(last_mod)
                issue = "0 invocations in 30 days"
                if age:
                    issue += f", code {age} days old"
                findings.append(finding(
                    "cost", "Lambda", region, fn_name,
                    issue + " — dead function",
                    "medium"
                ))
            # Fallback: just check last_modified if no invocation data
            elif invocations is None:
                last_mod = fn.get("last_modified", "")
                if is_stale(last_mod, days_threshold):
                    age = days_ago(last_mod)
                    findings.append(finding(
                        "cost", "Lambda", region, fn_name,
                        f"Not modified in {age} days — possibly unused",
                        "low"
                    ))
    return findings


def check_cost_efs_empty(account_dir, days_threshold):
    """EFS file systems that are empty."""
    findings = []
    path = find_latest_inventory(account_dir, "efs")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, filesystems in data.get("regions", {}).items():
        if not isinstance(filesystems, list):
            continue
        for fs in filesystems:
            if fs.get("size_gb", 0) < 0.01:
                findings.append(finding(
                    "cost", "EFS", region,
                    f"{fs.get('file_system_id')} ({fs.get('name', 'N/A')})",
                    "Empty file system — minimum charges apply",
                    "low",
                    est_monthly_cost=1
                ))
    return findings


def check_cost_ecr_empty(account_dir, days_threshold):
    """ECR repos with 0 images."""
    findings = []
    path = find_latest_inventory(account_dir, "ecr")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, repos in data.get("regions", {}).items():
        if not isinstance(repos, list):
            continue
        for repo in repos:
            if repo.get("image_count", 0) == 0:
                findings.append(finding(
                    "cost", "ECR", region,
                    repo.get("name", "unknown"),
                    "0 images — empty repository, can delete",
                    "low"
                ))
    return findings


def check_cost_dynamodb_overprovisioned(account_dir, days_threshold):
    """DynamoDB provisioned tables with 0 items."""
    findings = []
    path = find_latest_inventory(account_dir, "dynamodb")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, tables in data.get("regions", {}).items():
        if not isinstance(tables, list):
            continue
        for table in tables:
            if table.get("billing_mode") == "PROVISIONED" and _as_number(table.get("item_count")) == 0:
                rcu = _as_number(table.get("read_capacity"))
                wcu = _as_number(table.get("write_capacity"))
                # ponytail: rough cost — $0.00065/RCU/hr + $0.00065/WCU/hr
                monthly = (rcu + wcu) * 0.00065 * 730
                findings.append(finding(
                    "cost", "DynamoDB", region,
                    table.get("table_name", "unknown"),
                    f"Provisioned with 0 items (RCU={rcu}, WCU={wcu}) — switch to on-demand or delete",
                    "medium",
                    est_monthly_cost=round(monthly, 2)
                ))
    return findings


def check_cost_elb_idle(account_dir, days_threshold):
    """ELB with 0 target groups or targets."""
    findings = []
    path = find_latest_inventory(account_dir, "elb")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        lbs = region_data.get("load_balancers", [])
        tgs = region_data.get("target_groups", [])

        # Find LBs not referenced by any target group
        lb_arns_with_tg = set()
        for tg in tgs:
            for arn in tg.get("lb_arns", []):
                lb_arns_with_tg.add(arn)

        for lb in lbs:
            if lb.get("arn") not in lb_arns_with_tg:
                findings.append(finding(
                    "cost", "ELB", region,
                    lb.get("name", "unknown"),
                    f"No target groups attached — idle ({lb.get('type', '?')})",
                    "medium",
                    est_monthly_cost=16
                ))
    return findings


def check_cost_ebs_waste(account_dir, days_threshold):
    """Unattached EBS volumes and unassociated Elastic IPs."""
    findings = []
    path = find_latest_inventory(account_dir, "ebs")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        # Unattached volumes
        for vol in region_data.get("unattached_volumes", []):
            size = _as_number(vol.get("size_gb"))
            rate = ebs_rate(region, vol.get("volume_type", "gp3"))
            monthly = round(size * rate, 2)
            findings.append(finding(
                "cost", "EBS", region,
                f"{vol.get('volume_id')} ({vol.get('name') or 'unnamed'})",
                f"Unattached {vol.get('volume_type', '?')} {size} GB — pure waste",
                "medium" if monthly > 5 else "low",
                est_monthly_cost=monthly
            ))
        # Unassociated Elastic IPs
        for eip in region_data.get("elastic_ips", []):
            if not eip.get("associated", True):
                findings.append(finding(
                    "cost", "Elastic IP", region,
                    eip.get("public_ip", "unknown"),
                    "Unassociated EIP — $3.65/mo waste",
                    "low",
                    est_monthly_cost=3.65
                ))
    return findings


def check_cost_kinesis(account_dir, days_threshold):
    """Kinesis provisioned streams that may be unused."""
    findings = []
    path = find_latest_inventory(account_dir, "kinesis")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for stream in region_data.get("data_streams", []):
            if stream.get("mode") == "PROVISIONED" and is_stale(stream.get("created_at"), days_threshold):
                findings.append(finding(
                    "cost", "Kinesis", region,
                    stream.get("stream_name", "unknown"),
                    "Provisioned stream, old — verify still in use or switch to on-demand",
                    "low",
                    est_monthly_cost=15
                ))
    return findings


def check_cost_acm_unused(account_dir, days_threshold):
    """ACM certificates not in use or expiring."""
    findings = []
    path = find_latest_inventory(account_dir, "acm")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, certs in data.get("regions", {}).items():
        if not isinstance(certs, list):
            continue
        for cert in certs:
            remaining = days_until(cert.get("not_after"))
            if remaining is not None and remaining < 30:
                # Expiry is a reliability/security risk (TLS breaks), not cost.
                findings.append(finding(
                    "reliability", "ACM", region,
                    cert.get("domain_name", "unknown"),
                    f"Cert expires in {remaining} days!" if remaining > 0 else "Cert EXPIRED",
                    "critical" if remaining <= 0 else "high"
                ))
            if not cert.get("in_use", True):
                findings.append(finding(
                    "cost", "ACM", region,
                    cert.get("domain_name", "unknown"),
                    "Not attached to any resource — orphaned",
                    "low"
                ))
    return findings


def check_cost_ecs_scaled_zero(account_dir, days_threshold):
    """ECS services scaled to 0."""
    findings = []
    path = find_latest_inventory(account_dir, "ecs")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, clusters in data.get("regions", {}).items():
        if not isinstance(clusters, list):
            continue
        for cluster in clusters:
            for svc in cluster.get("services", []):
                if svc.get("desired_count", 1) == 0 and svc.get("running_count", 0) == 0:
                    findings.append(finding(
                        "cost", "ECS", region,
                        f"{cluster.get('cluster_name')}/{svc.get('service_name')}",
                        "Service scaled to 0 — delete if no longer needed",
                        "low"
                    ))
    return findings


# ============================================================
# ⚙️ RELIABILITY CHECKS
# ============================================================

def check_reliability_rds(account_dir, days_threshold):
    """RDS without Multi-AZ, backups, or deletion protection."""
    findings = []
    path = find_latest_inventory(account_dir, "rds")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for inst in region_data.get("instances", []):
            ident = inst.get("identifier", "unknown")
            if not inst.get("multi_az", True):
                findings.append(finding(
                    "reliability", "RDS", region, ident,
                    f"No Multi-AZ — single point of failure ({inst.get('instance_class', '?')})",
                    "high",
                    action="Enable Multi-AZ deployment for high availability and failover",
                    effort="medium"
                ))
            backup_retention_days = inst.get("backup_retention_days")
            if backup_retention_days is not None and backup_retention_days <= 0:
                findings.append(finding(
                    "reliability", "RDS", region, ident,
                    "Automated backups disabled — point-in-time recovery unavailable",
                    "high",
                    action="Enable automated backups with an appropriate retention period",
                    effort="low"
                ))
            if inst.get("deletion_protection") is False:
                findings.append(finding(
                    "reliability", "RDS", region, ident,
                    "Deletion protection disabled — risk of accidental database deletion",
                    "medium",
                    action="Enable deletion protection in DB instance configuration",
                    effort="low"
                ))
        for cluster in region_data.get("clusters", []):
            if cluster.get("deletion_protection") is False:
                findings.append(finding(
                    "reliability", "RDS", region, cluster.get("identifier", "unknown"),
                    "Cluster deletion protection disabled — risk of accidental cluster deletion",
                    "medium",
                    action="Enable deletion protection in DB cluster configuration",
                    effort="low"
                ))
    return findings


def check_reliability_eks_version(account_dir, days_threshold):
    """EKS clusters on outdated Kubernetes versions."""
    findings = []
    path = find_latest_inventory(account_dir, "eks")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, clusters in data.get("regions", {}).items():
        if not isinstance(clusters, list):
            continue
        for cluster in clusters:
            version = cluster.get("version", cluster.get("kubernetes_version", ""))
            if version and _version_tuple(version) < _version_tuple(EKS_MIN_SUPPORTED):
                findings.append(finding(
                    "reliability", "EKS", region,
                    cluster.get("name", "unknown"),
                    f"Kubernetes {version} — outdated (min supported: {EKS_MIN_SUPPORTED})",
                    "high"
                ))
    return findings


def check_reliability_lambda_runtime(account_dir, days_threshold):
    """Lambda functions using deprecated runtimes."""
    findings = []
    path = find_latest_inventory(account_dir, "lambda")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        functions = region_data if isinstance(region_data, list) else region_data.get("functions", [])
        for fn in functions:
            runtime = fn.get("runtime", "")
            if runtime in DEPRECATED_RUNTIMES:
                findings.append(finding(
                    "reliability", "Lambda", region,
                    fn.get("name", fn.get("function_name", "unknown")),
                    f"Deprecated runtime: {runtime} — will lose security patches",
                    "high"
                ))
    return findings


def check_reliability_opensearch(account_dir, days_threshold):
    """OpenSearch single-node clusters (no HA)."""
    findings = []
    path = find_latest_inventory(account_dir, "opensearch")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, domains in data.get("regions", {}).items():
        if not isinstance(domains, list):
            continue
        for d in domains:
            if d.get("instance_count", 1) == 1 and not d.get("zone_awareness", False):
                findings.append(finding(
                    "reliability", "OpenSearch", region,
                    d.get("name", "unknown"),
                    f"Single node, no zone awareness — no HA ({d.get('instance_type', '?')})",
                    "medium"
                ))
    return findings


def check_reliability_ecs_failing(account_dir, days_threshold):
    """ECS services where running < desired."""
    findings = []
    path = find_latest_inventory(account_dir, "ecs")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, clusters in data.get("regions", {}).items():
        if not isinstance(clusters, list):
            continue
        for cluster in clusters:
            for svc in cluster.get("services", []):
                desired = svc.get("desired_count", 0)
                running = svc.get("running_count", 0)
                if desired > 0 and running < desired:
                    findings.append(finding(
                        "reliability", "ECS", region,
                        f"{cluster.get('cluster_name')}/{svc.get('service_name')}",
                        f"Running {running}/{desired} — deployment may be failing",
                        "high"
                    ))
    return findings


def check_reliability_dynamodb_no_protection(account_dir, days_threshold):
    """DynamoDB tables without deletion protection."""
    findings = []
    path = find_latest_inventory(account_dir, "dynamodb")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, tables in data.get("regions", {}).items():
        if not isinstance(tables, list):
            continue
        for table in tables:
            if not table.get("deletion_protection", False) and table.get("item_count", 0) > 0:
                findings.append(finding(
                    "reliability", "DynamoDB", region,
                    table.get("table_name", "unknown"),
                    f"No deletion protection ({table.get('item_count', 0)} items) — accidental delete risk",
                    "medium"
                ))
    return findings


def check_reliability_backup_empty(account_dir, days_threshold):
    """Backup vaults with 0 recovery points."""
    findings = []
    path = find_latest_inventory(account_dir, "backup")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for vault in region_data.get("vaults", []):
            if vault.get("recovery_points", 0) == 0:
                findings.append(finding(
                    "reliability", "Backup", region,
                    vault.get("vault_name", "unknown"),
                    "0 recovery points — backups not running",
                    "high"
                ))
    return findings


# ============================================================
# 🧹 DRIFT / HYGIENE CHECKS
# ============================================================

def check_drift_untagged_ec2(account_dir, days_threshold):
    """EC2 instances without a Name tag."""
    findings = []
    path = find_latest_inventory(account_dir, "ec2")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    count = 0
    for region, instances in data.get("regions", {}).items():
        if not isinstance(instances, list):
            continue
        for inst in instances:
            if inst.get("name") in ("N/A", "", None) and inst.get("state") == "running":
                count += 1
    if count > 0:
        findings.append(finding(
            "drift", "EC2", "all",
            f"{count} instances",
            "Running instances without Name tag — unmanaged/untagged",
            "low"
        ))
    return findings


def check_drift_eventbridge_disabled(account_dir, days_threshold):
    """EventBridge rules that are disabled."""
    findings = []
    path = find_latest_inventory(account_dir, "eventbridge")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for rule in region_data.get("rules", []):
            if rule.get("state") == "DISABLED":
                findings.append(finding(
                    "drift", "EventBridge", region,
                    rule.get("name", "unknown"),
                    "Rule disabled — automation not running",
                    "low"
                ))
    return findings


def check_drift_config_not_recording(account_dir, days_threshold):
    """AWS Config recorders not recording."""
    findings = []
    path = find_latest_inventory(account_dir, "config")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for recorder in region_data.get("recorders", []):
            if not recorder.get("recording", True):
                findings.append(finding(
                    "drift", "AWS Config", region,
                    recorder.get("name", "default"),
                    "Config recorder NOT recording — compliance blind spot",
                    "high"
                ))
    return findings


def check_drift_cloudwatch_alarms(account_dir, days_threshold):
    """CloudWatch alarms in INSUFFICIENT_DATA."""
    findings = []
    path = find_latest_inventory(account_dir, "cloudwatch")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    count = 0
    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for alarm in region_data.get("alarms", []):
            if alarm.get("state") == "INSUFFICIENT_DATA":
                count += 1
    if count > 0:
        findings.append(finding(
            "drift", "CloudWatch", "all",
            f"{count} alarms",
            "INSUFFICIENT_DATA — misconfigured or monitoring deleted resources",
            "medium"
        ))
    return findings


def check_drift_step_functions_no_logging(account_dir, days_threshold):
    """Step Functions with logging OFF."""
    findings = []
    path = find_latest_inventory(account_dir, "step-functions")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, state_machines in data.get("regions", {}).items():
        if not isinstance(state_machines, list):
            continue
        for sm in state_machines:
            if sm.get("logging_level", "OFF") == "OFF":
                findings.append(finding(
                    "drift", "Step Functions", region,
                    sm.get("name", "unknown"),
                    "Logging OFF — no execution visibility for debugging",
                    "low"
                ))
    return findings


def check_drift_cloudtrail_stale(account_dir, days_threshold):
    """CloudTrail trails that haven't delivered logs recently."""
    findings = []
    path = find_latest_inventory(account_dir, "cloudtrail")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for trail in region_data.get("trails", []):
            if trail.get("is_logging") and is_stale(trail.get("latest_delivery_time"), 7):
                age = days_ago(trail.get("latest_delivery_time"))
                findings.append(finding(
                    "drift", "CloudTrail", region,
                    trail.get("name", "unknown"),
                    f"Last log delivery {age} days ago — trail may be broken",
                    "high"
                ))
    return findings


# ============================================================
# 💰 COST CHECKS — Additional services
# ============================================================

def check_cost_sagemaker(account_dir, days_threshold):
    """SageMaker endpoints running — very expensive if idle."""
    findings = []
    path = find_latest_inventory(account_dir, "sagemaker")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for ep in region_data.get("endpoints", []):
            if ep.get("status") == "InService":
                findings.append(finding(
                    "cost", "SageMaker", region,
                    ep.get("endpoint_name", "unknown"),
                    "Inference endpoint running — verify active usage (expensive)",
                    "medium",
                    est_monthly_cost=100  # ponytail: conservative, ml instances $50-500+/mo
                ))
    return findings


def check_cost_bedrock_provisioned(account_dir, days_threshold):
    """Bedrock provisioned throughput left running."""
    findings = []
    path = find_latest_inventory(account_dir, "bedrock")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for pt in region_data.get("provisioned_throughputs", []):
            if pt.get("status") in ("InService", "ACTIVE"):
                units = pt.get("model_units", 0)
                findings.append(finding(
                    "cost", "Bedrock", region,
                    pt.get("name", "unknown"),
                    f"Provisioned throughput active ({units} model units) — verify needed",
                    "high",
                    est_monthly_cost=units * 500  # ponytail: rough, varies by model
                ))
    return findings


def check_cost_dms_idle(account_dir, days_threshold):
    """DMS replication instances running with no active tasks."""
    findings = []
    path = find_latest_inventory(account_dir, "dms")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        instances = region_data.get("replication_instances", [])
        tasks = region_data.get("replication_tasks", [])

        # Build set of instance ARNs that have active tasks
        active_instance_arns = {t.get("replication_instance_arn") for t in tasks if t.get("status") in ("running", "starting")}

        for inst in instances:
            if inst.get("arn") not in active_instance_arns and inst.get("status") == "available":
                findings.append(finding(
                    "cost", "DMS", region,
                    inst.get("identifier", "unknown"),
                    f"Replication instance running, no active tasks ({inst.get('instance_class', '?')})",
                    "medium",
                    est_monthly_cost=50  # ponytail: dms.t3.medium ~$50/mo
                ))
    return findings


def check_cost_msk(account_dir, days_threshold):
    """MSK clusters — always expensive, flag for verification."""
    findings = []
    path = find_latest_inventory(account_dir, "msk")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, clusters in data.get("regions", {}).items():
        if not isinstance(clusters, list):
            continue
        for cluster in clusters:
            if cluster.get("state") == "ACTIVE":
                brokers = cluster.get("num_brokers", 0)
                instance_type = cluster.get("broker_instance_type", "?")
                storage = cluster.get("storage_gb_per_broker", 0)
                # ponytail: kafka.m5.large ~$175/mo per broker + storage
                est = brokers * 175
                findings.append(finding(
                    "cost", "MSK", region,
                    cluster.get("cluster_name", "unknown"),
                    f"{brokers}x {instance_type}, {storage}GB/broker — verify utilization",
                    "info",
                    est_monthly_cost=est
                ))
    return findings


def check_cost_mwaa(account_dir, days_threshold):
    """MWAA environments — expensive base cost."""
    findings = []
    path = find_latest_inventory(account_dir, "mwaa")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, envs in data.get("regions", {}).items():
        if not isinstance(envs, list):
            continue
        for env in envs:
            if env.get("status") == "AVAILABLE":
                env_class = env.get("environment_class", "mw1.small")
                # ponytail: mw1.small ~$0.49/hr=$360/mo, mw1.medium ~$720/mo
                cost_map = {"mw1.small": 360, "mw1.medium": 720, "mw1.large": 1440}
                est = cost_map.get(env_class, 360)
                findings.append(finding(
                    "cost", "MWAA", region,
                    env.get("name", "unknown"),
                    f"Airflow running ({env_class}) — verify DAGs active",
                    "info",
                    est_monthly_cost=est
                ))
    return findings


def check_cost_glue_stale(account_dir, days_threshold):
    """Glue jobs not run in months."""
    findings = []
    path = find_latest_inventory(account_dir, "glue")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for job in region_data.get("jobs", []):
            last_mod = job.get("last_modified", job.get("created_at", ""))
            if is_stale(last_mod, days_threshold):
                age = days_ago(last_mod)
                findings.append(finding(
                    "cost", "Glue", region,
                    job.get("name", "unknown"),
                    f"Job not modified in {age} days — possibly abandoned",
                    "low"
                ))
    return findings


def check_cost_emr_no_autoterminate(account_dir, days_threshold):
    """EMR clusters without auto-terminate."""
    findings = []
    path = find_latest_inventory(account_dir, "emr")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, clusters in data.get("regions", {}).items():
        if not isinstance(clusters, list):
            continue
        for cluster in clusters:
            if not cluster.get("auto_terminate", True) and cluster.get("state") in ("RUNNING", "WAITING"):
                findings.append(finding(
                    "cost", "EMR", region,
                    cluster.get("name", cluster.get("cluster_id", "unknown")),
                    "Auto-terminate disabled — will run (and charge) indefinitely",
                    "medium",
                    est_monthly_cost=200  # ponytail: varies wildly, conservative baseline
                ))
    return findings


def check_cost_s3_no_lifecycle(account_dir, days_threshold):
    """S3 buckets with no lifecycle, missing multipart abort rules, retention > 1yr, or no Glacier transition."""
    findings = []
    path = find_latest_inventory(account_dir, "s3")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    buckets = data.get("buckets", [])
    for bucket in buckets:
        lifecycle = bucket.get("lifecycle") or {}
        size_gb = _as_number(bucket.get("size_gb"))
        name = bucket.get("bucket_name", bucket.get("name", "unknown"))
        region = bucket.get("region", "global")

        # Skip only when we couldn't read lifecycle (error)
        if lifecycle.get("error"):
            continue

        retention_configured = lifecycle.get("retention_configured", False)
        retention_days_list = lifecycle.get("retention_days") or []
        transitions = lifecycle.get("transitions", [])
        abort_mp = lifecycle.get("abort_incomplete_multipart_days")

        # Check 1: No lifecycle at all
        if not retention_configured and not transitions:
            if size_gb > 10:
                findings.append(finding(
                    "cost", "S3", region, name,
                    f"No lifecycle policy ({size_gb:.0f} GB) — storage grows indefinitely",
                    "medium" if size_gb > 100 else "low",
                    est_monthly_cost=round(size_gb * 0.023, 2),
                    action="Add S3 Lifecycle rule to transition to Glacier or expire old objects",
                    effort="low"
                ))
            else:
                findings.append(finding(
                    "drift", "S3", region, name,
                    "No lifecycle policy configured — storage will grow indefinitely without retention or tiering rules",
                    "info",
                    action="Configure S3 Lifecycle policy with retention rules and tiering transitions",
                    effort="low"
                ))

        # Check 2: Retention > 365 days (keeping data > 1 year)
        long_retention = [d for d in retention_days_list if d > 365]
        if long_retention and size_gb > 10:
            max_days = max(long_retention)
            findings.append(finding(
                "cost", "S3", region, name,
                f"Retention {max_days} days (>{max_days // 365} yr) on {size_gb:.0f} GB — review if needed that long",
                "low",
                action="Review retention policy and transition data older than 90-180 days to Glacier",
                effort="low"
            ))

        # Check 3: Has retention/lifecycle but no Glacier transition on large buckets
        has_glacier = any("GLACIER" in t.upper() or "DEEP_ARCHIVE" in t.upper() for t in transitions)
        if not has_glacier and size_gb > 50 and retention_configured:
            findings.append(finding(
                "cost", "S3", region, name,
                f"No Glacier/Deep Archive transition ({size_gb:.0f} GB) — tiering could save 60-80%",
                "medium" if size_gb > 500 else "low",
                est_monthly_cost=round(size_gb * 0.019, 2),  # savings vs staying in Standard
                action="Add S3 Lifecycle transition rule to Glacier Flexible or Deep Archive after 30-90 days",
                effort="low"
            ))

        # Check 4: Missing AbortIncompleteMultipartUpload rule
        if not abort_mp:
            findings.append(finding(
                "cost", "S3", region, name,
                "Missing AbortIncompleteMultipartUpload rule — orphan multipart upload parts billed indefinitely",
                "info" if size_gb == 0 else "low",
                est_monthly_cost=0.50 if size_gb > 0 else 0.0,
                action="Add S3 Lifecycle rule to abort incomplete multipart uploads after 7 days",
                effort="low"
            ))

    return findings


def check_cost_cloudfront_disabled(account_dir, days_threshold):
    """CloudFront distributions that are disabled but still exist."""
    findings = []
    path = find_latest_inventory(account_dir, "cloudfront")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for dist in data.get("distributions", []):
        if not dist.get("enabled", True):
            findings.append(finding(
                "cost", "CloudFront", "global",
                f"{dist.get('distribution_id')} ({dist.get('comment', '') or dist.get('domain_name', '')})",
                "Distribution disabled — can delete if no longer needed",
                "low"
            ))
    return findings


def check_cost_waf_empty(account_dir, days_threshold):
    """WAF Web ACLs with 0 rules — paying base cost for nothing."""
    findings = []
    path = find_latest_inventory(account_dir, "waf")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, acls in data.get("regions", {}).items():
        if not isinstance(acls, list):
            continue
        for acl in acls:
            if acl.get("rule_count", 1) == 0:
                findings.append(finding(
                    "cost", "WAF", region,
                    acl.get("name", "unknown"),
                    "Web ACL with 0 rules — paying $5/mo base for nothing",
                    "low",
                    est_monthly_cost=5
                ))
    return findings


def check_cost_elasticache(account_dir, days_threshold):
    """ElastiCache clusters — flag for utilization review, grouped by replication group."""
    findings = []
    path = find_latest_inventory(account_dir, "elasticache")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue

        clusters = region_data.get("clusters", [])
        rep_groups = region_data.get("replication_groups", [])

        # Map clusters by cluster_id
        cluster_map = {c.get("cluster_id"): c for c in clusters if c.get("cluster_id")}
        handled_cluster_ids = set()

        # Group by replication group if present
        for rg in rep_groups:
            rg_id = rg.get("replication_group_id")
            member_ids = rg.get("member_clusters", [])
            if not member_ids:
                continue

            # Pick sample cluster for node type and created_at
            sample = cluster_map.get(member_ids[0]) if member_ids else None
            node_type = sample.get("node_type", "?") if sample else "?"
            created_at = sample.get("created_at") if sample else None
            num_nodes = len(member_ids)

            for mid in member_ids:
                handled_cluster_ids.add(mid)

            if is_stale(created_at, days_threshold):
                findings.append(finding(
                    "cost", "ElastiCache", region,
                    f"{rg_id} ({num_nodes} nodes)",
                    f"{num_nodes}x {node_type} — old cluster group, verify still needed",
                    "info",
                    est_monthly_cost=num_nodes * 25
                ))

        # Check standalone clusters not part of a replication group
        for cluster in clusters:
            cid = cluster.get("cluster_id")
            if cid in handled_cluster_ids:
                continue
            node_type = cluster.get("node_type", "?")
            num_nodes = cluster.get("num_nodes", 1)
            if is_stale(cluster.get("created_at"), days_threshold):
                findings.append(finding(
                    "cost", "ElastiCache", region,
                    cluster.get("cluster_id", "unknown"),
                    f"{num_nodes}x {node_type} — old cluster, verify still needed",
                    "info",
                    est_monthly_cost=num_nodes * 25
                ))

    return findings


def check_cost_transit_gateway(account_dir, days_threshold):
    """Transit Gateway attachments — per-hour + per-GB charges."""
    findings = []
    path = find_latest_inventory(account_dir, "transit-gateway")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        attachments = region_data.get("attachments", [])
        if attachments:
            # $0.05/hr per attachment = ~$36/mo
            est = len(attachments) * 36
            findings.append(finding(
                "cost", "Transit Gateway", region,
                f"{len(attachments)} TGW attachments",
                f"~${est}/mo ({len(attachments)} x $36/mo) — verify all needed",
                "info",
                est_monthly_cost=est
            ))
    return findings


# ============================================================
# ALL CHECKS REGISTRY
# ============================================================

def check_cost_workspaces_idle(account_dir, days_threshold):
    """WorkSpaces on ALWAYS_ON that look idle, plus long-stopped ones still billed."""
    findings = []
    path = find_latest_inventory(account_dir, "workspaces")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, workspaces in data.get("regions", {}).items():
        if not isinstance(workspaces, list):
            continue
        for ws in workspaces:
            ws_id = ws.get("workspace_id", "unknown")
            user = ws.get("user_name", "?")
            resource = f"{ws_id} ({user})"
            mode = ws.get("running_mode", "")
            last = ws.get("last_active", "")
            idle_days = days_ago(last) if last else None

            # ALWAYS_ON bills a flat monthly rate (~$21-64/mo by bundle) even
            # when unused. Idle ALWAYS_ON is the classic WorkSpaces waste.
            if mode == "ALWAYS_ON":
                if idle_days is None or idle_days >= days_threshold:
                    when = f"no login in {idle_days}d" if idle_days is not None else "never connected"
                    findings.append(finding(
                        "cost", "WorkSpaces", region, resource,
                        f"ALWAYS_ON but {when} — switch to AUTO_STOP or terminate",
                        "medium",
                        est_monthly_cost=35  # ponytail: mid-bundle avg; varies $21-64 by type
                    ))
            # Any workspace with a real user that hasn't connected in a long
            # time is a decommission candidate regardless of running mode.
            elif idle_days is not None and idle_days >= days_threshold:
                findings.append(finding(
                    "cost", "WorkSpaces", region, resource,
                    f"No login in {idle_days}d — decommission candidate",
                    "low",
                    est_monthly_cost=10  # ponytail: AUTO_STOP still bills storage + occasional use
                ))
    return findings


def check_security_workspaces_unencrypted(account_dir, days_threshold):
    """WorkSpaces user volumes without encryption."""
    findings = []
    path = find_latest_inventory(account_dir, "workspaces")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, workspaces in data.get("regions", {}).items():
        if not isinstance(workspaces, list):
            continue
        for ws in workspaces:
            if not ws.get("encrypted", False):
                findings.append(finding(
                    "security", "WorkSpaces", region,
                    f"{ws.get('workspace_id', 'unknown')} ({ws.get('user_name', '?')})",
                    "User volume NOT encrypted — data-at-rest exposure",
                    "high"
                ))
    return findings


def check_reliability_workspaces_unhealthy(account_dir, days_threshold):
    """WorkSpaces stuck in an error/unhealthy state."""
    findings = []
    path = find_latest_inventory(account_dir, "workspaces")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    bad_states = {"ERROR", "UNHEALTHY", "IMPAIRED", "MAINTENANCE"}
    for region, workspaces in data.get("regions", {}).items():
        if not isinstance(workspaces, list):
            continue
        for ws in workspaces:
            state = ws.get("state", "")
            if state in bad_states:
                findings.append(finding(
                    "reliability", "WorkSpaces", region,
                    f"{ws.get('workspace_id', 'unknown')} ({ws.get('user_name', '?')})",
                    f"State {state} — user cannot work / needs rebuild",
                    "high"
                ))
    return findings


def check_cost_amplify_stale(account_dir, days_threshold):
    """Amplify apps not updated in months, or apps with no branches."""
    findings = []
    path = find_latest_inventory(account_dir, "amplify")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, apps in data.get("regions", {}).items():
        if not isinstance(apps, list):
            continue
        for app in apps:
            name = app.get("name", app.get("app_id", "unknown"))
            if app.get("branch_count", 0) == 0:
                findings.append(finding(
                    "cost", "Amplify", region, name,
                    "App has 0 branches — orphaned, delete",
                    "low"
                ))
                continue
            age = days_ago(app.get("updated_at", ""))
            if age is not None and age >= days_threshold:
                findings.append(finding(
                    "cost", "Amplify", region, name,
                    f"Not updated in {age}d — possibly abandoned hosting",
                    "low"
                ))
    return findings


def check_cost_cloudwatch_log_retention(account_dir, days_threshold):
    """CloudWatch log groups with no retention (never expire) — silent, growing cost."""
    findings = []
    path = find_latest_inventory(account_dir, "cloudwatch")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for lg in region_data.get("log_groups", []):
            retention = lg.get("retention_days")
            # Scanner writes "Never expire" (str) when no retention is set.
            never_expires = isinstance(retention, str) or retention in (None, 0)
            if not never_expires:
                continue
            gb = lg.get("stored_bytes", 0) / (1024 ** 3)
            if gb < 1:  # ponytail: sub-GB log groups aren't worth the noise
                continue
            # CloudWatch Logs storage ~$0.03/GB-mo; unbounded retention means
            # this only grows. Flag the estimated monthly storage as waste.
            monthly = round(gb * 0.03, 2)
            findings.append(finding(
                "cost", "CloudWatch Logs", region,
                lg.get("name", "unknown"),
                f"No retention policy ({gb:.0f} GB) — logs kept forever, storage only grows",
                "medium" if gb > 50 else "low",
                est_monthly_cost=monthly
            ))
    return findings


def check_cost_xray_full_sampling(account_dir, days_threshold):
    """X-Ray sampling rules at 100% fixed rate — traces everything, expensive."""
    findings = []
    path = find_latest_inventory(account_dir, "xray")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        rules = region_data.get("sampling_rules", []) if isinstance(region_data, dict) else region_data
        if not isinstance(rules, list):
            continue
        for rule in rules:
            if rule.get("fixed_rate", 0) >= 1.0:
                findings.append(finding(
                    "cost", "X-Ray", region,
                    rule.get("rule_name", "unknown"),
                    "Sampling fixed_rate 100% — every request traced, high X-Ray cost",
                    "medium"
                ))
    return findings


def check_reliability_amp_status(account_dir, days_threshold):
    """AMP (Managed Prometheus) workspaces not in ACTIVE state."""
    findings = []
    path = find_latest_inventory(account_dir, "amp")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        workspaces = region_data.get("workspaces", []) if isinstance(region_data, dict) else region_data
        if not isinstance(workspaces, list):
            continue
        for ws in workspaces:
            status = (ws.get("status") or "").upper()
            if status and status != "ACTIVE":
                findings.append(finding(
                    "reliability", "AMP", region,
                    ws.get("alias", ws.get("workspace_id", "unknown")),
                    f"Workspace status {status} — metrics ingestion may be broken",
                    "high" if "FAIL" in status else "medium"
                ))
    return findings


def check_security_amg_auth(account_dir, days_threshold):
    """AMG (Managed Grafana) workspaces without authentication configured."""
    findings = []
    path = find_latest_inventory(account_dir, "amg")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        workspaces = region_data.get("workspaces", []) if isinstance(region_data, dict) else region_data
        if not isinstance(workspaces, list):
            continue
        for ws in workspaces:
            name = ws.get("name", ws.get("id", "unknown"))
            if not ws.get("auth_providers"):
                findings.append(finding(
                    "security", "AMG", region, name,
                    "No auth providers (SAML/IAM Identity Center) — access control gap",
                    "high"
                ))
    return findings


def check_reliability_internet_monitor(account_dir, days_threshold):
    """Internet Monitor monitoring 100% of traffic (cost) or in a bad state."""
    findings = []
    path = find_latest_inventory(account_dir, "cloudwatch-internet-monitor")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        monitors = region_data.get("monitors", []) if isinstance(region_data, dict) else region_data
        if not isinstance(monitors, list):
            continue
        for m in monitors:
            name = m.get("name", "unknown")
            if m.get("traffic_percentage") == 100:
                findings.append(finding(
                    "cost", "Internet Monitor", region, name,
                    "Monitoring 100% of traffic — sample a subset to cut cost",
                    "low"
                ))
            status = (m.get("status") or "").upper()
            if status and status not in ("ACTIVE", "OK"):
                findings.append(finding(
                    "reliability", "Internet Monitor", region, name,
                    f"Monitor status {status} — not collecting",
                    "medium"
                ))
    return findings


def check_reliability_health_events(account_dir, days_threshold):
    """Open/upcoming AWS Health events needing attention — forced retirements,
    scheduled changes, security notifications, and unresolved issues."""
    findings = []
    path = find_latest_inventory(account_dir, "health")
    if not path:
        return findings
    data = load_json(path)
    if not data or not data.get("access"):
        return findings

    events = data.get("events", {}).get("all", [])
    for ev in events:
        status = ev.get("status", "")
        # Only actionable events — closed ones are history, not findings.
        if status not in ("open", "upcoming"):
            continue

        category = ev.get("category", "")
        service = ev.get("service", "")
        region = ev.get("region", "global")
        code = ev.get("event_type_code", "")

        # Forced lifecycle/retirement changes are the ones that break things
        # if ignored (version EOL, mandatory reboots, patch retirements).
        if category == "scheduledChange":
            when = days_until(ev.get("start_time"))
            when_str = f"in {when}d" if when is not None and when >= 0 else "scheduled"
            findings.append(finding(
                "reliability", "Health", region, f"{service}: {code}",
                f"Scheduled change {when_str} — plan for it or resources may be affected",
                "high" if (when is not None and 0 <= when <= 30) else "medium"
            ))
        elif category == "issue":
            findings.append(finding(
                "reliability", "Health", region, f"{service}: {code}",
                "Open AWS issue affecting your resources",
                "high"
            ))
        elif "SECURITY" in code.upper():
            findings.append(finding(
                "security", "Health", region, f"{service}: {code}",
                "Open AWS security notification — review required",
                "high"
            ))
    return findings


def check_reliability_security_lake(account_dir, days_threshold):
    """Security Lake posture: weak encryption, no replication, no retention, dead subscribers."""
    findings = []
    path = find_latest_inventory(account_dir, "security-lake")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, rd in data.get("regions", {}).items():
        if not isinstance(rd, dict):
            continue

        for dl in rd.get("data_lakes", []):
            arn = dl.get("arn", "data-lake")

            # S3-managed key instead of a customer KMS key — weaker control
            if dl.get("kms_key_id") in ("S3_MANAGED_KEY", "", None):
                findings.append(finding(
                    "security", "Security Lake", region, arn,
                    "Data lake uses S3-managed key, not a customer KMS CMK",
                    "medium"
                ))

            # Single-region SIEM store with no replication = SPOF for security data
            if not dl.get("replication_enabled", False):
                findings.append(finding(
                    "reliability", "Security Lake", region, arn,
                    "Replication disabled — security data has no cross-region copy",
                    "medium"
                ))

            # No lifecycle transitions/expiration → S3 grows forever (real cost)
            if not dl.get("retention_settings") and not dl.get("expiration_days"):
                findings.append(finding(
                    "cost", "Security Lake", region, arn,
                    "No retention/lifecycle — log storage grows unbounded",
                    "medium"
                ))

        for sub in rd.get("subscribers", []):
            if sub.get("status") not in ("ACTIVE", ""):
                findings.append(finding(
                    "drift", "Security Lake", region,
                    sub.get("name", sub.get("subscriber_id", "unknown")),
                    f"Subscriber status {sub.get('status')} — not consuming data",
                    "low"
                ))
    return findings


def check_reliability_synthetics(account_dir, days_threshold):
    """Canaries that are broken (last run failed), stopped, or on an EOL runtime."""
    findings = []
    path = find_latest_inventory(account_dir, "cloudwatch-synthetics")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, canaries in data.get("regions", {}).items():
        if not isinstance(canaries, list):
            continue
        for c in canaries:
            name = c.get("name", "unknown")
            state = c.get("state", "")
            last_run = (c.get("last_run_state") or "").upper()
            runtime = c.get("runtime_version", "")

            # Broken canary = monitoring blind spot (thinks it's covered, isn't)
            if last_run in ("FAILED", "ERROR"):
                findings.append(finding(
                    "reliability", "Synthetics", region, name,
                    f"Last run {last_run} — monitoring blind spot, alerts won't fire correctly",
                    "high"
                ))

            # Stopped canary = configured monitoring that isn't running
            if state == "STOPPED":
                findings.append(finding(
                    "reliability", "Synthetics", region, name,
                    "Canary STOPPED — not monitoring; delete or restart",
                    "medium"
                ))

            # EOL runtime. ponytail: prefix heuristic, not an exhaustive AWS
            # list — syn-1.0 and puppeteer-3.x/selenium-1.x are long deprecated.
            # Upgrade path: check AWS Synthetics runtime deprecation page and
            # extend these prefixes when new versions age out.
            if (runtime == "syn-1.0"
                    or runtime.startswith("syn-nodejs-puppeteer-3.")
                    or runtime.startswith("syn-python-selenium-1.")):
                findings.append(finding(
                    "reliability", "Synthetics", region, name,
                    f"Deprecated runtime {runtime} — upgrade before AWS blocks it",
                    "medium"
                ))
    return findings


def check_drift_rum_no_sampling(account_dir, days_threshold):
    """RUM app monitors that collect nothing (0% sample) — configured but useless."""
    findings = []
    path = find_latest_inventory(account_dir, "cloudwatch-rum")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, monitors in data.get("regions", {}).items():
        if not isinstance(monitors, list):
            continue
        for m in monitors:
            rate = m.get("session_sample_rate")
            if rate == 0:
                findings.append(finding(
                    "drift", "RUM", region, m.get("name", "unknown"),
                    "Session sample rate 0% — monitor collects no data",
                    "low"
                ))
    return findings


def check_security_s3(account_dir, days_threshold):
    """S3 buckets — check encryption and replication gaps."""
    findings = []
    path = find_latest_inventory(account_dir, "s3")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for b in data.get("buckets", []):
        name = b.get("bucket_name", "unknown")
        region = b.get("region", "global")
        lifecycle = b.get("lifecycle", {}) or {}

        # Do not treat a failed lifecycle lookup as a missing security control.
        if lifecycle.get("error"):
            continue

        encryption = b.get("encryption")
        if (
            isinstance(encryption, dict)
            and encryption.get("status") != "unavailable"
            and not encryption.get("enabled", False)
        ):
            findings.append(finding(
                "security", "S3", region, name,
                "Bucket default encryption is not configured",
                "medium",
                action="Enable S3 server-side encryption with SSE-S3 or SSE-KMS",
                effort="low"
            ))
        # Public Access Block check
        pab = b.get("public_access_block")
        if isinstance(pab, dict) and pab.get("status") != "unavailable":
            if not pab.get("all_blocked", False) or pab.get("status") == "not_configured":
                findings.append(finding(
                    "security", "S3", region, name,
                    "S3 Block Public Access is not fully enabled on bucket",
                    "high",
                    action="Enable S3 Block Public Access with all 4 settings active in S3 Console",
                    effort="low"
                ))

        # Critical/production bucket replication and versioning checks
        tags = b.get("tags", {}) or {}
        env = str(tags.get("Environment", "")).lower()
        if "prod" in env or "production" in env:
            versioning = b.get("versioning")
            if isinstance(versioning, dict) and versioning.get("status") != "unavailable":
                if not versioning.get("enabled", False):
                    findings.append(finding(
                        "reliability", "S3", region, name,
                        "Production bucket has versioning disabled — risk of accidental object overwrite/loss",
                        "medium",
                        action="Enable bucket versioning in S3 bucket properties",
                        effort="low"
                    ))
            repl = b.get("replication", {}) or {}
            if not repl.get("enabled", False):
                findings.append(finding(
                    "reliability", "S3", region, name,
                    "Production bucket has no cross-region replication configured",
                    "info"
                ))

    return findings


def check_security_cloudfront(account_dir, days_threshold):
    """CloudFront distributions — check for missing WAF and insecure TLS protocols."""
    findings = []
    path = find_latest_inventory(account_dir, "cloudfront")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    distributions = data.get("distributions", []) if isinstance(data.get("distributions"), list) else []
    for d in distributions:
        dist_id = d.get("id", "unknown")
        domain = d.get("domain_name", "unknown")
        enabled = d.get("enabled", True)
        if not enabled:
            continue

        # Check WAF association
        web_acl = d.get("web_acl_id", "")
        if not web_acl:
            findings.append(finding(
                "security", "CloudFront", "global", f"{dist_id} ({domain})",
                "No WAF WebACL associated — distribution exposed to layer 7 attacks",
                "medium"
            ))

        # Check TLS minimum protocol version
        tls_ver = d.get("minimum_protocol_version", "")
        if tls_ver in ("SSLv3", "TLSv1", "TLSv1_2016", "TLSv1.1_2016"):
            findings.append(finding(
                "security", "CloudFront", "global", f"{dist_id} ({domain})",
                f"Outdated TLS minimum protocol version ({tls_ver}) — upgrade to TLSv1.2",
                "high"
            ))

    return findings


def check_security_ssm(account_dir, days_threshold):
    """SSM Parameter Store — check for sensitive secrets stored as plaintext Strings instead of SecureString."""
    findings = []
    path = find_latest_inventory(account_dir, "ssm")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    sensitive_keywords = ["password", "secret", "rsa_key", "token", "key.p8", "credentials", "auth_key", "api_key", "private_key", "passwd", "cert.pem"]
    for region, params in data.get("regions", {}).items():
        if not isinstance(params, list):
            continue
        for p in params:
            name = p.get("name", "")
            p_type = p.get("type", "")
            if p_type in ("String", "StringList"):
                name_lower = name.lower()
                if any(kw in name_lower for kw in sensitive_keywords):
                    findings.append(finding(
                        "security", "SSM", region, name,
                        f"Plaintext parameter ({p_type}) matches sensitive naming pattern — should be SecureString encrypted with KMS",
                        "high",
                        action="Delete plaintext parameter and recreate as SecureString encrypted with KMS",
                        effort="low"
                    ))
    return findings


def check_security_athena(account_dir, days_threshold):
    """Athena workgroups — check for unenforced configuration and missing scan limits."""
    findings = []
    path = find_latest_inventory(account_dir, "athena")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, workgroups in data.get("regions", {}).items():
        if not isinstance(workgroups, list):
            continue
        for wg in workgroups:
            name = wg.get("name", "unknown")
            state = wg.get("state", "ENABLED")
            if state != "ENABLED":
                continue
            enforce = wg.get("enforce_config", True)
            if not enforce:
                findings.append(finding(
                    "security", "Athena", region, f"workgroup/{name}",
                    "Workgroup does not enforce configuration — users can override encryption & output location",
                    "medium",
                    action="Enable 'Enforce workgroup configuration' in Athena settings",
                    effort="low"
                ))
            cutoff = wg.get("bytes_scanned_cutoff", 0)
            if cutoff == 0:
                findings.append(finding(
                    "cost", "Athena", region, f"workgroup/{name}",
                    "No query data scan limit configured — vulnerable to runaway scan costs",
                    "low",
                    action="Configure per-query data scan limit (e.g. 10 GB) to prevent expensive queries",
                    effort="low"
                ))
    return findings


def check_security_ses(account_dir, days_threshold):
    """SES — check for failed identity verifications and disabled sending."""
    findings = []
    path = find_latest_inventory(account_dir, "ses")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, reg_data in data.get("regions", {}).items():
        if not isinstance(reg_data, dict):
            continue
        for identity in reg_data.get("identities", []):
            name = identity.get("identity_name", "unknown")
            status = identity.get("verification_status", "UNKNOWN")
            sending = identity.get("sending_enabled", True)
            if status == "FAILED":
                findings.append(finding(
                    "drift", "SES", region, name,
                    "SES identity verification status is FAILED — broken email identity",
                    "low",
                    action="Re-verify DNS TXT/CNAME records or delete unused SES identity",
                    effort="low"
                ))
            elif not sending:
                findings.append(finding(
                    "drift", "SES", region, name,
                    "SES identity has sending disabled — inactive email identity",
                    "info",
                    action="Enable sending or remove obsolete SES identity",
                    effort="low"
                ))
    return findings


def check_cost_route53(account_dir, days_threshold):
    """Route53 — empty hosted zones costing $0.50/month each."""
    findings = []
    path = find_latest_inventory(account_dir, "route53")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for zone in data.get("hosted_zones", []):
        zone_id = zone.get("zone_id", "unknown")
        name = zone.get("name", "unknown")
        record_count = zone.get("record_count", 0)
        # Empty zone has only standard NS + SOA records (<= 2)
        if record_count <= 2:
            findings.append(finding(
                "cost", "Route53", "global", f"{name} ({zone_id})",
                f"Empty hosted zone ({record_count} records) — costing $0.50/mo",
                "info",
                est_monthly_cost=0.50,
                action="Delete empty Route 53 hosted zone if obsolete",
                effort="low"
            ))
    return findings


def check_cost_network_firewall(account_dir, days_threshold):
    """Network Firewall — high hourly endpoint costs ($0.395/hr = ~$285/mo per AZ endpoint)."""
    findings = []
    path = find_latest_inventory(account_dir, "network-firewall")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for fw in region_data.get("firewalls", []):
            name = fw.get("firewall_name") or fw.get("name", "unknown")
            endpoints = fw.get("sync_states", {}) or fw.get("endpoints", [])
            ep_count = len(endpoints) if isinstance(endpoints, (dict, list)) else 1
            est_cost = max(ep_count, 1) * 285.0
            findings.append(finding(
                "cost", "Network Firewall", region, name,
                f"Network Firewall active with {ep_count} endpoint(s) (~${est_cost:,.0f}/mo) — verify traffic requirement",
                "medium",
                est_monthly_cost=est_cost,
                action="Review Network Firewall endpoints and delete unused VPC attachments",
                effort="medium"
            ))
    return findings


def check_cost_globalaccelerator(account_dir, days_threshold):
    """Global Accelerator — $18/mo fixed fee per accelerator."""
    findings = []
    path = find_latest_inventory(account_dir, "globalaccelerator")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for acc in data.get("accelerators", []):
        name = acc.get("name", "unknown")
        enabled = acc.get("enabled", True)
        listeners = acc.get("listeners", []) or acc.get("listener_count", 0)
        num_listeners = len(listeners) if isinstance(listeners, list) else listeners
        if not enabled or num_listeners == 0:
            status_desc = "disabled" if not enabled else "0 active listeners"
            findings.append(finding(
                "cost", "Global Accelerator", "global", name,
                f"Global Accelerator {status_desc} (~$18/mo fixed fee) — wasting cost",
                "medium",
                est_monthly_cost=18.0,
                action="Delete unused Global Accelerator to save $18/mo",
                effort="low"
            ))
    return findings


def check_cost_timestream(account_dir, days_threshold):
    """Timestream — high memory retention store (~860x price difference vs magnetic)."""
    findings = []
    path = find_latest_inventory(account_dir, "timestream")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, dbs in data.get("regions", {}).items():
        if not isinstance(dbs, list):
            continue
        for db in dbs:
            db_name = db.get("database_name", "unknown")
            tables = db.get("tables", [])
            for tbl in tables:
                tbl_name = tbl.get("table_name", "unknown")
                mem_hours = tbl.get("memory_retention_hours", 0)
                if mem_hours > 24:
                    findings.append(finding(
                        "cost", "Timestream", region, f"{db_name}/{tbl_name}",
                        f"High memory store retention ({mem_hours}h) — memory tier is ~$0.036/GB-hr vs magnetic tier ~$0.03/GB-mo",
                        "medium",
                        action="Reduce memory retention to 2-6 hours and query magnetic storage tier for historical data",
                        effort="low"
                    ))
    return findings


def check_drift_api_gateway_stale(account_dir, days_threshold):
    """API Gateway — stale test, demo, or hackathon APIs."""
    findings = []
    path = find_latest_inventory(account_dir, "api-gateway")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, reg_data in data.get("regions", {}).items():
        if not isinstance(reg_data, dict):
            continue
        all_apis = reg_data.get("rest_apis", []) + reg_data.get("http_apis", [])
        for api in all_apis:
            name = api.get("name", "unknown")
            api_id = api.get("api_id", "unknown")
            created = api.get("created_date")
            name_lower = name.lower()
            if any(k in name_lower for k in ["test", "demo", "hackathon", "sample", "temp"]) and is_stale(created, days_threshold):
                d_ago = days_ago(created)
                findings.append(finding(
                    "drift", "API Gateway", region, f"{name} ({api_id})",
                    f"Test/demo API created {d_ago}d ago — likely obsolete endpoint",
                    "low",
                    action="Review API usage in CloudWatch and delete obsolete test API",
                    effort="low"
                ))
    return findings


def check_cost_quicksight(account_dir, days_threshold):
    """QuickSight — orphaned datasets with no dashboard associations."""
    findings = []
    path = find_latest_inventory(account_dir, "quicksight")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, reg_data in data.get("regions", {}).items():
        if not isinstance(reg_data, dict):
            continue
        dashboards = reg_data.get("dashboards", [])
        datasets = reg_data.get("datasets", [])
        if datasets and len(dashboards) == 0:
            for ds in datasets:
                name = ds.get("name", "unknown")
                created = ds.get("created_time")
                if is_stale(created, days_threshold):
                    findings.append(finding(
                        "cost", "QuickSight", region, name,
                        f"QuickSight dataset with 0 active dashboards (created {days_ago(created)}d ago)",
                        "info",
                        action="Delete unused QuickSight dataset to free SPICE storage",
                        effort="low"
                    ))
    return findings


def check_cost_apprunner(account_dir, days_threshold):
    """AppRunner — paused or idle services."""
    findings = []
    path = find_latest_inventory(account_dir, "apprunner")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, services in data.get("regions", {}).items():
        if not isinstance(services, list):
            continue
        for svc in services:
            name = svc.get("service_name", "unknown")
            status = svc.get("status", "UNKNOWN")
            if status == "PAUSED":
                findings.append(finding(
                    "cost", "AppRunner", region, name,
                    "AppRunner service is PAUSED — provisioned resources may incur memory retention fees",
                    "low",
                    action="Delete paused AppRunner service if not resuming",
                    effort="low"
                ))
    return findings


def check_cost_fsx(account_dir, days_threshold):
    """FSx — single-AZ file systems in production without high availability."""
    findings = []
    path = find_latest_inventory(account_dir, "fsx")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, fs_list in data.get("regions", {}).items():
        if not isinstance(fs_list, list):
            continue
        for fs in fs_list:
            fs_id = fs.get("file_system_id", "unknown")
            fs_type = fs.get("file_system_type", "unknown")
            # Only flag when deployment type is known to be single-AZ; a missing
            # field means the collector didn't capture it — don't assume single-AZ.
            dep_type = fs.get("deployment_type", "")
            if dep_type.startswith("SINGLE_AZ"):
                findings.append(finding(
                    "reliability", "FSx", region, f"{fs_id} ({fs_type})",
                    f"Single-AZ deployment ({dep_type}) — no automatic failover for storage",
                    "medium",
                    action="Migrate to Multi-AZ FSx file system for production data durability",
                    effort="high"
                ))
    return findings


def check_reliability_direct_connect(account_dir, days_threshold):
    """Direct Connect — degraded or down dedicated connections."""
    findings = []
    path = find_latest_inventory(account_dir, "direct-connect")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for c in region_data.get("connections", []):
            name = c.get("connection_name") or c.get("name", "unknown")
            state = (c.get("state") or c.get("connection_state") or "").lower()
            if state in ("down", "deleted", "rejected"):
                findings.append(finding(
                    "reliability", "Direct Connect", region, name,
                    f"Direct Connect link state is '{state}' — dedicated hybrid link disrupted",
                    "high",
                    action="Investigate circuit status with telecom provider and AWS Direct Connect console",
                    effort="medium"
                ))
    return findings


def check_cost_ebs_gp2_upgrade(account_dir, days_threshold):
    """EBS gp2 volumes that can be upgraded to gp3 for 20% cost savings and better baseline performance."""
    findings = []
    path = find_latest_inventory(account_dir, "ebs")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for vol in region_data.get("volumes", []):
            # Skip unattached volumes — check_cost_ebs_waste already flags them
            # as pure waste; counting a gp2 upgrade too would double-count savings.
            if vol.get("attached") is False:
                continue
            if vol.get("volume_type") == "gp2":
                size_gb = vol.get("size_gb", 0)
                # gp2 is $0.10/GB, gp3 is $0.08/GB -> savings is $0.02/GB-mo
                savings = round(size_gb * 0.02, 2)
                vol_id = vol.get("volume_id", "unknown")
                vol_name = vol.get("name") or vol_id
                findings.append(finding(
                    "cost", "EBS", region,
                    f"{vol_id} ({vol_name})",
                    f"Legacy gp2 volume ({size_gb} GB) — upgrade to gp3 for 20% savings + 3,000 IOPS / 125 MB/s baseline",
                    "medium" if savings > 10 else "low",
                    est_monthly_cost=savings,
                    action="Modify volume type from gp2 to gp3 in EC2 console or IaC (zero downtime, saves $0.02/GB/mo)",
                    effort="low"
                ))
    return findings


def check_security_amg_stale_permissions(account_dir, days_threshold):
    """Managed Grafana (AMG) workspaces with stale users holding active permissions/licenses."""
    findings = []
    path = find_latest_inventory(account_dir, "amg-permissions")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    workspaces = data.get("workspaces", {})
    if isinstance(workspaces, dict):
        for ws_id, ws_info in workspaces.items():
            if not isinstance(ws_info, dict):
                continue
            ws_name = ws_info.get("workspace_name", ws_id)
            region = ws_info.get("region", "global")
            summary = ws_info.get("summary", {})
            stale_count = summary.get("stale_users", 0)
            if stale_count > 0:
                findings.append(finding(
                    "security", "AMG", region,
                    f"{ws_name} ({ws_id})",
                    f"{stale_count} stale/orphaned users with active permissions — offboarding risk & wasted licenses",
                    "high" if stale_count > 5 else "medium",
                    action="Revoke AMG workspace role assignments for stale/offboarded users in IAM Identity Center",
                    effort="low"
                ))
    return findings


def check_security_sqs_unencrypted(account_dir, days_threshold):
    """SQS queues missing server-side encryption (SSE-SQS or AWS KMS)."""
    findings = []
    path = find_latest_inventory(account_dir, "sqs")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if isinstance(region_data, list):
            queues = region_data
        elif isinstance(region_data, dict):
            queues = region_data.get("queues", [])
        else:
            queues = []
        for q in queues:
            # Skip queues whose attributes could not be read — empty defaults
            # would otherwise look like a real unencrypted config.
            if q.get("attributes_available") is False:
                continue
            q_name = q.get("queue_name", q.get("name", "unknown"))
            is_encrypted = bool(
                q.get("kms_key_id")
                or q.get("kms_master_key_id")
                or q.get("sqs_managed_sse_enabled")
            )
            # Older inventories predate the SSE-SQS field; encryption state is unknown.
            if "sqs_managed_sse_enabled" not in q and not q.get("kms_key_id"):
                continue
            if not is_encrypted:
                findings.append(finding(
                    "security", "SQS", region, q_name,
                    "Queue unencrypted at rest — missing SSE-SQS / AWS KMS key",
                    "medium",
                    action="Enable SQS-managed server-side encryption (SSE-SQS) or Customer Managed Key (CMK)",
                    effort="low"
                ))
    return findings


def check_reliability_sqs_dlq(account_dir, days_threshold):
    """SQS queues without a Dead Letter Queue (DLQ) redrive policy."""
    findings = []
    path = find_latest_inventory(account_dir, "sqs")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if isinstance(region_data, list):
            queues = region_data
        elif isinstance(region_data, dict):
            queues = region_data.get("queues", [])
        else:
            queues = []
        for q in queues:
            if q.get("attributes_available") is False:
                continue
            q_name = q.get("queue_name", q.get("name", "unknown"))
            if "dlq" in q_name.lower() or "deadletter" in q_name.lower():
                continue
            has_dlq = bool(q.get("redrive_policy"))
            if not has_dlq:
                findings.append(finding(
                    "reliability", "SQS", region, q_name,
                    "No Dead Letter Queue (DLQ) configured — poisoned messages may be lost or loop indefinitely",
                    "medium",
                    action="Configure redrive policy with maxReceiveCount and a designated Dead Letter Queue",
                    effort="medium"
                ))
    return findings


def check_security_sns_unencrypted(account_dir, days_threshold):
    """SNS topics missing AWS KMS server-side encryption."""
    findings = []
    path = find_latest_inventory(account_dir, "sns")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for topic in region_data.get("topics", []):
            t_name = topic.get("name", topic.get("topic_name", topic.get("topic_arn", topic.get("arn", "unknown")).split(":")[-1]))
            is_encrypted = bool(topic.get("kms_key_id") or topic.get("kms_master_key_id"))
            if not is_encrypted:
                findings.append(finding(
                    "security", "SNS", region, t_name,
                    "Topic unencrypted at rest — missing AWS KMS encryption key",
                    "medium",
                    action="Enable AWS KMS encryption using alias/aws/sns or a Customer Managed Key (CMK)",
                    effort="low"
                ))
    return findings


def check_cost_lambda_graviton(account_dir, days_threshold):
    """Lambda functions running on x86_64 architecture that can switch to arm64 (Graviton2) for 20% cost savings."""
    findings = []
    path = find_latest_inventory(account_dir, "lambda")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        fn_list = region_data if isinstance(region_data, list) else region_data.get("functions", [])
        for fn in fn_list:
            fn_name = fn.get("name", fn.get("function_name", "unknown"))
            arch = fn.get("architectures", ["x86_64"])
            runtime = fn.get("runtime", "")
            is_graviton_ready = any(r in runtime.lower() for r in ["python", "nodejs", "java", "dotnet", "ruby", "provided"])
            if "arm64" not in arch and is_graviton_ready:
                findings.append(finding(
                    "cost", "Lambda", region, fn_name,
                    f"Running on x86_64 ({runtime}) — switch to arm64 (Graviton2) for 20% lower cost and better performance",
                    "low",
                    action="Change function architecture from x86_64 to arm64 in Lambda configuration",
                    effort="low"
                ))
    return findings


def check_security_cloudtrail_inactive(account_dir, days_threshold):
    """CloudTrail trails with logging turned OFF or missing KMS / CloudWatch Logs integration."""
    findings = []
    path = find_latest_inventory(account_dir, "cloudtrail")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, region_data in data.get("regions", {}).items():
        if not isinstance(region_data, dict):
            continue
        for trail in region_data.get("trails", []):
            t_name = trail.get("name", "unknown")
            if not trail.get("kms_key_id"):
                findings.append(finding(
                    "security", "CloudTrail", region, t_name,
                    "CloudTrail log files not encrypted with Customer Managed Key (CMK)",
                    "low",
                    action="Enable AWS KMS CMK encryption for CloudTrail trail log files",
                    effort="low"
                ))
            if not trail.get("cloudwatch_logs_arn"):
                findings.append(finding(
                    "security", "CloudTrail", region, t_name,
                    "CloudTrail not integrated with CloudWatch Logs — real-time alerting disabled",
                    "low",
                    action="Configure CloudTrail to deliver logs to a CloudWatch Logs log group",
                    effort="low"
                ))
    return findings


def check_security_eks(account_dir, days_threshold):
    """EKS clusters with public API server endpoints or missing KMS secrets envelope encryption."""
    findings = []
    path = find_latest_inventory(account_dir, "eks")
    if not path:
        return findings
    data = load_json(path)
    if not data:
        return findings

    for region, clusters in data.get("regions", {}).items():
        if not isinstance(clusters, list):
            continue
        for cluster in clusters:
            c_name = cluster.get("name", "unknown")
            vpc_cfg = cluster.get("vpc_config", {})
            if vpc_cfg.get("endpoint_public"):
                cidrs = vpc_cfg.get("public_access_cidrs", [])
                if not cidrs or "0.0.0.0/0" in cidrs:
                    findings.append(finding(
                        "security", "EKS", region, c_name,
                        "Kubernetes API server endpoint is public and open to 0.0.0.0/0 — exposed to internet",
                        "medium",
                        action="Restrict publicAccessCidrs in EKS cluster VPC config or disable public endpoint",
                        effort="low"
                    ))
            encryption = cluster.get("encryption", {})
            if encryption and not encryption.get("has_secrets_encryption", True):
                findings.append(finding(
                    "security", "EKS", region, c_name,
                    "Kubernetes Secrets KMS envelope encryption is disabled",
                    "low",
                    action="Enable AWS KMS envelope encryption for Kubernetes secrets in EKS cluster",
                    effort="medium"
                ))
    return findings


ALL_CHECKS = [
    # Security
    check_security_ec2_public_ips,
    check_security_rds,
    check_security_redshift,
    check_security_cloudtrail,
    check_security_cloudtrail_inactive,
    check_security_kms,
    check_security_secrets,
    check_security_iam,
    check_security_guardduty,
    check_security_inspector,
    check_security_hub,
    check_security_amg_auth,
    check_security_amg_stale_permissions,
    check_security_documentdb,
    check_security_workspaces_unencrypted,
    check_security_cloudfront,
    check_security_s3,
    check_security_eks,
    check_security_ssm,
    check_security_athena,
    check_security_sqs_unencrypted,
    check_security_sns_unencrypted,
    check_security_ses,
    # Cost
    check_cost_ec2_stopped,
    check_cost_nat_gateways,
    check_cost_vpc_endpoints,
    check_cost_sns_unused,
    check_cost_sqs_dead,
    check_cost_lambda_stale,
    check_cost_lambda_graviton,
    check_cost_efs_empty,
    check_cost_ecr_empty,
    check_cost_dynamodb_overprovisioned,
    check_cost_elb_idle,
    check_cost_ebs_waste,
    check_cost_ebs_gp2_upgrade,
    check_cost_kinesis,
    check_cost_acm_unused,
    check_cost_ecs_scaled_zero,
    check_cost_sagemaker,
    check_cost_bedrock_provisioned,
    check_cost_dms_idle,
    check_cost_msk,
    check_cost_mwaa,
    check_cost_glue_stale,
    check_cost_emr_no_autoterminate,
    check_cost_s3_no_lifecycle,
    check_cost_cloudfront_disabled,
    check_cost_waf_empty,
    check_cost_elasticache,
    check_cost_transit_gateway,
    check_cost_workspaces_idle,
    check_cost_amplify_stale,
    check_cost_cloudwatch_log_retention,
    check_cost_xray_full_sampling,
    check_cost_route53,
    check_cost_network_firewall,
    check_cost_globalaccelerator,
    check_cost_timestream,
    check_cost_quicksight,
    check_cost_apprunner,
    check_cost_fsx,
    # Reliability
    check_reliability_rds,
    check_reliability_eks_version,
    check_reliability_lambda_runtime,
    check_reliability_opensearch,
    check_reliability_ecs_failing,
    check_reliability_dynamodb_no_protection,
    check_reliability_backup_empty,
    check_reliability_security_lake,
    check_reliability_workspaces_unhealthy,
    check_reliability_synthetics,
    check_reliability_amp_status,
    check_reliability_internet_monitor,
    check_reliability_health_events,
    check_reliability_direct_connect,
    check_reliability_sqs_dlq,
    # Drift / Hygiene
    check_drift_rum_no_sampling,
    check_drift_untagged_ec2,
    check_drift_eventbridge_disabled,
    check_drift_config_not_recording,
    check_drift_cloudwatch_alarms,
    check_drift_step_functions_no_logging,
    check_drift_cloudtrail_stale,
    check_drift_api_gateway_stale,
]


# ============================================================
# MAIN
# ============================================================

def resolve_target_account(account_arg=None, profile_arg=None):
    """Resolve target account ID from -a, -p, or available directories in output/."""
    from common import get_accounts, create_session_with_identity

    if account_arg:
        if re.match(r'^\d{12}$', str(account_arg)):
            return str(account_arg)
        try:
            matched = get_accounts(account_arg)
            if matched:
                return matched[0]["account_id"]
        except Exception:
            pass
        return str(account_arg)

    if profile_arg:
        if re.match(r'^\d{12}$', profile_arg):
            return profile_arg
        match = re.match(r'^(\d{12})', profile_arg)
        if match:
            return match.group(1)
        try:
            matched = [a for a in get_accounts() if a.get("profile") == profile_arg]
            if matched:
                return matched[0]["account_id"]
        except Exception:
            pass
        try:
            _, acct_id, _ = create_session_with_identity(profile_arg)
            if acct_id:
                return acct_id
        except Exception:
            pass

    # Fallback: scan valid 12-digit account folders under output/
    candidates = [d.name for d in OUTPUT_DIR.iterdir()
                  if d.is_dir() and re.match(r'^\d{12}$', d.name)]
    if len(candidates) == 1:
        return candidates[0]
    elif len(candidates) > 1:
        print("ERROR: multiple accounts found in output/ — specify one with -a <account_id|name> or -p <profile>:")
        for c in sorted(candidates):
            print(f"  {c}")
        sys.exit(1)
    else:
        print("ERROR: No account inventory output found under output/. Run inventory scripts first.")
        sys.exit(1)


def generate_csv_report(output_data: dict, output_path: Path):
    """Generate a CSV report of all findings for spreadsheets / Jira import."""
    account_id = output_data.get("account_id")
    findings = output_data.get("findings", [])
    fieldnames = [
        "account_id", "severity", "category", "service", "region",
        "resource", "issue", "est_monthly_waste_usd", "action", "effort"
    ]
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in findings:
            writer.writerow({
                "account_id": account_id,
                "severity": item.get("severity", ""),
                "category": item.get("category", ""),
                "service": item.get("service", ""),
                "region": item.get("region", ""),
                "resource": item.get("resource", ""),
                "issue": item.get("issue", ""),
                "est_monthly_waste_usd": item.get("est_monthly_waste_usd", 0.0),
                "action": item.get("action", ""),
                "effort": item.get("effort", "medium"),
            })


def generate_markdown_report(output_data: dict, output_path: Path):
    """Generate a clean GitHub/Notion flavored Markdown summary with Table of Contents, Quick Wins, and Action Playbook."""
    account_id = output_data.get("account_id")
    total_findings = output_data.get("total_findings", 0)
    waste = output_data.get("estimated_monthly_waste_usd", 0)
    sev_counts = output_data.get("findings_by_severity", {})
    cat_counts = output_data.get("findings_by_category", {})
    top_costs = output_data.get("top_cost_savings", [])
    findings = output_data.get("findings", [])
    service_waste = output_data.get("service_waste_breakdown", [])

    critical_high = [f for f in findings if f.get("severity") in ("critical", "high")]
    quick_wins = output_data.get("quick_wins", [])[:15]
    quick_win_savings = sum(f.get("est_monthly_waste_usd", 0) for f in quick_wins)

    toc_links = [
        "- [📊 Executive Summary & Decision Matrix](#executive-summary)",
    ]
    if quick_wins:
        toc_links.append(f"- [🚀 Immediate Quick Wins (Save ${quick_win_savings:,.0f}/mo)](#quick-wins)")
    if top_costs:
        toc_links.append("- [💡 Top Cost Reduction Opportunities](#top-cost-reduction-opportunities)")
    if service_waste:
        toc_links.append("- [📈 Service Waste Breakdown](#service-waste-breakdown)")
    if critical_high:
        toc_links.append(f"- [🔴 Critical & High Findings Checklist ({len(critical_high)})](#critical--high-findings-checklist)")
    toc_links.append("- [📋 3-Phase Action Playbook](#action-playbook)")

    lines = [
        f"# AWS Resource Audit Report — Account `{account_id}`",
        f"\n**Generated**: `{output_data.get('generated')}` | **Staleness Threshold**: `{output_data.get('staleness_threshold_days')} days`\n",
        "## 📑 Table of Contents\n",
        "\n".join(toc_links),
        "\n---\n",
        '<a id="executive-summary"></a>',
        "## 📊 Executive Summary & Decision Matrix\n",
        "| Metric | Value | Action Priority |",
        "| :--- | :--- | :--- |",
        f"| **Account ID** | `{account_id}` | Reference |",
        f"| **Total Findings** | **{total_findings}** | Overall backlog |",
        f"| **Est. Monthly Waste** | **${waste:,.2f} / mo** (${waste * 12:,.2f}/yr) | 💰 High Financial ROI |",
        f"| **Instant Quick Wins** | **${quick_win_savings:,.2f} / mo** (${quick_win_savings * 12:,.2f}/yr) | 🟢 Zero Downtime Actions |",
        f"| **Severity Breakdown** | 🔴 `{sev_counts.get('critical', 0)} Critical` \\| 🟠 `{sev_counts.get('high', 0)} High` \\| 🟡 `{sev_counts.get('medium', 0)} Medium` \\| 🔵 `{sev_counts.get('low', 0)} Low` \\| ⚪ `{sev_counts.get('info', 0)} Info` | 🔴 Fix Critical immediately |",
        f"| **Category Breakdown** | 🔒 `{cat_counts.get('security', 0)} Security` \\| 💰 `{cat_counts.get('cost', 0)} Cost` \\| ⚙️ `{cat_counts.get('reliability', 0)} Reliability` \\| 🧹 `{cat_counts.get('drift', 0)} Drift` | Cross-functional allocation |\n",
    ]

    if quick_wins:
        lines.extend([
            '<a id="quick-wins"></a>',
            f"## 🚀 Immediate Quick Wins (Est. Savings: ${quick_win_savings:,.2f}/mo)\n",
            "> [!TIP]",
            "> These findings have **Low Effort / Zero Downtime Risk** and can be safely cleaned up immediately for instant billing reduction.\n",
            "| Est. Savings | Service | Resource | Issue | Action & Remediation |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])
        for f in quick_wins:
            lines.append(f"| **${f.get('est_monthly_waste_usd', 0):,.0f}/mo** | `{f.get('service')}` | `{f.get('resource')}` | {f.get('issue')} | **{f.get('action')}** |")
        lines.append("")

    if top_costs:
        lines.extend([
            '<a id="top-cost-reduction-opportunities"></a>',
            "## 💡 Top Cost Reduction Opportunities\n",
            "| Est. Waste | Service | Resource | Issue | Recommended Action | Effort |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ])
        for f in top_costs[:15]:
            effort_badge = "🟢 `LOW`" if f.get("effort") == "low" else ("🟡 `MEDIUM`" if f.get("effort") == "medium" else "🔴 `HIGH`")
            lines.append(f"| **${f.get('est_monthly_waste_usd', 0):,.0f}/mo** | `{f.get('service')}` | `{f.get('resource')}` | {f.get('issue')} | {f.get('action')} | {effort_badge} |")
        lines.append("")

    if service_waste:
        lines.extend([
            '<a id="service-waste-breakdown"></a>',
            "## 📈 Service Waste Breakdown\n",
            "| Service | Findings Count | Est. Monthly Waste | Est. Annual Waste | Share of Total Waste |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])
        for sw in service_waste[:10]:
            share = (sw['waste_monthly'] / waste * 100) if waste > 0 else 0
            lines.append(f"| `{sw['service']}` | {sw['count']} | **${sw['waste_monthly']:,.2f}/mo** | ${sw['waste_annual']:,.2f}/yr | {share:.1f}% |")
        lines.append("")

    if critical_high:
        lines.extend([
            '<a id="critical--high-findings-checklist"></a>',
            "## 🔴 Critical & High Findings Checklist\n",
            "| Severity | Category | Service | Region | Resource | Issue | Action & Remediation |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ])
        for f in critical_high:
            sev_badge = "🔴 `CRITICAL`" if f.get("severity") == "critical" else "🟠 `HIGH`"
            lines.append(f"| {sev_badge} | {f.get('category').capitalize()} | `{f.get('service')}` | `{f.get('region')}` | `{f.get('resource')}` | {f.get('issue')} | {f.get('action')} |")
        lines.append("")

    critical_count = sum(1 for f in findings if f.get("severity") == "critical")
    high_count = sum(1 for f in findings if f.get("severity") == "high")
    stopped_ec2 = sum(1 for f in findings if f.get("service") == "EC2" and "Stopped" in f.get("issue", ""))

    lines.extend([
        '<a id="action-playbook"></a>',
        "## 📋 3-Phase Action Playbook\n",
        "### 🟢 Phase 1: Immediate Actions (Today)",
    ])
    if quick_wins:
        lines.append(f"- [ ] 💰 **Execute Quick Wins**: Clean up unattached EBS, unused IPs, empty zones (Est. **${quick_win_savings:,.2f}/mo** savings).")
    if critical_count:
        lines.append(f"- [ ] 🔴 **Remediate {critical_count} CRITICAL vulnerabilities**: Fix exposed public databases/buckets and expired certificates.")
    if stopped_ec2:
        lines.append(f"- [ ] 🛑 **Clean up {stopped_ec2} stopped EC2 instances**: Terminate abandoned servers or snapshot+delete attached EBS volumes.")

    lines.extend([
        "\n### 🟠 Phase 2: Sprint Remediation (Next 2 Weeks)",
    ])
    if high_count:
        lines.append(f"- [ ] 🛡️ **Address {high_count} HIGH severity findings**: Setup secret rotations, upgrade deprecated Lambda runtimes.")
    if waste > 500:
        lines.append(f"- [ ] 📉 **Right-size oversized services**: Review Airflow MWAA, idle ElastiCache clusters, and NAT Gateways.")

    lines.extend([
        "\n### 🔵 Phase 3: Architectural Hardening (Quarterly)",
        "- [ ] ⚙️ **Enable Multi-AZ & Automated Backups**: Eliminate single points of failure for production databases & storage.",
        "- [ ] 🧹 **Tagging & Lifecycle Policies**: Enforce AWS Config rules and auto-archive S3 / CloudWatch log data.",
        "",
    ])

    with open(output_path, 'w') as f:
        f.write("\n".join(lines))


def audit_single_account(account_id: str, args, severity_order: dict, min_severity: int, quiet=False):
    """Run full audit for a single account directory and save reports."""
    account_dir = OUTPUT_DIR / account_id
    if not account_dir.exists():
        print(f"ERROR: No output found for account {account_id}")
        return None

    all_findings = []
    for check_fn in ALL_CHECKS:
        try:
            findings = check_fn(account_dir, args.days)
        except Exception as error:
            print(
                f"WARNING: {check_fn.__name__} failed for account {account_id}: {error}",
                file=sys.stderr,
            )
            continue
        for f in findings:
            if severity_order.get(f.get("severity", "info"), 4) <= min_severity:
                if args.category and f.get("category") != args.category:
                    continue
                all_findings.append(f)

    total_est_savings = sum(f.get("est_monthly_waste_usd", 0) for f in all_findings)

    # Service waste breakdown
    service_waste = {}
    for f in all_findings:
        w = f.get("est_monthly_waste_usd", 0)
        if w > 0:
            svc = f.get("service", "Other")
            if svc not in service_waste:
                service_waste[svc] = {"count": 0, "waste_monthly": 0.0}
            service_waste[svc]["count"] += 1
            service_waste[svc]["waste_monthly"] += w

    sorted_svc_waste = sorted(
        [{"service": k, "count": v["count"], "waste_monthly": round(v["waste_monthly"], 2), "waste_annual": round(v["waste_monthly"] * 12, 2)}
         for k, v in service_waste.items()],
        key=lambda x: x["waste_monthly"], reverse=True
    )

    output_data = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "account_id": account_id,
        "staleness_threshold_days": args.days,
        "total_findings": len(all_findings),
        "estimated_monthly_waste_usd": round(total_est_savings, 2),
        "findings_by_severity": {
            s: sum(1 for f in all_findings if f["severity"] == s)
            for s in severity_order if sum(1 for f in all_findings if f["severity"] == s) > 0
        },
        "findings_by_category": {
            c: sum(1 for f in all_findings if f["category"] == c)
            for c in ["security", "cost", "reliability", "drift"]
            if sum(1 for f in all_findings if f["category"] == c) > 0
        },
        "service_waste_breakdown": sorted_svc_waste,
        "quick_wins": sorted(
            [f for f in all_findings if f.get("est_monthly_waste_usd", 0) > 0 and (f.get("effort") == "low" or "unattached" in f.get("issue", "").lower() or "unassociated" in f.get("issue", "").lower() or "stopped" in f.get("issue", "").lower() or "idle" in f.get("issue", "").lower())],
            key=lambda x: x["est_monthly_waste_usd"], reverse=True
        )[:20],
        "top_cost_savings": sorted(
            [f for f in all_findings if f.get("est_monthly_waste_usd", 0) > 0],
            key=lambda x: x["est_monthly_waste_usd"], reverse=True
        )[:25],
        "findings": all_findings,
    }

    audit_dir = OUTPUT_DIR / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)

    # Clean up old timestamped audit files for this account to keep output/audit clean
    if not getattr(args, 'keep_history', False):
        for old_file in audit_dir.glob(f"audit-report-{account_id}-*.*"):
            try:
                old_file.unlink()
            except Exception:
                pass

    if getattr(args, 'keep_history', False):
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        audit_json = audit_dir / f"audit-report-{account_id}-{timestamp}.json"
        audit_md = audit_dir / f"audit-report-{account_id}-{timestamp}.md"
        audit_csv = audit_dir / f"audit-report-{account_id}-{timestamp}.csv"
    else:
        audit_json = audit_dir / f"audit-report-{account_id}.json"
        audit_md = audit_dir / f"audit-report-{account_id}.md"
        audit_csv = audit_dir / f"audit-report-{account_id}.csv"

    with open(audit_json, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, default=str, ensure_ascii=False)
    if not quiet:
        print(f"  📄 Saved JSON: {audit_json}")

    generate_markdown_report(output_data, audit_md)
    if not quiet:
        print(f"  📝 Saved Markdown: {audit_md}")

    generate_csv_report(output_data, audit_csv)
    if not quiet:
        print(f"  📊 Saved CSV: {audit_csv}")

    return output_data


def main():
    parser = argparse.ArgumentParser(description='AWS Resource Audit — Security, Cost, Reliability & Drift')
    parser.add_argument('--account-id', '-a', default=None,
                        help='Check specific account (ID, Name, or Alias)')
    parser.add_argument('--all', action='store_true',
                        help='Audit all accounts discovered in output/')
    parser.add_argument('--days', '-d', type=int, default=90,
                        help='Staleness threshold in days (default: 90)')
    parser.add_argument('--json', action='store_true',
                        help='Output as JSON (for presentations/reports)')
    parser.add_argument('--markdown', '-m', action='store_true',
                        help='Print Markdown report to stdout')
    parser.add_argument('--csv', action='store_true',
                        help='Print CSV report to stdout')
    parser.add_argument('--keep-history', action='store_true',
                        help='Keep timestamped historical report files instead of overwriting')
    parser.add_argument('--severity', '-s', default=None,
                        choices=['critical', 'high', 'medium', 'low', 'info'],
                        help='Minimum severity to show (this level and everything more severe)')
    parser.add_argument('--category', '-c', default=None,
                        choices=['security', 'cost', 'reliability', 'drift'],
                        help='Filter by category')
    parser.add_argument('--live-pricing', action='store_true',
                        help='Use live AWS Pricing API for cost estimates (needs --profile)')
    parser.add_argument('--profile', '-p', default=None,
                        help='AWS profile for --live-pricing or account resolution (Pricing API is free/read-only)')
    args = parser.parse_args()
    structured_output = args.json or args.markdown or args.csv

    # Optional: live pricing via AWS Pricing API
    if args.live_pricing:
        if not args.profile:
            print("ERROR: --live-pricing requires --profile")
            sys.exit(1)
        global _SESSION
        from common import create_session
        _SESSION = create_session(args.profile)
        if _SESSION is None:
            print(f"ERROR: could not create session for profile {args.profile}")
            sys.exit(1)
        print(f"  💲 Live pricing enabled via profile {args.profile}", file=sys.stderr)

    if not OUTPUT_DIR.exists():
        print(f"ERROR: {OUTPUT_DIR} does not exist. Run inventory scripts first.")
        sys.exit(1)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    min_severity = severity_order.get(args.severity, 4) if args.severity else 4

    # Determine accounts to audit
    accounts_to_audit = []
    if args.all:
        accounts_to_audit = sorted([d.name for d in OUTPUT_DIR.iterdir()
                                     if d.is_dir() and re.match(r'^\d{12}$', d.name)])
        if not accounts_to_audit:
            print("ERROR: No valid account directories found under output/")
            sys.exit(1)
    else:
        acct_id = resolve_target_account(args.account_id, args.profile)
        accounts_to_audit = [acct_id]

    multi_reports = []
    for acct_id in accounts_to_audit:
        if not structured_output:
            print(f"\n🔍 Auditing Account: {acct_id}")
        output_data = audit_single_account(
            acct_id, args, severity_order, min_severity, quiet=structured_output
        )
        if output_data:
            multi_reports.append(output_data)

            if len(accounts_to_audit) == 1:
                all_findings = output_data["findings"]
                total_est_savings = output_data["estimated_monthly_waste_usd"]

                if args.json:
                    print(json.dumps(output_data, indent=2, default=str))
                elif args.markdown:
                    audit_dir = OUTPUT_DIR / "audit"
                    md_path = audit_dir / f"audit-report-{acct_id}.md"
                    if not md_path.exists():
                        md_path = sorted(glob.glob(str(audit_dir / f"audit-report-{acct_id}*.md")), reverse=True)[0]
                    with open(md_path) as f:
                        print(f.read())
                elif args.csv:
                    audit_dir = OUTPUT_DIR / "audit"
                    csv_path = audit_dir / f"audit-report-{acct_id}.csv"
                    if not csv_path.exists():
                        csv_path = sorted(glob.glob(str(audit_dir / f"audit-report-{acct_id}*.csv")), reverse=True)[0]
                    with open(csv_path) as f:
                        print(f.read())
                else:
                    # Console report
                    print()
                    print("=" * 90)
                    print("  AWS RESOURCE AUDIT REPORT")
                    print("  Security • Cost • Reliability • Drift")
                    print("=" * 90)
                    print(f"  Account:               {acct_id}")
                    print(f"  Staleness threshold:   {args.days} days")
                    print(f"  Total findings:        {len(all_findings)}")
                    if total_est_savings > 0:
                        print(f"  💰 Est. monthly waste: ${total_est_savings:,.2f}/mo (${total_est_savings * 12:,.2f}/yr)")
                    print()

                    category_icons = {"security": "🔒", "cost": "💰", "reliability": "⚙️", "drift": "🧹"}
                    print("  📊 BY CATEGORY:")
                    for cat in ["security", "cost", "reliability", "drift"]:
                        count = sum(1 for f in all_findings if f["category"] == cat)
                        if count:
                            icon = category_icons[cat]
                            print(f"    {icon} {cat.upper():<14} {count:>5} findings")
                    print()

                    print("  📊 BY SEVERITY:")
                    severity_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
                    for sev in ["critical", "high", "medium", "low", "info"]:
                        count = sum(1 for f in all_findings if f["severity"] == sev)
                        if count:
                            print(f"    {severity_icons[sev]} {sev.upper():<10} {count:>5}")
                    print()

                    # Quick wins
                    top_costs = output_data.get("top_cost_savings", [])
                    quick_wins = [f for f in top_costs if f.get("effort") == "low" or "unattached" in f.get("issue", "").lower() or "stopped" in f.get("issue", "").lower() or "idle" in f.get("issue", "").lower()][:5]
                    if quick_wins:
                        qw_total = sum(f.get("est_monthly_waste_usd", 0) for f in quick_wins)
                        print(f"  🚀 INSTANT QUICK WINS (Save ${qw_total:,.2f}/mo today — Low Risk):")
                        print(f"  {'─' * 86}")
                        for f in quick_wins:
                            print(f"    ${f['est_monthly_waste_usd']:>8,.0f}/mo  {f['service']:<16} {f['resource'][:35]:<35} -> {f.get('action')[:45]}")
                        print()

                    cost_findings = sorted(
                        [f for f in all_findings if f.get("est_monthly_waste_usd", 0) > 0],
                        key=lambda x: x["est_monthly_waste_usd"], reverse=True
                    )[:10]
                    if cost_findings:
                        print("  💡 TOP COST REDUCTION OPPORTUNITIES:")
                        print(f"  {'─' * 86}")
                        for f in cost_findings:
                            print(f"    ${f['est_monthly_waste_usd']:>8,.0f}/mo  {f['service']:<18} {f['resource'][:40]:<40} {f['issue'][:40]}")
                        print()

                    svc_waste = output_data.get("service_waste_breakdown", [])
                    if svc_waste:
                        print("  📈 SERVICE WASTE BREAKDOWN (TOP 5):")
                        print(f"  {'─' * 86}")
                        for sw in svc_waste[:5]:
                            share = (sw['waste_monthly'] / total_est_savings * 100) if total_est_savings > 0 else 0
                            print(f"    ${sw['waste_monthly']:>8,.2f}/mo  {sw['service']:<18} ({sw['count']:>3} findings, {share:>5.1f}% of total waste)")
                        print()

                    for cat in ["security", "cost", "reliability", "drift"]:
                        items = [f for f in all_findings if f["category"] == cat]
                        if not items:
                            continue

                        icon = category_icons[cat]
                        print(f"  {icon} {cat.upper()} ({len(items)} findings)")
                        print(f"  {'━' * 86}")

                        for sev in ["critical", "high", "medium", "low", "info"]:
                            sev_items = [f for f in items if f["severity"] == sev]
                            if not sev_items:
                                continue
                            print(f"    {severity_icons[sev]} {sev.upper()} ({len(sev_items)})")
                            for f in sev_items[:25]:
                                region = f.get("region", "global")[:12]
                                resource = f["resource"][:35]
                                issue = f["issue"][:50]
                                print(f"      [{region:<12}] {f['service']:<16} {resource:<35} {issue}")
                            if len(sev_items) > 25:
                                print(f"      ... and {len(sev_items) - 25} more")
                        print()

                    print("  " + "=" * 86)
                    print("  📋 3-PHASE ACTION PLAYBOOK:")
                    print("  " + "=" * 86)

                    critical_count = sum(1 for f in all_findings if f["severity"] == "critical")
                    high_count = sum(1 for f in all_findings if f["severity"] == "high")

                    print("  🟢 Phase 1: Immediate Actions (Today)")
                    if quick_wins:
                        print(f"     1. 💰 Execute Quick Wins — Save ${sum(f.get('est_monthly_waste_usd', 0) for f in quick_wins):,.0f}/mo with zero downtime")
                    if critical_count:
                        print(f"     2. 🔴 Fix {critical_count} CRITICAL vulnerabilities immediately (exposed DBs, expired certs)")
                    stopped_ec2 = sum(1 for f in all_findings if f["service"] == "EC2" and "Stopped" in f["issue"])
                    if stopped_ec2:
                        print(f"     3. 🛑 Clean up {stopped_ec2} stopped EC2 instances — terminate or snapshot+delete EBS")

                    print("\n  🟠 Phase 2: Sprint Remediation (Next 2 Weeks)")
                    if high_count:
                        print(f"     4. 🛡️ Address {high_count} HIGH issues (stale credentials, unencrypted SSM, deprecated runtimes)")
                    if total_est_savings > 500:
                        print(f"     5. 📉 Review top waste services — ${total_est_savings:,.0f}/mo total savings potential")

                    print("\n  🔵 Phase 3: Architectural Hardening (Quarterly)")
                    print("     6. ⚙️ Eliminate Single Points of Failure (enable Multi-AZ for RDS/OpenSearch/FSx)")
                    print("     7. 🧹 Enforce AWS Config recording & automated S3/CloudWatch lifecycle rules")
                    print()

    if structured_output and len(multi_reports) > 1:
        if args.json:
            print(json.dumps({"accounts": multi_reports}, indent=2, default=str))
        elif args.csv:
            fieldnames = [
                "account_id", "severity", "category", "service", "region",
                "resource", "issue", "est_monthly_waste_usd", "action", "effort",
            ]
            writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
            writer.writeheader()
            for report in multi_reports:
                for item in report.get("findings", []):
                    writer.writerow({
                        "account_id": report.get("account_id"),
                        **{field: item.get(field, "") for field in fieldnames if field != "account_id"},
                    })
        else:
            audit_dir = OUTPUT_DIR / "audit"
            for report in multi_reports:
                acct_id = report["account_id"]
                paths = sorted(glob.glob(str(audit_dir / f"audit-report-{acct_id}*.md")))
                if paths:
                    with open(paths[-1]) as f:
                        print(f.read())

    # Multi-account consolidated summary table
    if not structured_output and len(multi_reports) > 1:
        print("\n" + "=" * 90)
        print("  🌐 MULTI-ACCOUNT AUDIT SUMMARY")
        print("=" * 90)
        print(f"  {'Account ID':<16} {'Total':<8} {'Critical':<10} {'High':<8} {'Medium':<8} {'Est. Waste/Mo':<15}")
        print(f"  {'-' * 86}")
        total_all_waste = 0
        total_all_findings = 0
        for r in multi_reports:
            acct = r['account_id']
            tot = r['total_findings']
            crit = r['findings_by_severity'].get('critical', 0)
            hi = r['findings_by_severity'].get('high', 0)
            med = r['findings_by_severity'].get('medium', 0)
            w = r['estimated_monthly_waste_usd']
            total_all_waste += w
            total_all_findings += tot
            print(f"  {acct:<16} {tot:<8} {crit:<10} {hi:<8} {med:<8} ${w:>10,.2f}/mo")

        print(f"  {'-' * 86}")
        print(f"  {'TOTAL':<16} {total_all_findings:<8} {'-':<10} {'-':<8} {'-':<8} ${total_all_waste:>10,.2f}/mo")
        print("=" * 90 + "\n")


if __name__ == "__main__":
    main()
