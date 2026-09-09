#!/usr/bin/env python3
"""
S3 Bucket Inventory Scanner
Scans all configured AWS accounts for S3 buckets with optional metrics and
object-level metadata.

Usage:
    python get_s3_inventory.py                         # All accounts
    python get_s3_inventory.py -a "TQ Primary"         # Single account
    python get_s3_inventory.py --metrics               # Bucket/configuration metrics
    python get_s3_inventory.py --details               # Metrics plus object metadata
    python get_s3_inventory.py --filter logarchival     # Filter bucket names
"""

import sys
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Add parent directory for common imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, create_session,
    get_output_dir, get_timestamp, add_common_args,
    create_session_with_identity, run_with_timer,
    IncrementalWriter, make_output_filename,
)


STORAGE_TYPES = (
    "StandardStorage",
    "StandardIAStorage",
    "OneZoneIAStorage",
    "ReducedRedundancyStorage",
    "GlacierStorage",
    "GlacierInstantRetrievalStorage",
    "GlacierFlexibleRetrievalStorage",
    "GlacierDeepArchiveStorage",
    "IntelligentTieringFAStorage",
    "IntelligentTieringIAStorage",
    "IntelligentTieringAAStorage",
    "IntelligentTieringAIAStorage",
    "IntelligentTieringDAAStorage",
)

REQUEST_METRICS = {
    "AllRequests": "total_requests",
    "GetRequests": "get_requests",
    "PutRequests": "put_requests",
    "DeleteRequests": "delete_requests",
    "PostRequests": "post_requests",
    "ListRequests": "list_requests",
}


def format_size(size_bytes):
    """Format bytes to human-readable binary units."""
    if size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.2f} KB"
    if size_bytes < 1024 ** 3:
        return f"{size_bytes / (1024 ** 2):.2f} MB"
    return f"{size_bytes / (1024 ** 3):.2f} GB"


def _unit_sizes(size_bytes):
    return {
        "size_bytes": int(size_bytes),
        "size_mb": round(size_bytes / (1024 ** 2), 2),
        "size_gb": round(size_bytes / (1024 ** 3), 2),
    }


def _error_code(error):
    return getattr(error, "response", {}).get("Error", {}).get("Code")


def _latest_metric_value(datapoints, statistic):
    if not datapoints:
        return None
    latest = max(datapoints, key=lambda point: point.get("Timestamp", datetime.min.replace(tzinfo=timezone.utc)))
    return latest.get(statistic)


def _get_metric_value(cw, metric_name, dimensions, statistic, start_time, end_time, period):
    try:
        response = cw.get_metric_statistics(
            Namespace="AWS/S3",
            MetricName=metric_name,
            Dimensions=dimensions,
            StartTime=start_time,
            EndTime=end_time,
            Period=period,
            Statistics=[statistic],
        )
        return _latest_metric_value(response.get("Datapoints", []), statistic)
    except Exception:
        return None


def get_bucket_metrics(session, bucket_name):
    """Get storage size and object count from the daily S3 CloudWatch metrics."""
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(days=7)
    try:
        cw = session.client("cloudwatch", region_name="us-east-1", config=BOTO_CONFIG)
    except Exception:
        return {
            "size_bytes": 0,
            "size_mb": 0.0,
            "size_gb": 0.0,
            "size_human": format_size(0),
            "object_count": 0,
        }

    # Sum BucketSizeBytes across every storage type — a StandardStorage-only
    # query reports 0 for IA/Glacier/Intelligent-Tiering buckets, which then
    # escape the audit's size-based lifecycle checks. ponytail: one call per
    # storage type; the per-bucket cost is bounded by the STORAGE_TYPES list.
    total_size = 0
    for storage_type in STORAGE_TYPES:
        size_value = _get_metric_value(
            cw,
            "BucketSizeBytes",
            [
                {"Name": "BucketName", "Value": bucket_name},
                {"Name": "StorageType", "Value": storage_type},
            ],
            "Average",
            start_time,
            now,
            86400,
        )
        if size_value is not None:
            total_size += int(size_value)

    object_count = _get_metric_value(
        cw,
        "NumberOfObjects",
        [
            {"Name": "BucketName", "Value": bucket_name},
            {"Name": "StorageType", "Value": "AllStorageTypes"},
        ],
        "Average",
        start_time,
        now,
        86400,
    )
    object_count = int(object_count) if object_count is not None else 0
    sizes = _unit_sizes(total_size)
    return {
        **sizes,
        "size_human": format_size(total_size),
        "object_count": object_count,
    }


def get_request_metrics(session, bucket_name):
    """Get optional one-minute S3 request metrics for the previous 24 hours."""
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(hours=24)
    try:
        cw = session.client("cloudwatch", region_name="us-east-1", config=BOTO_CONFIG)
    except Exception:
        return {
            "available": False,
            "source": "cloudwatch",
            "window_hours": 24,
            **{field: None for field in REQUEST_METRICS.values()},
        }

    values = {}
    for metric_name, field_name in REQUEST_METRICS.items():
        dimensions = [{"Name": "BucketName", "Value": bucket_name}]
        value = _get_metric_value(
            cw, metric_name, dimensions, "Sum", start_time, now, 86400
        )
        # Request metrics configured with the whole-bucket filter include FilterId.
        if value is None:
            value = _get_metric_value(
                cw,
                metric_name,
                dimensions + [{"Name": "FilterId", "Value": "EntireBucket"}],
                "Sum",
                start_time,
                now,
                86400,
            )
        values[field_name] = int(value) if value is not None else None

    return {
        "available": any(value is not None for value in values.values()),
        "source": "cloudwatch",
        "window_hours": 24,
        **values,
    }


def get_storage_lens_metrics(session, bucket_name, bucket_region):
    """Read published S3 Storage Lens metrics when CloudWatch publishing is enabled."""
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(days=7)
    try:
        cw = session.client("cloudwatch", region_name="us-east-1", config=BOTO_CONFIG)
        listed = cw.list_metrics(
            Namespace="AWS/S3/Storage-Lens",
            MetricName="StorageBytes",
            Dimensions=[{"Name": "BucketName", "Value": bucket_name}],
        ).get("Metrics", [])
    except Exception:
        return {
            "available": False,
            "source": "cloudwatch",
            "status": "unavailable",
            "storage_bytes": None,
            "object_count": None,
        }

    candidates = []
    for metric in listed:
        dimensions = metric.get("Dimensions", [])
        values = {item.get("Name"): item.get("Value") for item in dimensions}
        if values.get("BucketName") != bucket_name:
            continue
        if values.get("RecordType") not in (None, "BUCKET"):
            continue
        candidates.append(metric)

    if not candidates:
        return {
            "available": False,
            "source": "cloudwatch",
            "status": "not_published",
            "storage_bytes": None,
            "object_count": None,
        }

    # Prefer a bucket total series; otherwise aggregate the published storage-class series.
    bucket_totals = [
        metric for metric in candidates
        if not any(item.get("Name") == "StorageClass" for item in metric.get("Dimensions", []))
    ]
    selected = bucket_totals or candidates
    configuration_ids = {
        item.get("Value")
        for metric in selected
        for item in metric.get("Dimensions", [])
        if item.get("Name") == "ConfigurationId"
    }
    if configuration_ids:
        configuration_id = sorted(configuration_ids)[0]
        selected = [
            metric for metric in selected
            if any(
                item.get("Name") == "ConfigurationId" and item.get("Value") == configuration_id
                for item in metric.get("Dimensions", [])
            )
        ]

    def read_storage_lens_metric(metric_name, metric):
        try:
            response = cw.get_metric_statistics(
                Namespace="AWS/S3/Storage-Lens",
                MetricName=metric_name,
                Dimensions=metric.get("Dimensions", []),
                StartTime=start_time,
                EndTime=now,
                Period=86400,
                Statistics=["Average"],
            )
            return _latest_metric_value(response.get("Datapoints", []), "Average")
        except Exception:
            return None

    storage_bytes = sum(
        value for value in (read_storage_lens_metric("StorageBytes", metric) for metric in selected)
        if value is not None
    )
    object_count = sum(
        value for value in (read_storage_lens_metric("ObjectCount", metric) for metric in selected)
        if value is not None
    )
    available = bool(storage_bytes or object_count)
    result = {
        "available": available,
        "source": "cloudwatch",
        "status": "published" if available else "no_recent_data",
        "region": bucket_region,
        "storage_bytes": int(storage_bytes) if available else None,
        "object_count": int(object_count) if available else None,
    }
    if configuration_ids:
        result["configuration_id"] = sorted(configuration_ids)[0]
    return result


def get_bucket_region(s3_client, bucket_name):
    """Return the bucket region, including legacy S3 location values."""
    try:
        location = s3_client.get_bucket_location(Bucket=bucket_name).get("LocationConstraint")
        if location in (None, ""):
            return "us-east-1"
        if location == "EU":
            return "eu-west-1"
        return location
    except Exception:
        return "unknown"


def get_replication_summary(s3_client, bucket_name, bucket_region):
    """Summarize replication configuration and identify cross-Region rules."""
    try:
        response = s3_client.get_bucket_replication(Bucket=bucket_name)
    except Exception as error:
        if _error_code(error) in ("ReplicationConfigurationNotFoundError", "NoSuchReplicationConfiguration"):
            return {
                "enabled": False,
                "cross_region_enabled": False,
                "status": "not_configured",
                "rules": [],
            }
        return {
            "enabled": None,
            "cross_region_enabled": None,
            "status": "unavailable",
            "error_code": _error_code(error) or "unknown",
            "rules": [],
        }

    rules = []
    enabled_rules = []
    unknown_region_rule = False
    cross_region_enabled = False
    for rule in response.get("ReplicationConfiguration", {}).get("Rules", []):
        status = rule.get("Status", "Enabled")
        destination = rule.get("Destination") or {}
        destination_arn = destination.get("Bucket", "")
        destination_bucket = destination_arn.split(":::", 1)[-1] if ":::" in destination_arn else None
        destination_region = destination.get("Region")
        if not destination_region and destination_bucket:
            destination_region = get_bucket_region(s3_client, destination_bucket)
        if destination_region == "unknown":
            destination_region = None

        rule_summary = {
            "id": rule.get("ID"),
            "status": status,
            "destination_bucket": destination_bucket or destination_arn or None,
            "destination_region": destination_region,
        }
        rules.append(rule_summary)
        if status != "Disabled":
            enabled_rules.append(rule_summary)
            if destination_region is None:
                unknown_region_rule = True
            elif bucket_region != "unknown" and destination_region != bucket_region:
                cross_region_enabled = True

    if not cross_region_enabled and unknown_region_rule:
        cross_region_value = None
    else:
        cross_region_value = cross_region_enabled

    return {
        "enabled": bool(enabled_rules),
        "cross_region_enabled": cross_region_value,
        "status": "configured" if enabled_rules else "disabled",
        "rules": rules,
    }


def _summarize_lifecycle_rule(rule):
    actions = {}
    for key in (
        "Expiration",
        "Transitions",
        "NoncurrentVersionExpiration",
        "NoncurrentVersionTransitions",
        "AbortIncompleteMultipartUpload",
    ):
        if key in rule:
            actions[key] = rule[key]
    return {
        "id": rule.get("ID"),
        "status": rule.get("Status"),
        "filter": rule.get("Filter", {"Prefix": rule.get("Prefix", "")}),
        "actions": actions,
    }


def get_lifecycle_summary(s3_client, bucket_name):
    """Return whether data retention is configured and how many days."""
    try:
        response = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
    except Exception as error:
        if _error_code(error) in ("NoSuchLifecycleConfiguration", "NoSuchBucket"):
            return {
                "retention_configured": False,
                "retention_days": None,
                "transitions": [],
                "abort_incomplete_multipart_days": None,
            }
        return {
            "retention_configured": None,
            "retention_days": None,
            "transitions": [],
            "abort_incomplete_multipart_days": None,
            "error": "unavailable",
        }

    raw_rules = response.get("Rules", [])
    retention_days = []
    transitions = []
    abort_days = None

    for rule in raw_rules:
        if rule.get("Status") != "Enabled":
            continue
        # Expiration
        expiration = rule.get("Expiration", {})
        if isinstance(expiration, dict) and expiration.get("Days") is not None:
            retention_days.append(expiration["Days"])
        # Noncurrent version expiration
        noncurrent = rule.get("NoncurrentVersionExpiration", {})
        if isinstance(noncurrent, dict) and noncurrent.get("NoncurrentDays") is not None:
            retention_days.append(noncurrent["NoncurrentDays"])
        # Storage-class transitions
        for t in rule.get("Transitions", []):
            storage_class = t.get("StorageClass", "unknown")
            days = t.get("Days")
            if days is not None:
                transitions.append(f"{storage_class} after {days}d")
        for t in rule.get("NoncurrentVersionTransitions", []):
            storage_class = t.get("StorageClass", "unknown")
            days = t.get("NoncurrentDays")
            if days is not None:
                transitions.append(f"{storage_class} after {days}d (noncurrent)")
        # Abort incomplete multipart upload
        abort = rule.get("AbortIncompleteMultipartUpload", {})
        if isinstance(abort, dict) and abort.get("DaysAfterInitiation") is not None:
            abort_days = abort["DaysAfterInitiation"]

    return {
        "retention_configured": bool(retention_days),
        "retention_days": sorted(set(retention_days)) if retention_days else None,
        "transitions": sorted(set(transitions)) if transitions else [],
        "abort_incomplete_multipart_days": abort_days,
    }


def get_encryption_summary(s3_client, bucket_name):
    """Return bucket default encryption status without treating API errors as unencrypted."""
    try:
        response = s3_client.get_bucket_encryption(Bucket=bucket_name)
        rules = response.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        algorithms = [
            rule.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
            for rule in rules
        ]
        algorithms = [algorithm for algorithm in algorithms if algorithm]
        return {
            "enabled": bool(algorithms),
            "algorithm": algorithms[0] if algorithms else None,
            "status": "configured" if algorithms else "not_configured",
        }
    except Exception as error:
        if _error_code(error) in (
            "ServerSideEncryptionConfigurationNotFoundError",
            "NoSuchBucket",
        ):
            return {"enabled": False, "algorithm": None, "status": "not_configured"}
        return {
            "enabled": None,
            "algorithm": None,
            "status": "unavailable",
            "error_code": _error_code(error) or "unknown",
        }


def get_public_access_block_summary(s3_client, bucket_name):
    """Return bucket Public Access Block configuration."""
    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        pab = response.get("PublicAccessBlockConfiguration", {})
        block_acls = pab.get("BlockPublicAcls", False)
        ignore_acls = pab.get("IgnorePublicAcls", False)
        block_policy = pab.get("BlockPublicPolicy", False)
        restrict_buckets = pab.get("RestrictPublicBuckets", False)
        return {
            "status": "configured",
            "block_public_acls": block_acls,
            "ignore_public_acls": ignore_acls,
            "block_public_policy": block_policy,
            "restrict_public_buckets": restrict_buckets,
            "all_blocked": all([block_acls, ignore_acls, block_policy, restrict_buckets]),
        }
    except Exception as error:
        if _error_code(error) in ("NoSuchPublicAccessBlockConfiguration", "NoSuchBucket"):
            return {
                "status": "not_configured",
                "block_public_acls": False,
                "ignore_public_acls": False,
                "block_public_policy": False,
                "restrict_public_buckets": False,
                "all_blocked": False,
            }
        return {
            "status": "unavailable",
            "all_blocked": None,
            "error_code": _error_code(error) or "unknown",
        }


def get_versioning_summary(s3_client, bucket_name):
    """Return bucket versioning status and MFA delete setting."""
    try:
        response = s3_client.get_bucket_versioning(Bucket=bucket_name)
        status = response.get("Status", "Suspended")
        return {
            "status": status,
            "enabled": status == "Enabled",
            "mfa_delete": response.get("MfaDelete", "Disabled"),
        }
    except Exception as error:
        if _error_code(error) == "NoSuchBucket":
            return {"status": "not_configured", "enabled": False, "mfa_delete": "Disabled"}
        return {"status": "unavailable", "enabled": None, "error_code": _error_code(error) or "unknown"}


def get_object_lock_summary(s3_client, bucket_name):
    """Return default Object Lock retention where the bucket has it enabled."""
    try:
        response = s3_client.get_object_lock_configuration(Bucket=bucket_name)
        configuration = response.get("ObjectLockConfiguration", {})
        return {
            "enabled": configuration.get("ObjectLockEnabled") == "Enabled",
            "default_retention": configuration.get("Rule", {}).get("DefaultRetention"),
            "status": "configured",
        }
    except Exception as error:
        if _error_code(error) in ("ObjectLockConfigurationNotFoundError", "NoSuchObjectLockConfiguration"):
            return {"enabled": False, "default_retention": None, "status": "not_configured"}
        return {
            "enabled": None,
            "default_retention": None,
            "status": "unavailable",
            "error_code": _error_code(error) or "unknown",
        }


def _age_bucket(age_days):
    if age_days <= 30:
        return "0_30_days"
    if age_days <= 90:
        return "31_90_days"
    if age_days <= 180:
        return "91_180_days"
    if age_days <= 365:
        return "181_365_days"
    return "over_365_days"


def get_object_inventory(s3_client, bucket_name):
    """List current objects and aggregate storage class and age information.

    Returns access_denied=True when the bucket policy blocks ListBucket.
    """
    now = datetime.now(timezone.utc)
    storage_classes = {}
    total_size = 0
    object_count = 0
    newest = None
    oldest = None

    try:
        paginator = s3_client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            for item in page.get("Contents", []):
                size = int(item.get("Size", 0))
                storage_class = item.get("StorageClass", "STANDARD")
                last_modified = item.get("LastModified")
                if last_modified and last_modified.tzinfo is None:
                    last_modified = last_modified.replace(tzinfo=timezone.utc)

                class_entry = storage_classes.setdefault(storage_class, {"object_count": 0, "size_bytes": 0})
                class_entry["object_count"] += 1
                class_entry["size_bytes"] += size
                total_size += size
                object_count += 1

                if last_modified:
                    newest = max(newest, last_modified) if newest else last_modified
                    oldest = min(oldest, last_modified) if oldest else last_modified
    except Exception as error:
        if _error_code(error) == "AccessDenied":
            return {
                "access_denied": True,
                "object_count": None,
                "size_bytes": None,
                "size_mb": None,
                "size_gb": None,
                "size_human": None,
                "storage_class_breakdown": {},
                "newest_object_last_modified": None,
                "oldest_object_last_modified": None,
            }
        raise

    return {
        "object_count": object_count,
        **_unit_sizes(total_size),
        "size_human": format_size(total_size),
        "storage_class_breakdown": storage_classes,
        "newest_object_last_modified": newest.isoformat() if newest else None,
        "oldest_object_last_modified": oldest.isoformat() if oldest else None,
    }


MAX_WORKERS = 10  # ponytail: 10 threads balances throughput vs API throttling; increase if account has high S3 API limits


def _flush_bucket(writer, entry, lock):
    """Thread-safe: append a completed bucket entry to the incremental writer and flush to disk."""
    with lock:
        data = writer.get_data()
        data.setdefault("buckets", []).append(entry)
        writer.set("buckets", data["buckets"])


def _collect_single_bucket(session, bucket, include_metrics, include_details):
    """Collect all metrics/config for one bucket. Runs in a worker thread.

    Creates its own S3 client: botocore clients are not safe to share across
    threads, so each worker gets a dedicated client.
    """
    s3_client = session.client("s3", config=BOTO_CONFIG)
    try:
        bucket_name = bucket["Name"]
        bucket_region = get_bucket_region(s3_client, bucket_name)
        entry = {
            "bucket_name": bucket_name,
            "region": bucket_region,
            "created": str(bucket.get("CreationDate", "")) if bucket.get("CreationDate") else "",
        }

        if include_metrics:
            entry.update(get_bucket_metrics(session, bucket_name))
            request_metrics = get_request_metrics(session, bucket_name)
            if request_metrics.get("available"):
                entry["request_metrics"] = request_metrics
            entry["public_access_block"] = get_public_access_block_summary(s3_client, bucket_name)
            entry["versioning"] = get_versioning_summary(s3_client, bucket_name)
            entry["replication"] = get_replication_summary(s3_client, bucket_name, bucket_region)
            entry["lifecycle"] = get_lifecycle_summary(s3_client, bucket_name)
            entry["encryption"] = get_encryption_summary(s3_client, bucket_name)
            entry["object_lock"] = get_object_lock_summary(s3_client, bucket_name)
            try:
                tagging = s3_client.get_bucket_tagging(Bucket=bucket_name)
                entry["tags"] = {t["Key"]: t["Value"] for t in tagging.get("TagSet", [])}
            except Exception:
                entry["tags"] = {}

        if include_details:
            entry["storage_lens"] = get_storage_lens_metrics(session, bucket_name, bucket_region)
            object_inventory = get_object_inventory(s3_client, bucket_name)
            if object_inventory.get("access_denied"):
                entry["access_denied"] = True
            else:
                entry["storage_class"] = (
                    next(iter(object_inventory["storage_class_breakdown"]))
                    if len(object_inventory["storage_class_breakdown"]) == 1
                    else "MULTIPLE"
                )
                entry.update({
                    "size_bytes": object_inventory["size_bytes"],
                    "size_mb": object_inventory["size_mb"],
                    "size_gb": object_inventory["size_gb"],
                    "size_human": object_inventory["size_human"],
                    "object_count": object_inventory["object_count"],
                    "newest_object_last_modified": object_inventory["newest_object_last_modified"],
                    "oldest_object_last_modified": object_inventory["oldest_object_last_modified"],
                })

        if include_metrics:
            logger.info(f"  {bucket_name} - done")

        return entry
    finally:
        try:
            s3_client.close()
        except Exception:
            pass


def scan_s3_buckets(session, include_metrics=False, name_filter=None, include_details=False, on_bucket_collected=None):
    """Scan S3 buckets for the account, collecting metrics in parallel."""
    try:
        s3_client = session.client("s3", config=BOTO_CONFIG)
        response = s3_client.list_buckets()
        all_buckets = response.get("Buckets", [])

        filtered = [
            bucket for bucket in all_buckets
            if not name_filter or name_filter.lower() in bucket["Name"].lower()
        ]

        if not include_metrics and not include_details:
            # Fast path: no API calls per bucket needed
            buckets = []
            for bucket in filtered:
                bucket_name = bucket["Name"]
                bucket_region = get_bucket_region(s3_client, bucket_name)
                entry = {
                    "bucket_name": bucket_name,
                    "region": bucket_region,
                    "created": bucket.get("CreationDate", ""),
                }
                buckets.append(entry)
                if on_bucket_collected:
                    on_bucket_collected(entry)
            logger.info(
                f"  {len(buckets)} buckets found"
                + (f" (filtered by '{name_filter}')" if name_filter else "")
            )
            return buckets

        # Parallel collection — each bucket's metrics are independent I/O
        buckets = []
        lock = threading.Lock()
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(
                    _collect_single_bucket, session, bucket, include_metrics, include_details
                ): bucket["Name"]
                for bucket in filtered
            }
            for future in as_completed(futures):
                bucket_name = futures[future]
                try:
                    entry = future.result()
                except Exception as error:
                    logger.info(f"  {bucket_name} - skipped ({_error_code(error) or 'error'})")
                    entry = {"bucket_name": bucket_name, "access_denied": True}
                buckets.append(entry)
                if on_bucket_collected:
                    on_bucket_collected(entry)

        logger.info(
            f"  {len(buckets)} buckets found"
            + (f" (filtered by '{name_filter}')" if name_filter else "")
        )
        return buckets

    except Exception as error:
        logger.error(f"  Error listing buckets: {error}")
        return []


def main():
    parser = argparse.ArgumentParser(description="S3 Bucket Inventory Scanner")
    add_common_args(parser)
    parser.add_argument("--filter", "-f", help="Filter bucket names containing this string", default=None)
    parser.add_argument("--metrics", action="store_true",
                        help="Collect bucket size, request, config, replication, lifecycle, encryption metrics")
    parser.add_argument("--details", action="store_true",
                        help="Metrics plus per-object inventory (storage class, age, Storage Lens). Implies --metrics.")
    args = parser.parse_args()

    # --details is a superset of --metrics. Default (neither flag) = fast bucket list.
    include_details = args.details
    include_metrics = args.metrics or args.details

    accounts = get_accounts(args.account)
    timestamp = get_timestamp()

    # If --profile is used, bypass accounts.yaml entirely
    if args.profile:
        session, account_id, arn = create_session_with_identity(args.profile)
        if not session:
            sys.exit(1)
        accounts = [{"name": account_id, "account_id": account_id, "profile": args.profile, "_session": session}]

    logger.info(f"Scanning {len(accounts)} account(s)")
    logger.info("=" * 60)

    total_buckets = 0

    for account in accounts:
        name = account["name"]
        account_id = account["account_id"]
        profile = account["profile"]

        if account.get("enabled") is False:
            logger.info(f"⏭️  {name} ({account_id}) — skipped (disabled)")
            continue

        logger.info(f"🔍 {name} ({account_id}) — profile: {profile}")

        # Reuse session from --profile if already authenticated
        session = account.get("_session") or create_session(profile)
        if not session:
            output_dir = get_output_dir(account_id, "s3")
            writer = IncrementalWriter(output_dir, make_output_filename("s3", account_id, timestamp))
            writer.update({"name": name, "status": "auth_failed", "buckets": []})
            continue

        # Per-account incremental writer — flushes after every bucket
        output_dir = get_output_dir(account_id, "s3")
        writer = IncrementalWriter(output_dir, make_output_filename("s3", account_id, timestamp))
        writer.update({
            "name": name,
            "profile_used": profile,
            "status": "ok",
            "total_buckets": 0,
            "buckets": [],
        })

        writer_lock = threading.Lock()
        buckets = scan_s3_buckets(
            session,
            include_metrics=include_metrics,
            name_filter=args.filter,
            include_details=include_details,
            on_bucket_collected=lambda entry: _flush_bucket(writer, entry, writer_lock),
        )

        writer.set("total_buckets", len(buckets))
        total_buckets += len(buckets)

    # Summary
    logger.info("" + "=" * 60)
    logger.info("📊 SUMMARY")
    logger.info("=" * 60)
    logger.info(f"  Total S3 Buckets: {total_buckets}")


if __name__ == "__main__":
    run_with_timer(main)
