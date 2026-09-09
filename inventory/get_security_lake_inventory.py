#!/usr/bin/env python3
"""
Amazon Security Lake Inventory Scanner
Scans Security Lake data lakes, subscribers, and log sources across regions.

Usage:
    python get_security_lake_inventory.py                  # All accounts, all regions
    python get_security_lake_inventory.py -a "TQ Hosted"   # Single account
    python get_security_lake_inventory.py -p <profile> -r us-east-1
"""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, get_regions, create_session,
    get_output_dir, get_timestamp, add_common_args,
    create_session_with_identity, is_region_unsupported_error, log_region_skip,
    run_with_timer, make_output_filename, IncrementalWriter,
    scan_regions_parallel,
)

SERVICE = "security-lake"


def scan_region(session, region):
    """Scan Security Lake config in one region. Returns (region_data, counts)."""
    data_lakes = []
    subscribers = []
    log_sources = []
    try:
        client = session.client('securitylake', region_name=region, config=BOTO_CONFIG)

        # Data lake(s) configured in this region
        try:
            resp = client.list_data_lakes(regions=[region])
            for dl in resp.get('dataLakes', []):
                enc = dl.get('encryptionConfiguration', {}) or {}
                lifecycle = dl.get('lifecycleConfiguration', {}) or {}
                data_lakes.append({
                    "region": dl.get('region', region),
                    "arn": dl.get('dataLakeArn', ''),
                    "s3_bucket_arn": dl.get('s3BucketArn', ''),
                    "status": dl.get('createStatus', ''),
                    "kms_key_id": enc.get('kmsKeyId', ''),
                    "replication_enabled": bool(dl.get('replicationConfiguration')),
                    "retention_settings": lifecycle.get('transitions', []),
                    "expiration_days": (lifecycle.get('expiration', {}) or {}).get('days'),
                })
        except Exception as e:
            if is_region_unsupported_error(e) or 'AccessDeniedException' in str(e):
                log_region_skip(region, SERVICE, str(e))
                return {}, {"data_lakes": 0, "subscribers": 0, "log_sources": 0}
            raise

        # Subscribers
        try:
            sp = client.get_paginator('list_subscribers')
            for spage in sp.paginate():
                for sub in spage.get('subscribers', []):
                    subscribers.append({
                        "subscriber_id": sub.get('subscriberId', ''),
                        "name": sub.get('subscriberName', ''),
                        "arn": sub.get('subscriberArn', ''),
                        "status": sub.get('subscriberStatus', ''),
                        "access_types": sub.get('accessTypes', []),
                        "created_at": sub.get('createdAt', ''),
                    })
        except Exception:
            pass

        # Log sources (scope to this region — unfiltered returns all regions'
        # sources, double-counting across the parallel region scans)
        try:
            lp = client.get_paginator('list_log_sources')
            for lpage in lp.paginate(regions=[region]):
                for src in lpage.get('sources', []):
                    for s in src.get('sources', []):
                        aws_src = s.get('awsLogSource', {}) or {}
                        if aws_src:
                            log_sources.append({
                                "account": src.get('account', ''),
                                "region": src.get('region', region),
                                "source_name": aws_src.get('sourceName', ''),
                                "source_version": aws_src.get('sourceVersion', ''),
                            })
        except Exception:
            pass

    except Exception as e:
        if is_region_unsupported_error(e):
            log_region_skip(region, SERVICE, str(e))
        else:
            logger.warning(f"  {region}: Error — {e}")
        return {}, {"data_lakes": 0, "subscribers": 0, "log_sources": 0}

    if not (data_lakes or subscribers or log_sources):
        return {}, {"data_lakes": 0, "subscribers": 0, "log_sources": 0}

    region_data = {
        "data_lakes": data_lakes,
        "subscribers": subscribers,
        "log_sources": log_sources,
    }
    return region_data, {
        "data_lakes": len(data_lakes),
        "subscribers": len(subscribers),
        "log_sources": len(log_sources),
    }


def scan_security_lake(session, regions, writer):
    """Scan Security Lake across all regions in parallel."""
    totals = scan_regions_parallel(
        session, regions, writer, scan_region,
        log_fn=lambda region, c: logger.info(
            f"  {region}: {c['data_lakes']} data lake(s), "
            f"{c['subscribers']} subscriber(s), {c['log_sources']} log source(s)"
        ),
    )
    return totals


def main():
    parser = argparse.ArgumentParser(description='Amazon Security Lake Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('securitylake')
    timestamp = get_timestamp()

    if args.profile:
        session, account_id, arn = create_session_with_identity(args.profile)
        if not session:
            sys.exit(1)
        accounts = [{"name": account_id, "account_id": account_id, "profile": args.profile, "_session": session}]

    logger.info(f"Scanning {len(accounts)} account(s) across {len(regions)} region(s)")
    logger.info("=" * 60)

    for account in accounts:
        name = account['name']
        account_id = account['account_id']
        profile = account['profile']

        logger.info(f"🔍 {name} ({account_id})")

        session = account.get("_session") or create_session(profile)
        if not session:
            continue

        output_dir = get_output_dir(account_id, SERVICE)
        writer = IncrementalWriter(output_dir, make_output_filename(SERVICE, account_id, timestamp))
        writer.update({"name": name, "profile_used": profile, "status": "in_progress", "regions": {}})

        totals = scan_security_lake(session, regions, writer)

        writer.set("total_data_lakes", totals.get("data_lakes", 0))
        writer.set("total_subscribers", totals.get("subscribers", 0))
        writer.set("total_log_sources", totals.get("log_sources", 0))
        writer.set("status", "ok")

        logger.info(f"  Total: {totals.get('data_lakes', 0)} data lakes, {totals.get('subscribers', 0)} subscribers, {totals.get('log_sources', 0)} log sources")

    logger.info("=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
