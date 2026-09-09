#!/usr/bin/env python3
"""
KMS Key Inventory Scanner
Scans KMS keys in parallel across enabled regions.

Usage:
    python get_kms_inventory.py -p <profile>
    python get_kms_inventory.py -p <profile> -r us-east-1
"""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, get_regions, create_session,
    get_output_dir, get_timestamp, add_common_args,
    create_session_with_identity, is_region_unsupported_error, log_region_skip,
    IncrementalWriter, make_output_filename,
    run_with_timer, scan_regions_parallel,
)

SERVICE = "kms"


def scan_region(session, region):
    """Scan KMS keys in one region. Returns (region_data, counts)."""
    region_data = []
    counts = {"keys": 0, "customer_managed": 0, "aws_managed": 0}

    try:
        kms = session.client('kms', region_name=region, config=BOTO_CONFIG)

        paginator = kms.get_paginator('list_keys')
        for page in paginator.paginate():
            for key in page.get('Keys', []):
                try:
                    desc = kms.describe_key(KeyId=key['KeyId'])
                    meta = desc['KeyMetadata']

                    key_info = {
                        "key_id": meta['KeyId'],
                        "description": meta.get('Description', ''),
                        "state": meta.get('KeyState', ''),
                        "key_manager": meta.get('KeyManager', ''),
                        "key_spec": meta.get('KeySpec', ''),
                        "key_usage": meta.get('KeyUsage', ''),
                        "creation_date": meta.get('CreationDate', ''),
                        "enabled": meta.get('Enabled', False),
                        "multi_region": meta.get('MultiRegion', False),
                    }
                    region_data.append(key_info)

                    if meta.get('KeyManager') == 'CUSTOMER':
                        counts["customer_managed"] += 1
                    else:
                        counts["aws_managed"] += 1

                except Exception:
                    continue

        counts["keys"] = len(region_data)

    except Exception as e:
        if is_region_unsupported_error(e):
            log_region_skip(region, SERVICE, str(e))
            return [], counts
        logger.warning(f"  {region}: Error — {e}")
        return [], counts

    return region_data, counts


def scan_kms(session, regions, writer):
    """Scan KMS keys in parallel across all regions."""
    totals = scan_regions_parallel(
        session, regions, writer, scan_region,
        log_fn=lambda region, c: logger.info(f"  {region}: {c['keys']} key(s)") if c.get('keys', 0) > 0 else None,
    )
    return totals


def main():
    parser = argparse.ArgumentParser(description='KMS Key Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    if args.profile:
        session, account_id, arn = create_session_with_identity(args.profile)
        if not session:
            sys.exit(1)
        accounts = [{"name": account_id, "account_id": account_id, "profile": args.profile, "_session": session}]
    else:
        accounts = get_accounts(args.account)

    regions = [args.region] if args.region else get_regions('kms')
    timestamp = get_timestamp()

    logger.info(f"Scanning {len(accounts)} account(s) across {len(regions)} region(s)")
    logger.info("=" * 60)

    for account in accounts:
        name = account['name']
        account_id = account['account_id']
        profile = account['profile']

        logger.info(f"🔍 {name} ({account_id}) — profile: {profile}")

        session = account.get("_session") or create_session(profile)
        if not session:
            continue

        output_dir = get_output_dir(account_id, SERVICE)
        writer = IncrementalWriter(output_dir, make_output_filename(SERVICE, account_id, timestamp))
        writer.update({"name": name, "profile_used": profile, "status": "in_progress", "regions": {}})

        totals = scan_kms(session, regions, writer)

        writer.set("total_keys", totals.get("keys", 0))
        writer.set("customer_managed", totals.get("customer_managed", 0))
        writer.set("aws_managed", totals.get("aws_managed", 0))
        writer.set("status", "ok")

        logger.info(f"  Total: {totals.get('keys', 0)} keys ({totals.get('customer_managed', 0)} customer, {totals.get('aws_managed', 0)} AWS-managed)")

    logger.info("=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
