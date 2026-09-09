#!/usr/bin/env python3
"""
Route 53 Inventory Scanner
Scans hosted zones and record counts (Route 53 is global, not regional).

Usage:
    python get_route53_inventory.py                     # All accounts
    python get_route53_inventory.py -a "TQ Automation"   # Single account
    python get_route53_inventory.py -p <profile>
"""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, create_session,
    get_output_dir, get_timestamp, add_common_args,
    create_session_with_identity,
    run_with_timer, make_output_filename, IncrementalWriter,
)


def scan_route53(session, writer):
    """Scan Route 53 hosted zones and record counts."""
    hosted_zones = []
    total_records = 0

    try:
        r53 = session.client('route53', config=BOTO_CONFIG)

        paginator = r53.get_paginator('list_hosted_zones')
        for page in paginator.paginate():
            for zone in page['HostedZones']:
                zone_id = zone['Id'].split('/')[-1]
                record_count = zone.get('ResourceRecordSetCount', 0)

                zone_info = {
                    "zone_id": zone_id,
                    "name": zone['Name'],
                    "private": zone['Config'].get('PrivateZone', False),
                    "record_count": record_count,
                    "comment": zone['Config'].get('Comment', ''),
                }
                hosted_zones.append(zone_info)
                total_records += record_count

        if hosted_zones:
            logger.info(f"  {len(hosted_zones)} hosted zones, {total_records} total records")
            writer.set("hosted_zones", hosted_zones)

    except Exception as e:
        logger.warning(f"  Error: {e}")

    return len(hosted_zones), total_records


def main():
    parser = argparse.ArgumentParser(description='Route 53 Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    timestamp = get_timestamp()

    if args.profile:
        session, account_id, arn = create_session_with_identity(args.profile)
        if not session:
            sys.exit(1)
        accounts = [{"name": account_id, "account_id": account_id, "profile": args.profile, "_session": session}]

    logger.info(f"Scanning {len(accounts)} account(s) (Route 53 is global)")
    logger.info("=" * 60)

    inventory = {
        "generated": timestamp,
        "accounts": {},
        "summary": {"total_hosted_zones": 0, "total_records": 0}
    }

    for account in accounts:
        name = account['name']
        account_id = account['account_id']
        profile = account['profile']

        logger.info(f"🔍 {name} ({account_id})")

        # Reuse session from --profile if already authenticated
        session = account.get("_session") or create_session(profile)
        if not session:
            inventory["accounts"][account_id] = {"name": name, "status": "auth_failed", "hosted_zones": []}
            continue

        output_dir = get_output_dir(account_id, "route53")
        writer = IncrementalWriter(output_dir, make_output_filename("route53", account_id, timestamp))
        writer.update({"name": name, "profile_used": profile, "status": "in_progress", "hosted_zones": []})

        zone_count, records = scan_route53(session, writer)

        writer.set("total_hosted_zones", zone_count)
        writer.set("total_records", records)
        writer.set("status", "ok")

        inventory["accounts"][account_id] = {"name": name, "status": "ok"}
        inventory["summary"]["total_hosted_zones"] += zone_count
        inventory["summary"]["total_records"] += records

    logger.info("" + "=" * 60)
    logger.info("📊 SUMMARY")
    logger.info("=" * 60)
    logger.info(f"  Total Hosted Zones: {inventory['summary']['total_hosted_zones']} (💰 ~${inventory['summary']['total_hosted_zones'] * 0.50:.2f}/mo)")
    logger.info(f"  Total DNS Records: {inventory['summary']['total_records']}")


if __name__ == "__main__":
    run_with_timer(main)
