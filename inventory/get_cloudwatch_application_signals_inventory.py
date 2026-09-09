#!/usr/bin/env python3
"""
CloudWatch Application Signals Inventory Scanner
Scans SLOs (Service Level Objectives) and discovered services.

Usage:
    python get_cloudwatch_application_signals_inventory.py                     # All accounts, all regions
    python get_cloudwatch_application_signals_inventory.py -a "TQ Hosted"      # Single account
    python get_cloudwatch_application_signals_inventory.py -p <profile> -r us-east-1
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

SERVICE = "cloudwatch-application-signals"


def scan_region(session, region):
    """Scan Application Signals SLOs in one region. Returns (region_data, counts)."""
    slos = []
    try:
        client = session.client('application-signals', region_name=region, config=BOTO_CONFIG)

        paginator = client.get_paginator('list_service_level_objectives')
        for page in paginator.paginate():
            for s in page.get('SloSummaries', []):
                slos.append({
                    "name": s.get('Name', 'N/A'),
                    "arn": s.get('Arn', ''),
                    "operation_name": s.get('OperationName', ''),
                    "created_at": s.get('CreatedTime', ''),
                    "key_attributes": s.get('KeyAttributes', {}),
                })

    except Exception as e:
        if is_region_unsupported_error(e):
            log_region_skip(region, SERVICE, str(e))
        else:
            logger.warning(f"  {region}: Error — {e}")
        return {}, {"slos": 0}

    if not slos:
        return {}, {"slos": 0}

    return {"slos": slos}, {"slos": len(slos)}


def scan_application_signals(session, regions, writer):
    """Scan Application Signals across all regions in parallel."""
    totals = scan_regions_parallel(
        session, regions, writer, scan_region,
        log_fn=lambda region, c: logger.info(f"  {region}: {c['slos']} SLO(s)"),
    )
    return totals.get("slos", 0)


def main():
    parser = argparse.ArgumentParser(description='CloudWatch Application Signals Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('application-signals')
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

        count = scan_application_signals(session, regions, writer)

        writer.set("total_slos", count)
        writer.set("status", "ok")

        logger.info(f"  Total: {count} SLOs")

    logger.info("=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
