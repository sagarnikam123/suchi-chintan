#!/usr/bin/env python3
"""
CloudWatch RUM (Real User Monitoring) Inventory Scanner
Scans app monitors with state, sampling rate, and telemetry config.

Usage:
    python get_cloudwatch_rum_inventory.py                     # All accounts, all regions
    python get_cloudwatch_rum_inventory.py -a "TQ Hosted"      # Single account
    python get_cloudwatch_rum_inventory.py -p <profile> -r us-east-1
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

SERVICE = "cloudwatch-rum"


def scan_region(session, region):
    """Scan RUM app monitors in one region. Returns (monitors, counts)."""
    monitors = []
    try:
        client = session.client('rum', region_name=region, config=BOTO_CONFIG)

        paginator = client.get_paginator('list_app_monitors')
        for page in paginator.paginate():
            for m in page.get('AppMonitorSummaries', []):
                name = m.get('Name', 'N/A')

                # Detail for sampling + telemetries
                sample_rate = None
                telemetries = []
                domain = ''
                try:
                    detail = client.get_app_monitor(Name=name).get('AppMonitor', {})
                    cfg = detail.get('AppMonitorConfiguration', {}) or {}
                    sample_rate = cfg.get('SessionSampleRate')
                    telemetries = cfg.get('Telemetries', [])
                    domain = detail.get('Domain', '')
                except Exception:
                    pass

                monitors.append({
                    "name": name,
                    "id": m.get('Id', ''),
                    "state": m.get('State', ''),
                    "domain": domain,
                    "session_sample_rate": sample_rate,
                    "telemetries": telemetries,
                    "created_at": m.get('Created', ''),
                    "last_modified": m.get('LastModified', ''),
                })

    except Exception as e:
        if is_region_unsupported_error(e):
            log_region_skip(region, SERVICE, str(e))
        else:
            logger.warning(f"  {region}: Error — {e}")
        return [], {"app_monitors": 0}

    return monitors, {"app_monitors": len(monitors)}


def scan_rum(session, regions, writer):
    """Scan RUM across all regions in parallel."""
    totals = scan_regions_parallel(
        session, regions, writer, scan_region,
        log_fn=lambda region, c: logger.info(f"  {region}: {c['app_monitors']} app monitor(s)"),
    )
    return totals.get("app_monitors", 0)


def main():
    parser = argparse.ArgumentParser(description='CloudWatch RUM Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('rum')
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

        count = scan_rum(session, regions, writer)

        writer.set("total_app_monitors", count)
        writer.set("status", "ok")

        logger.info(f"  Total: {count} app monitors")

    logger.info("=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
