#!/usr/bin/env python3
"""
CloudWatch Inventory Scanner
Scans log groups, alarms, and dashboards across all configured accounts/regions.
Data is flushed to disk incrementally per region — partial results are saved on crash.

Usage:
    python get_cloudwatch_inventory.py                     # All accounts
    python get_cloudwatch_inventory.py -a "TQ Hosted"      # Single account
    python get_cloudwatch_inventory.py -p <profile> -r us-east-1
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

SERVICE = "cloudwatch"


def scan_region(session, region):
    """Scan CloudWatch log groups, alarms, dashboards in one region.
    Returns (region_data, counts)."""
    region_data = {"log_groups": [], "alarms": []}

    try:
        logs_client = session.client('logs', region_name=region, config=BOTO_CONFIG)
        cw_client = session.client('cloudwatch', region_name=region, config=BOTO_CONFIG)

        # Log Groups
        paginator = logs_client.get_paginator('describe_log_groups')
        for page in paginator.paginate():
            for lg in page['logGroups']:
                stored_bytes = lg.get('storedBytes', 0)
                region_data["log_groups"].append({
                    "name": lg['logGroupName'],
                    "stored_bytes": stored_bytes,
                    "stored_gb": round(stored_bytes / (1024**3), 2),
                    "retention_days": lg.get('retentionInDays', 'Never expire'),
                    "created_at": lg.get('creationTime', 0),
                })

        # Alarms
        paginator = cw_client.get_paginator('describe_alarms')
        for page in paginator.paginate():
            for alarm in page.get('MetricAlarms', []):
                region_data["alarms"].append({
                    "name": alarm['AlarmName'],
                    "state": alarm['StateValue'],
                    "metric": alarm.get('MetricName', 'N/A'),
                    "namespace": alarm.get('Namespace', 'N/A'),
                    "statistic": alarm.get('Statistic', ''),
                    "period": alarm.get('Period', 0),
                    "comparison": alarm.get('ComparisonOperator', ''),
                    "threshold": alarm.get('Threshold', 0),
                    "actions": alarm.get('AlarmActions', []),
                })

    except Exception as e:
        if is_region_unsupported_error(e):
            log_region_skip(region, SERVICE, str(e))
        else:
            logger.warning(f"  {region}: Error — {e}")
        return {}, {"log_groups": 0, "alarms": 0, "stored_bytes": 0}

    stored = sum(lg["stored_bytes"] for lg in region_data["log_groups"])
    counts = {
        "log_groups": len(region_data["log_groups"]),
        "alarms": len(region_data["alarms"]),
        "stored_bytes": stored,
    }

    # Empty region → return falsy so the helper skips the flush + log line
    if not (region_data["log_groups"] or region_data["alarms"]):
        return {}, counts

    region_data["total_log_groups"] = counts["log_groups"]
    region_data["total_alarms"] = counts["alarms"]
    region_data["stored_bytes"] = stored
    return region_data, counts


def scan_dashboards(session, regions):
    """List CloudWatch dashboards once. Dashboards are a global (per-account)
    resource — list_dashboards returns the same set in every region, so we
    query a single region to avoid counting them N times."""
    # Use a region we're scanning if it's a standard one, else us-east-1 —
    # avoids opt-in regions (regions[0] could be one) that reject the call.
    region = "us-east-1" if (not regions or "us-east-1" in regions) else regions[0]
    try:
        cw = session.client('cloudwatch', region_name=region, config=BOTO_CONFIG)
        resp = cw.list_dashboards()
        return [{"name": d['DashboardName'], "size": d.get('Size', 0)}
                for d in resp.get('DashboardEntries', [])]
    except Exception as e:
        logger.warning(f"  dashboards: {e}")
        return []


def scan_cloudwatch(session, regions, writer):
    """Scan CloudWatch across all regions in parallel."""
    totals = scan_regions_parallel(
        session, regions, writer, scan_region,
        log_fn=lambda region, c: logger.info(
            f"  {region}: {c['log_groups']} log groups "
            f"({c['stored_bytes'] / (1024**3):.2f} GB), {c['alarms']} alarms"
        ),
    )
    # Dashboards are account-global — fetch once, not per region.
    dashboards = scan_dashboards(session, regions)
    if dashboards:
        writer.set("dashboards", dashboards)
        logger.info(f"  dashboards (global): {len(dashboards)}")
    totals["dashboards"] = len(dashboards)
    return totals


def main():
    parser = argparse.ArgumentParser(description='CloudWatch Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('logs')
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

        totals = scan_cloudwatch(session, regions, writer)

        writer.set("total_log_groups", totals.get("log_groups", 0))
        writer.set("total_alarms", totals.get("alarms", 0))
        writer.set("total_dashboards", totals.get("dashboards", 0))
        writer.set("total_stored_gb", round(totals.get("stored_bytes", 0) / (1024**3), 2))
        writer.set("status", "ok")

        logger.info(f"📊 {name}: {totals.get('log_groups', 0)} log groups, "
                    f"{totals.get('alarms', 0)} alarms, "
                    f"{round(totals.get('stored_bytes', 0) / (1024**3), 1)} GB stored")

    logger.info("=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
