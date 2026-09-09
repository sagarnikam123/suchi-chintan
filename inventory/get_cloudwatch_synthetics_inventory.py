#!/usr/bin/env python3
"""
CloudWatch Synthetics (Canaries) Inventory Scanner
Scans canaries with state, schedule, runtime, and last-run result.

Idle/stopped canaries still cost (Lambda + S3 artifacts); failing canaries
are monitoring blind spots. Both are worth flagging.

Usage:
    python get_cloudwatch_synthetics_inventory.py                     # All accounts, all regions
    python get_cloudwatch_synthetics_inventory.py -a "TQ Hosted"      # Single account
    python get_cloudwatch_synthetics_inventory.py -p <profile> -r us-east-1
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

SERVICE = "cloudwatch-synthetics"


def scan_region(session, region):
    """Scan Synthetics canaries in one region. Returns (canaries, counts)."""
    canaries = []
    try:
        client = session.client('synthetics', region_name=region, config=BOTO_CONFIG)

        # describe_canaries has no boto3 paginator — manual NextToken loop
        next_token = None
        while True:
            kwargs = {"MaxResults": 100}
            if next_token:
                kwargs["NextToken"] = next_token
            resp = client.describe_canaries(**kwargs)
            for c in resp.get('Canaries', []):
                status = c.get('Status', {}) or {}
                schedule = c.get('Schedule', {}) or {}
                timeline = c.get('Timeline', {}) or {}

                # Last run result (single latest run)
                last_run_state = ''
                last_run_time = ''
                try:
                    runs = client.get_canary_runs(Name=c['Name'], MaxResults=1)
                    cr = runs.get('CanaryRuns', [])
                    if cr:
                        rs = cr[0].get('Status', {}) or {}
                        last_run_state = rs.get('State', '')
                        last_run_time = (cr[0].get('Timeline', {}) or {}).get('Completed', '')
                except Exception:
                    pass

                canaries.append({
                    "name": c.get('Name', 'N/A'),
                    "id": c.get('Id', ''),
                    "state": status.get('State', ''),
                    "state_reason": status.get('StateReason', ''),
                    "runtime_version": c.get('RuntimeVersion', ''),
                    "schedule_expression": schedule.get('Expression', ''),
                    "artifact_s3_location": c.get('ArtifactS3Location', ''),
                    "engine_arn": c.get('EngineArn', ''),
                    "created_at": timeline.get('Created', ''),
                    "last_modified": timeline.get('LastModified', ''),
                    "last_started": timeline.get('LastStarted', ''),
                    "last_run_state": last_run_state,
                    "last_run_time": last_run_time,
                    "tags": c.get('Tags', {}),
                })

            next_token = resp.get('NextToken')
            if not next_token:
                break

    except Exception as e:
        if is_region_unsupported_error(e):
            log_region_skip(region, SERVICE, str(e))
        else:
            logger.warning(f"  {region}: Error — {e}")
        return [], {"canaries": 0}

    return canaries, {"canaries": len(canaries)}


def scan_synthetics(session, regions, writer):
    """Scan Synthetics across all regions in parallel."""
    totals = scan_regions_parallel(
        session, regions, writer, scan_region,
        log_fn=lambda region, c: logger.info(f"  {region}: {c['canaries']} canary(ies)"),
    )
    return totals.get("canaries", 0)


def main():
    parser = argparse.ArgumentParser(description='CloudWatch Synthetics Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('synthetics')
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

        canary_count = scan_synthetics(session, regions, writer)

        writer.set("total_canaries", canary_count)
        writer.set("status", "ok")

        logger.info(f"  Total: {canary_count} canaries")

    logger.info("=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
