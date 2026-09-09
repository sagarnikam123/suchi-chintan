#!/usr/bin/env python3
"""
Amazon Athena Inventory Scanner
Scans all configured AWS accounts/regions for Athena workgroups and named queries.

Usage:
    python get_athena_inventory.py
    python get_athena_inventory.py -a "TQ Primary"
    python get_athena_inventory.py -r us-east-1
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, get_regions, create_session,
    get_output_dir, get_timestamp, add_common_args,
    create_session_with_identity, is_region_unsupported_error, log_region_skip,
    IncrementalWriter, make_output_filename,
    run_with_timer,
)

import argparse

SERVICE = "athena"


def scan_athena(session, regions, writer):
    """Scan Athena workgroups across all specified regions."""
    total_workgroups = 0

    for region in regions:
        try:
            client = session.client('athena', region_name=region, config=BOTO_CONFIG)
            workgroups = []

            kwargs = {}
            while True:
                resp = client.list_work_groups(**kwargs)
                for wg_summary in resp.get('WorkGroups', []):
                    wg_name = wg_summary['Name']
                    entry = {
                        "name": wg_name,
                        "state": wg_summary.get('State', 'N/A'),
                        "engine_version": wg_summary.get('EngineVersion', {}).get('EffectiveEngineVersion', 'N/A'),
                        "creation_time": wg_summary.get('CreationTime', ''),
                    }

                    # Get workgroup details
                    try:
                        detail = client.get_work_group(WorkGroup=wg_name)['WorkGroup']
                        config = detail.get('Configuration', {})
                        entry.update({
                            "description": detail.get('Description', ''),
                            "output_location": config.get('ResultConfiguration', {}).get('OutputLocation', ''),
                            "enforce_config": config.get('EnforceWorkGroupConfiguration', False),
                            "publish_cloudwatch": config.get('PublishCloudWatchMetricsEnabled', False),
                            "bytes_scanned_cutoff": config.get('BytesScannedCutoffPerQuery', 0),
                        })
                    except Exception:
                        pass

                    workgroups.append(entry)
                token = resp.get('NextToken')
                if not token:
                    break
                kwargs['NextToken'] = token

            writer.set_nested("regions", region, value=workgroups)
            total_workgroups += len(workgroups)

            if workgroups:
                logger.info(f"  {region}: {len(workgroups)} workgroups")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value=[])

    return total_workgroups


def main():
    parser = argparse.ArgumentParser(description='Athena Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('athena')
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

        logger.info(f"🔍 {name} ({account_id}) — profile: {profile}")

        session = account.get("_session") or create_session(profile)
        if not session:
            continue

        output_dir = get_output_dir(account_id, SERVICE)
        writer = IncrementalWriter(output_dir, make_output_filename(SERVICE, account_id, timestamp))
        writer.update({"name": name, "profile_used": profile, "status": "in_progress"})

        total = scan_athena(session, regions, writer)
        writer.set("total_workgroups", total)
        writer.set("status", "ok")

        logger.info(f"  Total: {total} workgroups")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
