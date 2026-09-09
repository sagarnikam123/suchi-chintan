#!/usr/bin/env python3
"""
Amazon QuickSight Inventory Scanner
Scans all configured AWS accounts for QuickSight dashboards, datasets, and users.

Note: QuickSight is a regional service but its API requires the account ID explicitly.

Usage:
    python get_quicksight_inventory.py
    python get_quicksight_inventory.py -a "TQ Primary"
    python get_quicksight_inventory.py -r us-east-1
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

SERVICE = "quicksight"


def scan_quicksight(session, account_id, regions, writer):
    """Scan QuickSight resources across specified regions."""
    total_dashboards = 0
    total_datasets = 0

    for region in regions:
        try:
            client = session.client('quicksight', region_name=region, config=BOTO_CONFIG)
            region_data = {"dashboards": [], "datasets": [], "users": []}

            # Dashboards
            try:
                resp = client.list_dashboards(AwsAccountId=account_id)
                for d in resp.get('DashboardSummaryList', []):
                    region_data["dashboards"].append({
                        "dashboard_id": d.get('DashboardId', 'N/A'),
                        "name": d.get('Name', 'N/A'),
                        "arn": d.get('Arn', 'N/A'),
                        "published_version": d.get('PublishedVersionNumber', 0),
                        "created_time": d.get('CreatedTime', ''),
                        "last_updated": d.get('LastUpdatedTime', ''),
                        "last_published": d.get('LastPublishedTime', ''),
                    })
            except Exception as e:
                if 'UnsupportedUserEditionException' not in str(e):
                    logger.debug(f"  {region}: Dashboards — {e}")

            # Datasets
            try:
                resp = client.list_data_sets(AwsAccountId=account_id)
                for ds in resp.get('DataSetSummaries', []):
                    region_data["datasets"].append({
                        "dataset_id": ds.get('DataSetId', 'N/A'),
                        "name": ds.get('Name', 'N/A'),
                        "arn": ds.get('Arn', 'N/A'),
                        "import_mode": ds.get('ImportMode', 'N/A'),
                        "created_time": ds.get('CreatedTime', ''),
                        "last_updated": ds.get('LastUpdatedTime', ''),
                    })
            except Exception as e:
                if 'UnsupportedUserEditionException' not in str(e):
                    logger.debug(f"  {region}: Datasets — {e}")

            # Users
            try:
                resp = client.list_users(AwsAccountId=account_id, Namespace='default')
                for u in resp.get('UserList', []):
                    region_data["users"].append({
                        "user_name": u.get('UserName', 'N/A'),
                        "email": u.get('Email', 'N/A'),
                        "role": u.get('Role', 'N/A'),
                        "active": u.get('Active', False),
                    })
            except Exception as e:
                if 'UnsupportedUserEditionException' not in str(e):
                    logger.debug(f"  {region}: Users — {e}")

            writer.set_nested("regions", region, value=region_data)
            total_dashboards += len(region_data["dashboards"])
            total_datasets += len(region_data["datasets"])

            if region_data["dashboards"] or region_data["datasets"]:
                logger.info(f"  {region}: {len(region_data['dashboards'])} dashboards, "
                           f"{len(region_data['datasets'])} datasets, {len(region_data['users'])} users")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value={})

    return total_dashboards, total_datasets


def main():
    parser = argparse.ArgumentParser(description='QuickSight Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('quicksight')
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

        dashboards, datasets = scan_quicksight(session, account_id, regions, writer)
        writer.set("total_dashboards", dashboards)
        writer.set("total_datasets", datasets)
        writer.set("status", "ok")

        logger.info(f"  Total: {dashboards} dashboards, {datasets} datasets")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
