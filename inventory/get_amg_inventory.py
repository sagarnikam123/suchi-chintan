#!/usr/bin/env python3
"""
Amazon Managed Grafana (AMG) Inventory Scanner
Scans all configured AWS accounts/regions for AMG workspaces.

Usage:
    python get_amg_inventory.py                          # All accounts from accounts.yaml
    python get_amg_inventory.py -p <profile>
    python get_amg_inventory.py -p <profile> -r us-east-1
"""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, get_regions, create_session,
    get_output_dir, get_timestamp, add_common_args,
    create_session_with_identity, is_region_unsupported_error,
    IncrementalWriter, make_output_filename,
    run_with_timer,
)

SERVICE = "amg"


def scan_amg_workspaces(session, region):
    """Scan AMG workspaces in a single region. Returns list of workspace dicts."""
    workspaces = []
    try:
        client = session.client('grafana', region_name=region, config=BOTO_CONFIG)
        paginator = client.get_paginator('list_workspaces')
        for page in paginator.paginate():
            for ws in page.get('workspaces', []):
                workspaces.append({
                    "id": ws.get("id"),
                    "name": ws.get("name", ""),
                    "description": ws.get("description", ""),
                    "status": ws.get("status"),
                    "grafana_version": ws.get("grafanaVersion", "unknown"),
                    "endpoint": ws.get("endpoint", ""),
                    "license_type": ws.get("licenseType", ""),
                    "auth_providers": ws.get("authentication", {}).get("providers", []),
                    "notification_destinations": ws.get("notificationDestinations", []),
                    "tags": ws.get("tags", {}),
                    "created": ws.get("created"),
                    "modified": ws.get("modified"),
                })
    except Exception as e:
        if is_region_unsupported_error(e):
            return workspaces
        logger.warning(f"  {region}: error — {e}")
    return workspaces


def main():
    parser = argparse.ArgumentParser(description='Amazon Managed Grafana Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    if args.profile:
        session, account_id, arn = create_session_with_identity(args.profile)
        if not session:
            sys.exit(1)
        accounts = [{"name": account_id, "account_id": account_id, "profile": args.profile, "_session": session}]

    regions = [args.region] if args.region else get_regions('grafana')
    timestamp = get_timestamp()

    logger.info(f"Scanning {len(accounts)} account(s) across {len(regions)} region(s)")
    logger.info("=" * 60)

    combined_data = {
        "generated": timestamp,
        "accounts": {},
        "summary": {"total_workspaces": 0},
    }

    for account in accounts:
        name = account['name']
        account_id = account['account_id']
        profile = account['profile']

        logger.info(f"🔍 {name} ({account_id})")

        # Reuse session from --profile if already authenticated
        session = account.get("_session") or create_session(profile)
        if not session:
            combined_data["accounts"][account_id] = {"name": name, "status": "auth_failed"}
            continue

        acct_writer = IncrementalWriter(
            get_output_dir(account_id, SERVICE), make_output_filename(SERVICE, account_id, timestamp)
        )
        acct_writer.update({"name": name, "profile_used": profile, "status": "ok", "regions": {}})

        acct_total = 0
        for region in regions:
            workspaces = scan_amg_workspaces(session, region)
            if not workspaces:
                continue

            acct_writer.set_nested("regions", region, value=workspaces)
            acct_total += len(workspaces)

            for ws in workspaces:
                logger.info(f"  {region}: {ws['name'] or ws['id']} — v{ws['grafana_version']}, "
                            f"{ws['status']}, {ws['license_type']}")

        acct_writer.set("total_workspaces", acct_total)
        combined_data["accounts"][account_id] = acct_writer.get_data()

        summary = combined_data["summary"]
        summary["total_workspaces"] += acct_total

    logger.info("" + "=" * 60)
    logger.info("📊 SUMMARY")
    logger.info("=" * 60)
    logger.info(f"  Total AMG Workspaces: {combined_data['summary']['total_workspaces']}")


if __name__ == "__main__":
    run_with_timer(main)
