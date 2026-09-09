#!/usr/bin/env python3
"""
Amazon Managed Prometheus (AMP) Inventory Scanner
Scans all configured AWS accounts/regions for AMP workspaces and rule groups.

Usage:
    python get_amp_inventory.py
    python get_amp_inventory.py -a "Production"
    python get_amp_inventory.py -r us-east-1
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

SERVICE = "amp"


def scan_amp(session, regions, writer):
    """Scan AMP workspaces across all specified regions."""
    total_workspaces = 0

    for region in regions:
        try:
            client = session.client('amp', region_name=region, config=BOTO_CONFIG)
            workspaces = []

            paginator = client.get_paginator('list_workspaces')
            for page in paginator.paginate():
                for ws in page.get('workspaces', []):
                    ws_id = ws.get('workspaceId', 'N/A')
                    entry = {
                        "workspace_id": ws_id,
                        "alias": ws.get('alias', ''),
                        "arn": ws.get('arn', 'N/A'),
                        "status": ws.get('status', {}).get('statusCode', 'N/A'),
                        "created_at": ws.get('createdAt', ''),
                    }

                    # Get workspace details (endpoints)
                    try:
                        desc = client.describe_workspace(workspaceId=ws_id)['workspace']
                        entry["prometheus_endpoint"] = desc.get('prometheusEndpoint', '')
                        entry["kms_key_arn"] = desc.get('kmsKeyArn', '')
                    except Exception:
                        pass

                    # Count rule groups
                    try:
                        rg_resp = client.list_rule_groups_namespaces(workspaceId=ws_id)
                        entry["rule_group_count"] = len(rg_resp.get('ruleGroupsNamespaces', []))
                    except Exception:
                        entry["rule_group_count"] = 0

                    workspaces.append(entry)

            writer.set_nested("regions", region, value=workspaces)
            total_workspaces += len(workspaces)

            if workspaces:
                logger.info(f"  {region}: {len(workspaces)} workspaces")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value=[])

    return total_workspaces


def main():
    parser = argparse.ArgumentParser(description='Amazon Managed Prometheus Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('amp')
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

        total = scan_amp(session, regions, writer)
        writer.set("total_workspaces", total)
        writer.set("status", "ok")

        logger.info(f"  Total: {total} workspaces")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
