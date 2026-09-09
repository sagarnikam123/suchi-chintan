#!/usr/bin/env python3
"""
AWS Amplify Inventory Scanner
Scans Amplify apps, branches, and hosting config across all regions.

Usage:
    python get_amplify_inventory.py                     # All accounts, all regions
    python get_amplify_inventory.py -a "TQ Hosted"      # Single account
    python get_amplify_inventory.py -p <profile> -r us-east-1
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

SERVICE = "amplify"


def scan_region(session, region):
    """Scan Amplify apps + branches in one region. Returns (apps, counts)."""
    apps = []
    branch_total = 0
    try:
        client = session.client('amplify', region_name=region, config=BOTO_CONFIG)

        paginator = client.get_paginator('list_apps')
        for page in paginator.paginate():
            for app in page.get('apps', []):
                app_id = app['appId']

                # Branches for this app
                branches = []
                try:
                    bp = client.get_paginator('list_branches')
                    for bpage in bp.paginate(appId=app_id):
                        for br in bpage.get('branches', []):
                            branches.append({
                                "branch_name": br.get('branchName', ''),
                                "stage": br.get('stage', ''),
                                "active": br.get('activeJobId', '') != '',
                                "auto_build": br.get('enableAutoBuild', False),
                                "updated_at": br.get('updateTime', ''),
                            })
                except Exception:
                    pass

                apps.append({
                    "app_id": app_id,
                    "name": app.get('name', 'N/A'),
                    "arn": app.get('appArn', ''),
                    "platform": app.get('platform', ''),
                    "repository": app.get('repository', ''),
                    "default_domain": app.get('defaultDomain', ''),
                    "custom_rules_count": len(app.get('customRules', [])),
                    "basic_auth_enabled": app.get('enableBasicAuth', False),
                    "created_at": app.get('createTime', ''),
                    "updated_at": app.get('updateTime', ''),
                    "branch_count": len(branches),
                    "branches": branches,
                    "tags": app.get('tags', {}),
                })
                branch_total += len(branches)

    except Exception as e:
        if is_region_unsupported_error(e):
            log_region_skip(region, SERVICE, str(e))
        else:
            logger.warning(f"  {region}: Error — {e}")
        return [], {"apps": 0, "branches": 0}

    return apps, {"apps": len(apps), "branches": branch_total}


def scan_amplify(session, regions, writer):
    """Scan Amplify across all regions in parallel."""
    totals = scan_regions_parallel(
        session, regions, writer, scan_region,
        log_fn=lambda region, c: logger.info(
            f"  {region}: {c['apps']} app(s), {c['branches']} branch(es)"
        ),
    )
    return totals.get("apps", 0), totals.get("branches", 0)


def main():
    parser = argparse.ArgumentParser(description='AWS Amplify Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('amplify')
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

        app_count, branch_count = scan_amplify(session, regions, writer)

        writer.set("total_apps", app_count)
        writer.set("total_branches", branch_count)
        writer.set("status", "ok")

        logger.info(f"  Total: {app_count} apps, {branch_count} branches")

    logger.info("=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
