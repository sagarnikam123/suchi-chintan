#!/usr/bin/env python3
"""
Amazon WorkSpaces Inventory Scanner
Scans WorkSpaces with bundle, running mode, state, and last-active time.

Running mode matters for cost: ALWAYS_ON bills a flat monthly rate even when
idle, while AUTO_STOP bills hourly. Idle ALWAYS_ON workspaces are common waste.

Usage:
    python get_workspaces_inventory.py                     # All accounts, all regions
    python get_workspaces_inventory.py -a "TQ Hosted"      # Single account
    python get_workspaces_inventory.py -p <profile> -r us-east-1
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

SERVICE = "workspaces"


def scan_region(session, region):
    """Scan WorkSpaces in one region. Returns (workspaces, counts)."""
    workspaces = []
    try:
        client = session.client('workspaces', region_name=region, config=BOTO_CONFIG)

        # Last-active time per workspace (single paginated call, map by id)
        last_active = {}
        try:
            cp = client.get_paginator('describe_workspaces_connection_status')
            for cpage in cp.paginate():
                for cs in cpage.get('WorkspacesConnectionStatus', []):
                    last_active[cs['WorkspaceId']] = cs.get('LastKnownUserConnectionTimestamp', '')
        except Exception:
            pass

        paginator = client.get_paginator('describe_workspaces')
        for page in paginator.paginate():
            for ws in page.get('Workspaces', []):
                ws_id = ws['WorkspaceId']
                props = ws.get('WorkspaceProperties', {})
                workspaces.append({
                    "workspace_id": ws_id,
                    "directory_id": ws.get('DirectoryId', ''),
                    "user_name": ws.get('UserName', ''),
                    "state": ws.get('State', ''),
                    "bundle_id": ws.get('BundleId', ''),
                    "compute_type": props.get('ComputeTypeName', ''),
                    "running_mode": props.get('RunningMode', ''),
                    "auto_stop_timeout_min": props.get('RunningModeAutoStopTimeoutInMinutes', 0),
                    "root_volume_gb": props.get('RootVolumeSizeGib', 0),
                    "user_volume_gb": props.get('UserVolumeSizeGib', 0),
                    "encrypted": ws.get('UserVolumeEncryptionEnabled', False),
                    "last_active": last_active.get(ws_id, ''),
                })

    except Exception as e:
        if is_region_unsupported_error(e):
            log_region_skip(region, SERVICE, str(e))
        else:
            logger.warning(f"  {region}: Error — {e}")
        return [], {"workspaces": 0}

    return workspaces, {"workspaces": len(workspaces)}


def scan_workspaces(session, regions, writer):
    """Scan WorkSpaces across all regions in parallel."""
    totals = scan_regions_parallel(
        session, regions, writer, scan_region,
        log_fn=lambda region, c: logger.info(f"  {region}: {c['workspaces']} workspace(s)"),
    )
    return totals.get("workspaces", 0)


def main():
    parser = argparse.ArgumentParser(description='Amazon WorkSpaces Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('workspaces')
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

        ws_count = scan_workspaces(session, regions, writer)

        writer.set("total_workspaces", ws_count)
        writer.set("status", "ok")

        logger.info(f"  Total: {ws_count} workspaces")

    logger.info("=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
