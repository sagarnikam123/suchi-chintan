#!/usr/bin/env python3
"""
EFS (Elastic File System) Inventory Scanner
Scans file systems with size, throughput mode, and mount targets.

Usage:
    python get_efs_inventory.py                     # All accounts, all regions
    python get_efs_inventory.py -a "TQ Hosted"      # Single account
    python get_efs_inventory.py -p <profile> -r us-east-1
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

SERVICE = "efs"


def scan_region(session, region):
    """Scan EFS file systems in one region. Returns (filesystems, counts)."""
    filesystems = []
    try:
        efs = session.client('efs', region_name=region, config=BOTO_CONFIG)
        resp = efs.describe_file_systems()

        for fs in resp.get('FileSystems', []):
            size_bytes = fs.get('SizeInBytes', {}).get('Value', 0)
            size_gb = round(size_bytes / (1024**3), 2)

            filesystems.append({
                "file_system_id": fs['FileSystemId'],
                "name": fs.get('Name', 'N/A'),
                "lifecycle_state": fs['LifeCycleState'],
                "performance_mode": fs.get('PerformanceMode', 'generalPurpose'),
                "throughput_mode": fs.get('ThroughputMode', 'bursting'),
                "provisioned_throughput_mibps": fs.get('ProvisionedThroughputInMibps', 0),
                "size_gb": size_gb,
                "mount_targets": fs.get('NumberOfMountTargets', 0),
                "encrypted": fs.get('Encrypted', False),
                "created_at": fs.get('CreationTime', ''),
                "tags": fs.get('Tags', []),
            })

    except Exception as e:
        if is_region_unsupported_error(e):
            log_region_skip(region, SERVICE, str(e))
        else:
            logger.warning(f"  {region}: Error — {e}")
        return [], {"filesystems": 0, "size_gb": 0}

    total_gb = sum(f['size_gb'] for f in filesystems)
    return filesystems, {"filesystems": len(filesystems), "size_gb": total_gb}


def scan_efs(session, regions, writer):
    """Scan EFS across all regions in parallel."""
    totals = scan_regions_parallel(
        session, regions, writer, scan_region,
        log_fn=lambda region, c: logger.info(
            f"  {region}: {c['filesystems']} file systems ({c['size_gb']:.1f} GB)"
        ),
    )
    return totals.get("filesystems", 0), totals.get("size_gb", 0)


def main():
    parser = argparse.ArgumentParser(description='EFS Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('efs')
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

        fs_count, size_gb = scan_efs(session, regions, writer)

        writer.set("total_filesystems", fs_count)
        writer.set("total_size_gb", round(size_gb, 2))
        writer.set("status", "ok")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
