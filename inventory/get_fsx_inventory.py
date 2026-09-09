#!/usr/bin/env python3
"""
Amazon FSx Inventory Scanner
Scans all configured AWS accounts/regions for FSx file systems
(Windows, Lustre, NetApp ONTAP, OpenZFS).

Usage:
    python get_fsx_inventory.py
    python get_fsx_inventory.py -a "TQ Primary"
    python get_fsx_inventory.py -r us-east-1
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

SERVICE = "fsx"


def scan_fsx(session, regions, writer):
    """Scan FSx file systems across all specified regions."""
    total = 0

    for region in regions:
        try:
            client = session.client('fsx', region_name=region, config=BOTO_CONFIG)
            filesystems = []

            paginator = client.get_paginator('describe_file_systems')
            for page in paginator.paginate():
                for fs in page.get('FileSystems', []):
                    entry = {
                        "file_system_id": fs['FileSystemId'],
                        "file_system_type": fs.get('FileSystemType', 'N/A'),
                        "lifecycle": fs.get('Lifecycle', 'N/A'),
                        "storage_capacity_gb": fs.get('StorageCapacity', 0),
                        "storage_type": fs.get('StorageType', 'N/A'),
                        "vpc_id": fs.get('VpcId', 'N/A'),
                        "subnet_ids": fs.get('SubnetIds', []),
                        "dns_name": fs.get('DNSName', 'N/A'),
                        "kms_key_id": fs.get('KmsKeyId', ''),
                        "created_at": fs.get('CreationTime', ''),
                        "tags": {t['Key']: t['Value'] for t in fs.get('Tags', [])},
                    }

                    # Type-specific details
                    fs_type = fs.get('FileSystemType', '')
                    if fs_type == 'WINDOWS' and 'WindowsConfiguration' in fs:
                        wc = fs['WindowsConfiguration']
                        entry["throughput_mbps"] = wc.get('ThroughputCapacity', 0)
                        entry["deployment_type"] = wc.get('DeploymentType', 'N/A')
                    elif fs_type == 'LUSTRE' and 'LustreConfiguration' in fs:
                        lc = fs['LustreConfiguration']
                        entry["deployment_type"] = lc.get('DeploymentType', 'N/A')
                        entry["data_compression"] = lc.get('DataCompressionType', 'NONE')
                    elif fs_type == 'ONTAP' and 'OntapConfiguration' in fs:
                        oc = fs['OntapConfiguration']
                        entry["deployment_type"] = oc.get('DeploymentType', 'N/A')
                        entry["throughput_mbps"] = oc.get('ThroughputCapacity', 0)
                    elif fs_type == 'OPENZFS' and 'OpenZFSConfiguration' in fs:
                        zc = fs['OpenZFSConfiguration']
                        entry["deployment_type"] = zc.get('DeploymentType', 'N/A')
                        entry["throughput_mbps"] = zc.get('ThroughputCapacity', 0)

                    filesystems.append(entry)

            writer.set_nested("regions", region, value=filesystems)
            total += len(filesystems)

            if filesystems:
                logger.info(f"  {region}: {len(filesystems)} file systems")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value=[])

    return total


def main():
    parser = argparse.ArgumentParser(description='FSx Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('fsx')
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

        total = scan_fsx(session, regions, writer)
        writer.set("total_file_systems", total)
        writer.set("status", "ok")

        logger.info(f"  Total: {total} file systems")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
