#!/usr/bin/env python3
"""
Amazon S3 Glacier Inventory Scanner
Scans all configured AWS accounts/regions for Glacier vaults.

Usage:
    python get_glacier_inventory.py
    python get_glacier_inventory.py -a "TQ Primary"
    python get_glacier_inventory.py -r us-east-1
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

SERVICE = "glacier"


def scan_glacier(session, regions, writer):
    """Scan Glacier vaults across all specified regions."""
    total = 0

    for region in regions:
        try:
            client = session.client('glacier', region_name=region, config=BOTO_CONFIG)
            vaults = []

            paginator = client.get_paginator('list_vaults')
            for page in paginator.paginate():
                for vault in page.get('VaultList', []):
                    vaults.append({
                        "vault_name": vault.get('VaultName', 'N/A'),
                        "vault_arn": vault.get('VaultARN', 'N/A'),
                        "creation_date": vault.get('CreationDate', ''),
                        "last_inventory_date": vault.get('LastInventoryDate', ''),
                        "number_of_archives": vault.get('NumberOfArchives', 0),
                        "size_bytes": vault.get('SizeInBytes', 0),
                    })

            writer.set_nested("regions", region, value=vaults)
            total += len(vaults)

            if vaults:
                logger.info(f"  {region}: {len(vaults)} vaults")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value=[])

    return total


def main():
    parser = argparse.ArgumentParser(description='Glacier Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('glacier')
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

        total = scan_glacier(session, regions, writer)
        writer.set("total_vaults", total)
        writer.set("status", "ok")

        logger.info(f"  Total: {total} vaults")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
