#!/usr/bin/env python3
"""
AWS Backup Inventory Scanner
Scans all configured AWS accounts/regions for Backup vaults, plans, and recovery points.

Usage:
    python get_backup_inventory.py
    python get_backup_inventory.py -a "TQ Primary"
    python get_backup_inventory.py -r us-east-1
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

SERVICE = "backup"


def scan_backup(session, regions, writer):
    """Scan AWS Backup vaults and plans across all specified regions."""
    total_vaults = 0
    total_plans = 0

    for region in regions:
        try:
            client = session.client('backup', region_name=region, config=BOTO_CONFIG)
            region_data = {"vaults": [], "plans": []}

            # Backup Vaults
            try:
                paginator = client.get_paginator('list_backup_vaults')
                for page in paginator.paginate():
                    for vault in page.get('BackupVaultList', []):
                        region_data["vaults"].append({
                            "vault_name": vault.get('BackupVaultName', 'N/A'),
                            "vault_arn": vault.get('BackupVaultArn', 'N/A'),
                            "recovery_points": vault.get('NumberOfRecoveryPoints', 0),
                            "encryption_key_arn": vault.get('EncryptionKeyArn', ''),
                            "locked": vault.get('Locked', False),
                            "created_at": vault.get('CreationDate', ''),
                        })
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: Vaults error — {e}")

            # Backup Plans
            try:
                paginator = client.get_paginator('list_backup_plans')
                for page in paginator.paginate():
                    for plan in page.get('BackupPlansList', []):
                        region_data["plans"].append({
                            "plan_id": plan.get('BackupPlanId', 'N/A'),
                            "plan_name": plan.get('BackupPlanName', 'N/A'),
                            "plan_arn": plan.get('BackupPlanArn', 'N/A'),
                            "version_id": plan.get('VersionId', 'N/A'),
                            "last_execution_date": plan.get('LastExecutionDate', ''),
                            "created_at": plan.get('CreationDate', ''),
                        })
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: Plans error — {e}")

            writer.set_nested("regions", region, value=region_data)
            total_vaults += len(region_data["vaults"])
            total_plans += len(region_data["plans"])

            if region_data["vaults"] or region_data["plans"]:
                logger.info(f"  {region}: {len(region_data['vaults'])} vaults, {len(region_data['plans'])} plans")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value={})

    return total_vaults, total_plans


def main():
    parser = argparse.ArgumentParser(description='AWS Backup Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('backup')
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

        vaults, plans = scan_backup(session, regions, writer)
        writer.set("total_vaults", vaults)
        writer.set("total_plans", plans)
        writer.set("status", "ok")

        logger.info(f"  Total: {vaults} vaults, {plans} plans")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
