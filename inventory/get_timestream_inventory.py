#!/usr/bin/env python3
"""
Amazon Timestream Inventory Scanner
Scans all configured AWS accounts/regions for Timestream databases and tables.

Usage:
    python get_timestream_inventory.py
    python get_timestream_inventory.py -a "TQ Primary"
    python get_timestream_inventory.py -r us-east-1
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

SERVICE = "timestream"


def scan_timestream(session, regions, writer):
    """Scan Timestream databases and tables across all specified regions."""
    total_dbs = 0
    total_tables = 0

    for region in regions:
        try:
            client = session.client('timestream-write', region_name=region, config=BOTO_CONFIG)
            databases = []

            db_kwargs = {}
            while True:
                db_resp = client.list_databases(**db_kwargs)
                for db in db_resp.get('Databases', []):
                    db_name = db['DatabaseName']
                    tables = []

                    try:
                        tbl_kwargs = {'DatabaseName': db_name}
                        while True:
                            tbl_resp = client.list_tables(**tbl_kwargs)
                            for tbl in tbl_resp.get('Tables', []):
                                retention = tbl.get('RetentionProperties', {})
                                tables.append({
                                    "table_name": tbl['TableName'],
                                    "table_status": tbl.get('TableStatus', 'N/A'),
                                    "memory_retention_hours": retention.get('MemoryStoreRetentionPeriodInHours', 0),
                                    "magnetic_retention_days": retention.get('MagneticStoreRetentionPeriodInDays', 0),
                                    "magnetic_writes_enabled": tbl.get('MagneticStoreWriteProperties', {}).get('EnableMagneticStoreWrites', False),
                                })
                            tbl_token = tbl_resp.get('NextToken')
                            if not tbl_token:
                                break
                            tbl_kwargs['NextToken'] = tbl_token
                    except Exception as e:
                        if is_region_unsupported_error(e):
                            raise  # opt-in region — outer handler skips it once
                        logger.warning(f"  {region}: Error listing tables for {db_name} — {e}")

                    databases.append({
                        "database_name": db_name,
                        "arn": db.get('Arn', 'N/A'),
                        "table_count": db.get('TableCount', 0),
                        "kms_key_id": db.get('KmsKeyId', ''),
                        "created_at": db.get('CreationTime', ''),
                        "tables": tables,
                    })
                    total_tables += len(tables)

                db_token = db_resp.get('NextToken')
                if not db_token:
                    break
                db_kwargs['NextToken'] = db_token

            writer.set_nested("regions", region, value=databases)
            total_dbs += len(databases)

            if databases:
                logger.info(f"  {region}: {len(databases)} databases, {total_tables} tables")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value=[])

    return total_dbs, total_tables


def main():
    parser = argparse.ArgumentParser(description='Timestream Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('timestream-write')
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

        dbs, tables = scan_timestream(session, regions, writer)
        writer.set("total_databases", dbs)
        writer.set("total_tables", tables)
        writer.set("status", "ok")

        logger.info(f"  Total: {dbs} databases, {tables} tables")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
