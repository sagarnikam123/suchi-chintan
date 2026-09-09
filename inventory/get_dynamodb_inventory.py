#!/usr/bin/env python3
"""
Amazon DynamoDB Inventory Scanner
Scans all configured AWS accounts/regions for DynamoDB tables.

Usage:
    python get_dynamodb_inventory.py
    python get_dynamodb_inventory.py -a "TQ Primary"
    python get_dynamodb_inventory.py -r us-east-1
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

SERVICE = "dynamodb"


def scan_dynamodb(session, regions, writer):
    """Scan DynamoDB tables across all specified regions."""
    total = 0

    for region in regions:
        try:
            client = session.client('dynamodb', region_name=region, config=BOTO_CONFIG)
            tables = []

            paginator = client.get_paginator('list_tables')
            for page in paginator.paginate():
                for table_name in page.get('TableNames', []):
                    try:
                        desc = client.describe_table(TableName=table_name)['Table']
                        billing = desc.get('BillingModeSummary', {})
                        provisioned = desc.get('ProvisionedThroughput', {})

                        tables.append({
                            "table_name": table_name,
                            "status": desc.get('TableStatus', 'N/A'),
                            "billing_mode": billing.get('BillingMode', 'PROVISIONED'),
                            "read_capacity": provisioned.get('ReadCapacityUnits', 0),
                            "write_capacity": provisioned.get('WriteCapacityUnits', 0),
                            "item_count": desc.get('ItemCount', 0),
                            "size_bytes": desc.get('TableSizeBytes', 0),
                            "gsi_count": len(desc.get('GlobalSecondaryIndexes', [])),
                            "lsi_count": len(desc.get('LocalSecondaryIndexes', [])),
                            "stream_enabled": desc.get('StreamSpecification', {}).get('StreamEnabled', False),
                            "encryption_type": desc.get('SSEDescription', {}).get('SSEType', 'DEFAULT'),
                            "deletion_protection": desc.get('DeletionProtectionEnabled', False),
                            "table_class": desc.get('TableClassSummary', {}).get('TableClass', 'STANDARD'),
                            "created_at": desc.get('CreationDateTime', ''),
                        })
                    except Exception as e:
                        if is_region_unsupported_error(e):
                            raise  # opt-in region — outer handler skips it once
                        logger.warning(f"  {region}: Error describing {table_name} — {e}")

            writer.set_nested("regions", region, value=tables)
            total += len(tables)

            if tables:
                logger.info(f"  {region}: {len(tables)} tables")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value=[])

    return total


def main():
    parser = argparse.ArgumentParser(description='DynamoDB Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('dynamodb')
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

        total = scan_dynamodb(session, regions, writer)
        writer.set("total_tables", total)
        writer.set("status", "ok")

        logger.info(f"  Total: {total} tables")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
