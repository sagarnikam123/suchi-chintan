#!/usr/bin/env python3
"""
AWS Systems Manager (SSM) Parameter Store Inventory Scanner
Scans all configured AWS accounts/regions for SSM parameters.

Usage:
    python get_ssm_inventory.py
    python get_ssm_inventory.py -a "TQ Primary"
    python get_ssm_inventory.py -r us-east-1
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

SERVICE = "ssm"


def scan_ssm(session, regions, writer):
    """Scan SSM Parameter Store across all specified regions."""
    total = 0

    for region in regions:
        try:
            client = session.client('ssm', region_name=region, config=BOTO_CONFIG)
            parameters = []

            paginator = client.get_paginator('describe_parameters')
            for page in paginator.paginate():
                for param in page.get('Parameters', []):
                    parameters.append({
                        "name": param.get('Name', 'N/A'),
                        "type": param.get('Type', 'N/A'),
                        "tier": param.get('Tier', 'Standard'),
                        "version": param.get('Version', 0),
                        "data_type": param.get('DataType', 'text'),
                        "last_modified": param.get('LastModifiedDate', ''),
                        "last_modified_user": param.get('LastModifiedUser', 'N/A'),
                        "description": param.get('Description', ''),
                    })

            writer.set_nested("regions", region, value=parameters)
            total += len(parameters)

            if parameters:
                # Count by type
                types = {}
                for p in parameters:
                    types[p["type"]] = types.get(p["type"], 0) + 1
                type_str = ", ".join(f"{v} {k}" for k, v in types.items())
                logger.info(f"  {region}: {len(parameters)} parameters ({type_str})")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value=[])

    return total


def main():
    parser = argparse.ArgumentParser(description='SSM Parameter Store Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('ssm')
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

        total = scan_ssm(session, regions, writer)
        writer.set("total_parameters", total)
        writer.set("status", "ok")

        logger.info(f"  Total: {total} parameters")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
