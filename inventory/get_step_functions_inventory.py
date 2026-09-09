#!/usr/bin/env python3
"""
AWS Step Functions Inventory Scanner
Scans all configured AWS accounts/regions for state machines.

Usage:
    python get_step_functions_inventory.py
    python get_step_functions_inventory.py -a "TQ Primary"
    python get_step_functions_inventory.py -r us-east-1
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

SERVICE = "step-functions"


def scan_step_functions(session, regions, writer):
    """Scan Step Functions state machines across all specified regions."""
    total = 0

    for region in regions:
        try:
            client = session.client('stepfunctions', region_name=region, config=BOTO_CONFIG)
            state_machines = []

            paginator = client.get_paginator('list_state_machines')
            for page in paginator.paginate():
                for sm in page.get('stateMachines', []):
                    sm_arn = sm['stateMachineArn']
                    entry = {
                        "name": sm.get('name', 'N/A'),
                        "arn": sm_arn,
                        "type": sm.get('type', 'STANDARD'),
                        "created_at": sm.get('creationDate', ''),
                    }

                    # Get details
                    try:
                        desc = client.describe_state_machine(stateMachineArn=sm_arn)
                        entry.update({
                            "status": desc.get('status', 'N/A'),
                            "role_arn": desc.get('roleArn', 'N/A'),
                            "logging_level": desc.get('loggingConfiguration', {}).get('level', 'OFF'),
                            "tracing_enabled": desc.get('tracingConfiguration', {}).get('enabled', False),
                        })
                    except Exception:
                        pass

                    state_machines.append(entry)

            writer.set_nested("regions", region, value=state_machines)
            total += len(state_machines)

            if state_machines:
                logger.info(f"  {region}: {len(state_machines)} state machines")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value=[])

    return total


def main():
    parser = argparse.ArgumentParser(description='Step Functions Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('stepfunctions')
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

        total = scan_step_functions(session, regions, writer)
        writer.set("total_state_machines", total)
        writer.set("status", "ok")

        logger.info(f"  Total: {total} state machines")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
