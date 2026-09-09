#!/usr/bin/env python3
"""
Amazon EventBridge (CloudWatch Events) Inventory Scanner
Scans all configured AWS accounts/regions for EventBridge buses, rules, and schedules.

Usage:
    python get_eventbridge_inventory.py
    python get_eventbridge_inventory.py -a "TQ Primary"
    python get_eventbridge_inventory.py -r us-east-1
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

SERVICE = "eventbridge"


def scan_eventbridge(session, regions, writer):
    """Scan EventBridge buses and rules across all specified regions."""
    total_buses = 0
    total_rules = 0

    for region in regions:
        try:
            client = session.client('events', region_name=region, config=BOTO_CONFIG)
            region_data = {"event_buses": [], "rules": []}

            # Event buses
            try:
                resp = client.list_event_buses()
                for bus in resp.get('EventBuses', []):
                    bus_name = bus['Name']
                    region_data["event_buses"].append({
                        "name": bus_name,
                        "arn": bus.get('Arn', 'N/A'),
                        "policy": "yes" if bus.get('Policy') else "no",
                    })

                    # Rules for each bus
                    try:
                        rules_paginator = client.get_paginator('list_rules')
                        for page in rules_paginator.paginate(EventBusName=bus_name):
                            for rule in page.get('Rules', []):
                                region_data["rules"].append({
                                    "name": rule['Name'],
                                    "event_bus": bus_name,
                                    "state": rule.get('State', 'N/A'),
                                    "schedule_expression": rule.get('ScheduleExpression', ''),
                                    "event_pattern": "yes" if rule.get('EventPattern') else "no",
                                    "description": rule.get('Description', ''),
                                })
                    except Exception as e:
                        if is_region_unsupported_error(e):
                            raise  # opt-in region — outer handler skips it once
                        logger.warning(f"  {region}: Error listing rules for bus {bus_name} — {e}")

            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: Error listing buses — {e}")

            writer.set_nested("regions", region, value=region_data)
            total_buses += len(region_data["event_buses"])
            total_rules += len(region_data["rules"])

            if region_data["event_buses"] or region_data["rules"]:
                logger.info(f"  {region}: {len(region_data['event_buses'])} buses, {len(region_data['rules'])} rules")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value={"event_buses": [], "rules": []})

    return total_buses, total_rules


def main():
    parser = argparse.ArgumentParser(description='EventBridge Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('events')
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

        buses, rules = scan_eventbridge(session, regions, writer)
        writer.set("total_event_buses", buses)
        writer.set("total_rules", rules)
        writer.set("status", "ok")

        logger.info(f"  Total: {buses} buses, {rules} rules")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
