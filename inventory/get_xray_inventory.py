#!/usr/bin/env python3
"""
AWS X-Ray Inventory Scanner
Scans all configured AWS accounts/regions for X-Ray groups and sampling rules.

Usage:
    python get_xray_inventory.py
    python get_xray_inventory.py -a "Production"
    python get_xray_inventory.py -r us-east-1
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

SERVICE = "xray"


def scan_xray(session, regions, writer):
    """Scan X-Ray groups and sampling rules across all specified regions."""
    total_groups = 0
    total_rules = 0

    for region in regions:
        try:
            client = session.client('xray', region_name=region, config=BOTO_CONFIG)
            region_data = {"groups": [], "sampling_rules": []}

            # Groups
            try:
                resp = client.get_groups()
                for group in resp.get('Groups', []):
                    region_data["groups"].append({
                        "group_name": group.get('GroupName', 'N/A'),
                        "group_arn": group.get('GroupARN', 'N/A'),
                        "filter_expression": group.get('FilterExpression', ''),
                        "insights_enabled": group.get('InsightsConfiguration', {}).get('InsightsEnabled', False),
                    })
            except Exception as e:
                if is_region_unsupported_error(e):
                    log_region_skip(region, SERVICE, str(e))
                    writer.set_nested("regions", region, value={})
                    continue
                logger.warning(f"  {region}: Groups error — {e}")

            # Sampling rules
            try:
                resp = client.get_sampling_rules()
                for record in resp.get('SamplingRuleRecords', []):
                    rule = record.get('SamplingRule', {})
                    region_data["sampling_rules"].append({
                        "rule_name": rule.get('RuleName', 'N/A'),
                        "rule_arn": rule.get('RuleARN', 'N/A'),
                        "priority": rule.get('Priority', 0),
                        "fixed_rate": rule.get('FixedRate', 0),
                        "reservoir_size": rule.get('ReservoirSize', 0),
                        "service_name": rule.get('ServiceName', '*'),
                        "service_type": rule.get('ServiceType', '*'),
                        "host": rule.get('Host', '*'),
                        "http_method": rule.get('HTTPMethod', '*'),
                        "url_path": rule.get('URLPath', '*'),
                        "version": rule.get('Version', 1),
                    })
            except Exception as e:
                if not is_region_unsupported_error(e):
                    logger.warning(f"  {region}: Sampling rules error — {e}")

            writer.set_nested("regions", region, value=region_data)
            total_groups += len(region_data["groups"])
            total_rules += len(region_data["sampling_rules"])

            if region_data["groups"] or region_data["sampling_rules"]:
                logger.info(f"  {region}: {len(region_data['groups'])} groups, {len(region_data['sampling_rules'])} sampling rules")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value={})

    return total_groups, total_rules


def main():
    parser = argparse.ArgumentParser(description='X-Ray Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('xray')
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

        groups, rules = scan_xray(session, regions, writer)
        writer.set("total_groups", groups)
        writer.set("total_sampling_rules", rules)
        writer.set("status", "ok")

        logger.info(f"  Total: {groups} groups, {rules} sampling rules")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
