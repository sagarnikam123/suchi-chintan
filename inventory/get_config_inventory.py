#!/usr/bin/env python3
"""
AWS Config Inventory Scanner
Scans all configured AWS accounts/regions for Config recorders and rules.

Usage:
    python get_config_inventory.py
    python get_config_inventory.py -a "TQ Primary"
    python get_config_inventory.py -r us-east-1
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

SERVICE = "config"


def scan_config(session, regions, writer):
    """Scan AWS Config recorders and rules across all specified regions."""
    total_rules = 0

    for region in regions:
        try:
            client = session.client('config', region_name=region, config=BOTO_CONFIG)
            region_data = {"recorders": [], "rules": []}

            # Configuration recorders
            try:
                resp = client.describe_configuration_recorders()
                for recorder in resp.get('ConfigurationRecorders', []):
                    # Get status
                    status = {}
                    try:
                        status_resp = client.describe_configuration_recorder_status(
                            ConfigurationRecorderNames=[recorder['name']]
                        )
                        statuses = status_resp.get('ConfigurationRecordersStatus', [])
                        if statuses:
                            status = statuses[0]
                    except Exception:
                        pass

                    region_data["recorders"].append({
                        "name": recorder.get('name', 'N/A'),
                        "role_arn": recorder.get('roleARN', 'N/A'),
                        "all_supported": recorder.get('recordingGroup', {}).get('allSupported', False),
                        "include_global": recorder.get('recordingGroup', {}).get('includeGlobalResourceTypes', False),
                        "recording": status.get('recording', False),
                        "last_status": status.get('lastStatus', 'N/A'),
                    })
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: Recorders error — {e}")

            # Config rules
            try:
                paginator = client.get_paginator('describe_config_rules')
                for page in paginator.paginate():
                    for rule in page.get('ConfigRules', []):
                        region_data["rules"].append({
                            "rule_name": rule.get('ConfigRuleName', 'N/A'),
                            "rule_id": rule.get('ConfigRuleId', 'N/A'),
                            "state": rule.get('ConfigRuleState', 'N/A'),
                            "source_owner": rule.get('Source', {}).get('Owner', 'N/A'),
                            "source_identifier": rule.get('Source', {}).get('SourceIdentifier', 'N/A'),
                            "scope_resource_types": rule.get('Scope', {}).get('ComplianceResourceTypes', []),
                        })
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: Rules error — {e}")

            writer.set_nested("regions", region, value=region_data)
            total_rules += len(region_data["rules"])

            if region_data["recorders"] or region_data["rules"]:
                logger.info(f"  {region}: {len(region_data['recorders'])} recorders, {len(region_data['rules'])} rules")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value={})

    return total_rules


def main():
    parser = argparse.ArgumentParser(description='AWS Config Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('config')
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

        rules = scan_config(session, regions, writer)
        writer.set("total_rules", rules)
        writer.set("status", "ok")

        logger.info(f"  Total: {rules} config rules")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
