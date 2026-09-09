#!/usr/bin/env python3
"""
AWS Network Firewall Inventory Scanner
Scans all configured AWS accounts/regions for Network Firewall firewalls and rule groups.

Usage:
    python get_network_firewall_inventory.py
    python get_network_firewall_inventory.py -a "TQ Primary"
    python get_network_firewall_inventory.py -r us-east-1
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

SERVICE = "network-firewall"


def scan_network_firewall(session, regions, writer):
    """Scan Network Firewall resources across all specified regions."""
    total_firewalls = 0
    total_rule_groups = 0

    for region in regions:
        try:
            client = session.client('network-firewall', region_name=region, config=BOTO_CONFIG)
            region_data = {"firewalls": [], "rule_groups": []}

            # Firewalls
            try:
                resp = client.list_firewalls()
                for fw in resp.get('Firewalls', []):
                    fw_name = fw.get('FirewallName', 'N/A')
                    entry = {
                        "firewall_name": fw_name,
                        "firewall_arn": fw.get('FirewallArn', 'N/A'),
                    }
                    # Get details
                    try:
                        detail = client.describe_firewall(FirewallName=fw_name)
                        fw_detail = detail.get('Firewall', {})
                        status = detail.get('FirewallStatus', {})
                        entry.update({
                            "vpc_id": fw_detail.get('VpcId', 'N/A'),
                            "subnet_mappings": [s.get('SubnetId', '') for s in fw_detail.get('SubnetMappings', [])],
                            "delete_protection": fw_detail.get('DeleteProtection', False),
                            "policy_arn": fw_detail.get('FirewallPolicyArn', 'N/A'),
                            "status": status.get('Status', 'N/A'),
                        })
                    except Exception:
                        pass
                    region_data["firewalls"].append(entry)
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: Firewalls error — {e}")

            # Rule groups
            try:
                resp = client.list_rule_groups()
                for rg in resp.get('RuleGroups', []):
                    region_data["rule_groups"].append({
                        "name": rg.get('Name', 'N/A'),
                        "arn": rg.get('Arn', 'N/A'),
                    })
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: Rule groups error — {e}")

            writer.set_nested("regions", region, value=region_data)
            total_firewalls += len(region_data["firewalls"])
            total_rule_groups += len(region_data["rule_groups"])

            if region_data["firewalls"] or region_data["rule_groups"]:
                logger.info(f"  {region}: {len(region_data['firewalls'])} firewalls, "
                           f"{len(region_data['rule_groups'])} rule groups")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value={})

    return total_firewalls, total_rule_groups


def main():
    parser = argparse.ArgumentParser(description='Network Firewall Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('network-firewall')
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

        firewalls, rule_groups = scan_network_firewall(session, regions, writer)
        writer.set("total_firewalls", firewalls)
        writer.set("total_rule_groups", rule_groups)
        writer.set("status", "ok")

        logger.info(f"  Total: {firewalls} firewalls, {rule_groups} rule groups")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
