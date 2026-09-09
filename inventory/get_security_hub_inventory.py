#!/usr/bin/env python3
"""
AWS Security Hub Inventory Scanner
Scans all configured AWS accounts/regions for Security Hub enabled standards and finding counts.

Usage:
    python get_security_hub_inventory.py
    python get_security_hub_inventory.py -a "TQ Primary"
    python get_security_hub_inventory.py -r us-east-1
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

SERVICE = "security-hub"


def scan_security_hub(session, regions, writer):
    """Scan Security Hub across all specified regions."""
    total_standards = 0

    for region in regions:
        try:
            client = session.client('securityhub', region_name=region, config=BOTO_CONFIG)
            region_data = {"enabled": False, "standards": [], "finding_counts": {}}

            # Check if enabled
            try:
                hub = client.describe_hub()
                region_data["enabled"] = True
                region_data["hub_arn"] = hub.get('HubArn', 'N/A')
                region_data["subscribed_at"] = hub.get('SubscribedAt', '')
                region_data["auto_enable_controls"] = hub.get('AutoEnableControls', False)
            except client.exceptions.InvalidAccessException:
                # Security Hub not enabled
                writer.set_nested("regions", region, value={"enabled": False})
                continue
            except Exception as e:
                if 'not subscribed' in str(e).lower() or 'InvalidAccess' in str(e):
                    writer.set_nested("regions", region, value={"enabled": False})
                    continue
                raise

            # Enabled standards
            try:
                resp = client.get_enabled_standards()
                for std in resp.get('StandardsSubscriptions', []):
                    region_data["standards"].append({
                        "standards_arn": std.get('StandardsArn', 'N/A'),
                        "subscription_arn": std.get('StandardsSubscriptionArn', 'N/A'),
                        "status": std.get('StandardsStatus', 'N/A'),
                    })
                total_standards += len(region_data["standards"])
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: Standards error — {e}")

            # Finding counts by severity
            try:
                for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    resp = client.get_findings(
                        Filters={
                            'SeverityLabel': [{'Value': severity, 'Comparison': 'EQUALS'}],
                            'WorkflowStatus': [{'Value': 'NEW', 'Comparison': 'EQUALS'}],
                            'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}],
                        },
                        MaxResults=1
                    )
                    # We just need the total, not all findings
                    region_data["finding_counts"][severity] = len(resp.get('Findings', []))
            except Exception:
                pass

            writer.set_nested("regions", region, value=region_data)

            if region_data["enabled"]:
                logger.info(f"  {region}: enabled, {len(region_data['standards'])} standards")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value={"enabled": False})

    return total_standards


def main():
    parser = argparse.ArgumentParser(description='Security Hub Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('securityhub')
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

        standards = scan_security_hub(session, regions, writer)
        writer.set("total_enabled_standards", standards)
        writer.set("status", "ok")

        logger.info(f"  Total: {standards} enabled standards across regions")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
