#!/usr/bin/env python3
"""
Amazon Inspector Inventory Scanner
Scans all configured AWS accounts/regions for Inspector coverage and finding counts.

Usage:
    python get_inspector_inventory.py
    python get_inspector_inventory.py -a "TQ Primary"
    python get_inspector_inventory.py -r us-east-1
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

SERVICE = "inspector"


def scan_inspector(session, regions, writer):
    """Scan Inspector coverage across all specified regions."""
    total_findings = 0

    for region in regions:
        try:
            client = session.client('inspector2', region_name=region, config=BOTO_CONFIG)
            region_data = {"enabled": False, "coverage": {}, "finding_counts": {}}

            # Check account status
            try:
                resp = client.batch_get_account_status(accountIds=[])
                accounts_status = resp.get('accounts', [])
                if accounts_status:
                    status = accounts_status[0]
                    resource_state = status.get('resourceState', {})
                    region_data["enabled"] = status.get('state', {}).get('status', '') == 'ENABLED'
                    region_data["ec2_scanning"] = resource_state.get('ec2', {}).get('status', 'DISABLED')
                    region_data["ecr_scanning"] = resource_state.get('ecr', {}).get('status', 'DISABLED')
                    region_data["lambda_scanning"] = resource_state.get('lambda', {}).get('status', 'DISABLED')
            except Exception as e:
                if is_region_unsupported_error(e) or 'AccessDeniedException' in str(e) or 'not enabled' in str(e).lower():
                    writer.set_nested("regions", region, value={"enabled": False})
                    continue
                logger.warning(f"  {region}: Status error — {e}")

            # Finding counts by severity
            try:
                resp = client.list_finding_aggregations(
                    aggregationType='SEVERITY',
                )
                for agg in resp.get('responses', []):
                    severity_agg = agg.get('severityCounts', agg)
                    if 'severityCounts' in agg:
                        region_data["finding_counts"] = {
                            "critical": severity_agg.get('critical', 0),
                            "high": severity_agg.get('high', 0),
                            "medium": severity_agg.get('medium', 0),
                        }
                        total_findings += sum(region_data["finding_counts"].values())
            except Exception:
                pass

            writer.set_nested("regions", region, value=region_data)

            if region_data["enabled"]:
                logger.info(f"  {region}: enabled (EC2={region_data.get('ec2_scanning','?')}, "
                           f"ECR={region_data.get('ecr_scanning','?')}, Lambda={region_data.get('lambda_scanning','?')})")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value={"enabled": False})

    return total_findings


def main():
    parser = argparse.ArgumentParser(description='Inspector Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('inspector2')
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

        findings = scan_inspector(session, regions, writer)
        writer.set("total_findings_across_regions", findings)
        writer.set("status", "ok")

        logger.info(f"  Total findings: {findings}")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
