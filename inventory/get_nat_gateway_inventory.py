#!/usr/bin/env python3
"""
NAT Gateway Inventory Scanner
Scans all NAT Gateways across regions in parallel.

Usage:
    python get_nat_gateway_inventory.py -p <profile>
    python get_nat_gateway_inventory.py -p <profile> -r us-east-1
"""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, get_regions, create_session,
    get_output_dir, get_timestamp, add_common_args,
    create_session_with_identity, is_region_unsupported_error, log_region_skip,
    IncrementalWriter, make_output_filename,
    run_with_timer, scan_regions_parallel,
)

SERVICE = "nat-gateways"
NAT_HOURLY_COST = 0.045  # $/hr per NAT gateway
HOURS_PER_MONTH = 720


def get_name_tag(tags):
    if not tags:
        return 'N/A'
    for tag in tags:
        if tag['Key'] == 'Name':
            return tag['Value']
    return 'N/A'


def scan_region(session, region):
    """Scan NAT gateways in one region. Returns (region_data, counts)."""
    region_data = []
    counts = {"nat_gateways": 0, "estimated_monthly_cost": 0.0}

    try:
        ec2 = session.client('ec2', region_name=region, config=BOTO_CONFIG)

        paginator = ec2.get_paginator('describe_nat_gateways')
        for page in paginator.paginate(Filter=[{'Name': 'state', 'Values': ['available']}]):
            for nat in page.get('NatGateways', []):
                nat_info = {
                    "nat_gateway_id": nat['NatGatewayId'],
                    "name": get_name_tag(nat.get('Tags')),
                    "state": nat['State'],
                    "vpc_id": nat.get('VpcId', ''),
                    "subnet_id": nat.get('SubnetId', ''),
                    "connectivity_type": nat.get('ConnectivityType', 'public'),
                    "public_ip": nat.get('NatGatewayAddresses', [{}])[0].get('PublicIp', 'N/A') if nat.get('NatGatewayAddresses') else 'N/A',
                    "private_ip": nat.get('NatGatewayAddresses', [{}])[0].get('PrivateIp', 'N/A') if nat.get('NatGatewayAddresses') else 'N/A',
                    "created_at": nat.get('CreateTime', ''),
                    "monthly_base_cost_usd": round(NAT_HOURLY_COST * HOURS_PER_MONTH, 2),
                }
                region_data.append(nat_info)

        count = len(region_data)
        counts["nat_gateways"] = count
        counts["estimated_monthly_cost"] = round(count * NAT_HOURLY_COST * HOURS_PER_MONTH, 2)

    except Exception as e:
        if is_region_unsupported_error(e):
            log_region_skip(region, "nat-gateway", str(e))
            return [], counts
        logger.warning(f"  {region}: Error — {e}")
        return [], counts

    return region_data, counts


def scan_nat_gateways(session, regions, writer):
    """Scan NAT gateways across all regions in parallel."""
    totals = scan_regions_parallel(
        session, regions, writer, scan_region,
        log_fn=lambda region, c: logger.info(
            f"  {region}: {c['nat_gateways']} NAT gateway(s) (💰 ~${c['estimated_monthly_cost']:.0f}/mo base)"
        ) if c.get('nat_gateways', 0) > 0 else None,
    )
    return totals


def main():
    parser = argparse.ArgumentParser(description='NAT Gateway Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    if args.profile:
        session, account_id, arn = create_session_with_identity(args.profile)
        if not session:
            sys.exit(1)
        accounts = [{"name": account_id, "account_id": account_id, "profile": args.profile, "_session": session}]
    else:
        accounts = get_accounts(args.account)

    regions = [args.region] if args.region else get_regions('ec2')
    timestamp = get_timestamp()

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
        writer = IncrementalWriter(output_dir, make_output_filename("nat-gateway", account_id, timestamp))
        writer.update({
            "name": name,
            "profile_used": profile,
            "status": "in_progress",
            "note": "Base cost only ($0.045/hr per NAT). Data processing adds $0.045/GB on top.",
            "regions": {},
        })

        totals = scan_nat_gateways(session, regions, writer)

        writer.set("total_nat_gateways", totals.get("nat_gateways", 0))
        writer.set("estimated_monthly_base_cost_usd", round(totals.get("estimated_monthly_cost", 0.0), 2))
        writer.set("status", "ok")

        logger.info(f"  Total: {totals.get('nat_gateways', 0)} NAT gateways, ~${totals.get('estimated_monthly_cost', 0.0):.0f}/mo base cost")

    logger.info("=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
