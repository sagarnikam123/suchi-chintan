#!/usr/bin/env python3
"""
AWS VPC Endpoints Inventory Scanner
Scans all configured AWS accounts/regions for VPC Interface and Gateway endpoints.

Usage:
    python get_vpc_endpoints_inventory.py
    python get_vpc_endpoints_inventory.py -a "TQ Primary"
    python get_vpc_endpoints_inventory.py -r us-east-1
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

SERVICE = "vpc-endpoints"


def scan_vpc_endpoints(session, regions, writer):
    """Scan VPC endpoints across all specified regions."""
    total = 0

    for region in regions:
        try:
            client = session.client('ec2', region_name=region, config=BOTO_CONFIG)
            endpoints = []

            paginator = client.get_paginator('describe_vpc_endpoints')
            for page in paginator.paginate():
                for ep in page.get('VpcEndpoints', []):
                    endpoints.append({
                        "endpoint_id": ep['VpcEndpointId'],
                        "service_name": ep.get('ServiceName', 'N/A'),
                        "endpoint_type": ep.get('VpcEndpointType', 'N/A'),
                        "state": ep.get('State', 'N/A'),
                        "vpc_id": ep.get('VpcId', 'N/A'),
                        "subnet_ids": ep.get('SubnetIds', []),
                        "network_interface_ids": ep.get('NetworkInterfaceIds', []),
                        "private_dns_enabled": ep.get('PrivateDnsEnabled', False),
                        "route_table_ids": ep.get('RouteTableIds', []),
                        "created_at": ep.get('CreationTimestamp', ''),
                        "tags": {t['Key']: t['Value'] for t in ep.get('Tags', [])},
                    })

            writer.set_nested("regions", region, value=endpoints)
            total += len(endpoints)

            if endpoints:
                # Count by type
                interface_count = sum(1 for e in endpoints if e["endpoint_type"] == "Interface")
                gateway_count = sum(1 for e in endpoints if e["endpoint_type"] == "Gateway")
                logger.info(f"  {region}: {interface_count} interface, {gateway_count} gateway endpoints")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value=[])

    return total


def main():
    parser = argparse.ArgumentParser(description='VPC Endpoints Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('ec2')
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

        total = scan_vpc_endpoints(session, regions, writer)
        writer.set("total_endpoints", total)
        writer.set("status", "ok")

        logger.info(f"  Total: {total} endpoints")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
