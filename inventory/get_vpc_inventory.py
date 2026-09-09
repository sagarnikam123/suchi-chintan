#!/usr/bin/env python3
"""
VPC Inventory Scanner
Scans VPCs, subnets, NAT gateways, VPC endpoints, and peering connections.

Usage:
    python get_vpc_inventory.py                     # All accounts, all regions
    python get_vpc_inventory.py -a "TQ Hosted"      # Single account
    python get_vpc_inventory.py -p <profile> -r us-east-1
"""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, get_regions, create_session,
    get_output_dir, get_timestamp, add_common_args,
    create_session_with_identity, is_region_unsupported_error, log_region_skip,
    run_with_timer, make_output_filename, IncrementalWriter,
)


def get_name_tag(tags):
    """Extract Name tag from a list of tag dicts."""
    if not tags:
        return 'N/A'
    for tag in tags:
        if tag['Key'] == 'Name':
            return tag['Value']
    return 'N/A'


def scan_vpc(session, regions, writer):
    """Scan VPCs, subnets, NAT gateways, endpoints, and peering."""
    totals = {"vpcs": 0, "subnets": 0, "nat_gateways": 0, "endpoints": 0, "peering": 0, "transit_gateways": 0, "tgw_attachments": 0}

    for region in regions:
        region_data = {"vpcs": [], "nat_gateways": [], "endpoints": [], "peering": [], "transit_gateways": [], "tgw_attachments": []}

        try:
            ec2 = session.client('ec2', region_name=region, config=BOTO_CONFIG)

            # VPCs with subnets
            vpc_resp = ec2.describe_vpcs()
            for vpc in vpc_resp.get('Vpcs', []):
                vpc_id = vpc['VpcId']

                # Get subnets for this VPC
                subnet_resp = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
                subnets = []
                for s in subnet_resp.get('Subnets', []):
                    subnets.append({
                        "subnet_id": s['SubnetId'],
                        "name": get_name_tag(s.get('Tags')),
                        "cidr": s['CidrBlock'],
                        "az": s['AvailabilityZone'],
                        "available_ips": s['AvailableIpAddressCount'],
                        "public": s.get('MapPublicIpOnLaunch', False),
                    })

                vpc_info = {
                    "vpc_id": vpc_id,
                    "name": get_name_tag(vpc.get('Tags')),
                    "cidr": vpc.get('CidrBlock', ''),
                    "state": vpc.get('State', ''),
                    "is_default": vpc.get('IsDefault', False),
                    "subnet_count": len(subnets),
                    "subnets": subnets,
                }
                region_data["vpcs"].append(vpc_info)
                totals["subnets"] += len(subnets)

            # NAT Gateways (expensive — $0.045/hr each)
            nat_resp = ec2.describe_nat_gateways(
                Filter=[{'Name': 'state', 'Values': ['available', 'pending']}]
            )
            for nat in nat_resp.get('NatGateways', []):
                region_data["nat_gateways"].append({
                    "nat_gateway_id": nat['NatGatewayId'],
                    "name": get_name_tag(nat.get('Tags')),
                    "state": nat['State'],
                    "vpc_id": nat.get('VpcId', ''),
                    "subnet_id": nat.get('SubnetId', ''),
                    "connectivity_type": nat.get('ConnectivityType', 'public'),
                    "public_ip": nat.get('NatGatewayAddresses', [{}])[0].get('PublicIp', 'N/A') if nat.get('NatGatewayAddresses') else 'N/A',
                    "created_at": nat.get('CreateTime', ''),
                })

            # VPC Endpoints
            ep_resp = ec2.describe_vpc_endpoints()
            for ep in ep_resp.get('VpcEndpoints', []):
                region_data["endpoints"].append({
                    "endpoint_id": ep['VpcEndpointId'],
                    "service_name": ep['ServiceName'],
                    "type": ep['VpcEndpointType'],
                    "state": ep['State'],
                    "vpc_id": ep.get('VpcId', ''),
                })

            # VPC Peering
            peer_resp = ec2.describe_vpc_peering_connections(
                Filters=[{'Name': 'status-code', 'Values': ['active', 'pending-acceptance']}]
            )
            for pc in peer_resp.get('VpcPeeringConnections', []):
                region_data["peering"].append({
                    "peering_id": pc['VpcPeeringConnectionId'],
                    "name": get_name_tag(pc.get('Tags')),
                    "status": pc['Status']['Code'],
                    "requester_vpc": pc.get('RequesterVpcInfo', {}).get('VpcId', ''),
                    "requester_cidr": pc.get('RequesterVpcInfo', {}).get('CidrBlock', ''),
                    "accepter_vpc": pc.get('AccepterVpcInfo', {}).get('VpcId', ''),
                    "accepter_cidr": pc.get('AccepterVpcInfo', {}).get('CidrBlock', ''),
                    "accepter_account": pc.get('AccepterVpcInfo', {}).get('OwnerId', ''),
                })

            # Transit Gateways
            try:
                tgw_resp = ec2.describe_transit_gateways(
                    Filters=[{'Name': 'state', 'Values': ['available', 'pending']}]
                )
                for tgw in tgw_resp.get('TransitGateways', []):
                    region_data["transit_gateways"].append({
                        "tgw_id": tgw['TransitGatewayId'],
                        "name": get_name_tag(tgw.get('Tags')),
                        "state": tgw['State'],
                        "owner_id": tgw.get('OwnerId', ''),
                        "amazon_side_asn": tgw.get('Options', {}).get('AmazonSideAsn', ''),
                        "auto_accept_shared": tgw.get('Options', {}).get('AutoAcceptSharedAttachments', ''),
                    })
            except Exception:
                pass  # ponytail: TGW API may not be available in all regions/accounts

            # Transit Gateway VPC Attachments (the key connectivity data)
            try:
                tgw_att_resp = ec2.describe_transit_gateway_vpc_attachments(
                    Filters=[{'Name': 'state', 'Values': ['available', 'pending', 'modifying']}]
                )
                for att in tgw_att_resp.get('TransitGatewayVpcAttachments', []):
                    region_data["tgw_attachments"].append({
                        "attachment_id": att['TransitGatewayAttachmentId'],
                        "tgw_id": att['TransitGatewayId'],
                        "vpc_id": att['VpcId'],
                        "vpc_owner_id": att.get('VpcOwnerId', ''),
                        "state": att['State'],
                        "subnet_ids": att.get('SubnetIds', []),
                        "name": get_name_tag(att.get('Tags')),
                    })
            except Exception:
                pass  # ponytail: TGW attachments API may not be available

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, 'ec2', str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")

        vpc_count = len(region_data["vpcs"])
        nat_count = len(region_data["nat_gateways"])
        ep_count = len(region_data["endpoints"])
        tgw_count = len(region_data["transit_gateways"])
        tgw_att_count = len(region_data["tgw_attachments"])

        if vpc_count > 0:
            logger.info(f"  {region}: {vpc_count} VPCs, {nat_count} NAT GWs, {ep_count} endpoints, {tgw_count} TGWs, {tgw_att_count} TGW attachments")

        writer.set_nested("regions", region, value=region_data)
        totals["vpcs"] += vpc_count
        totals["nat_gateways"] += nat_count
        totals["endpoints"] += ep_count
        totals["peering"] += len(region_data["peering"])
        totals["transit_gateways"] += tgw_count
        totals["tgw_attachments"] += tgw_att_count

    return totals


def main():
    parser = argparse.ArgumentParser(description='VPC Inventory Scanner')
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

    inventory = {
        "generated": timestamp,
        "accounts": {},
        "summary": {"total_vpcs": 0, "total_subnets": 0, "total_nat_gateways": 0, "total_endpoints": 0, "total_peering": 0, "total_transit_gateways": 0, "total_tgw_attachments": 0}
    }

    for account in accounts:
        name = account['name']
        account_id = account['account_id']
        profile = account['profile']

        logger.info(f"🔍 {name} ({account_id})")

        # Reuse session from --profile if already authenticated
        session = account.get('_session') or create_session(profile)
        if not session:
            inventory["accounts"][account_id] = {"name": name, "status": "auth_failed", "regions": {}}
            continue

        output_dir = get_output_dir(account_id, "vpc")
        writer = IncrementalWriter(output_dir, make_output_filename("vpc", account_id, timestamp))
        writer.update({"name": name, "profile_used": profile, "status": "in_progress", "regions": {}})

        totals = scan_vpc(session, regions, writer)

        writer.set("total_vpcs", totals["vpcs"])
        writer.set("total_subnets", totals["subnets"])
        writer.set("total_nat_gateways", totals["nat_gateways"])
        writer.set("total_endpoints", totals["endpoints"])
        writer.set("total_peering", totals["peering"])
        writer.set("total_transit_gateways", totals["transit_gateways"])
        writer.set("total_tgw_attachments", totals["tgw_attachments"])
        writer.set("status", "ok")

        inventory["accounts"][account_id] = {"name": name, "status": "ok"}
        for k in totals:
            inventory["summary"][f"total_{k}"] += totals[k]

    logger.info("" + "=" * 60)
    logger.info("📊 SUMMARY")
    logger.info("=" * 60)
    logger.info(f"  Total VPCs: {inventory['summary']['total_vpcs']}")
    logger.info(f"  Total Subnets: {inventory['summary']['total_subnets']}")
    logger.info(f"  Total NAT Gateways: {inventory['summary']['total_nat_gateways']} (💰 ~${inventory['summary']['total_nat_gateways'] * 32:.0f}/mo)")
    logger.info(f"  Total VPC Endpoints: {inventory['summary']['total_endpoints']}")
    logger.info(f"  Total Peering Connections: {inventory['summary']['total_peering']}")
    logger.info(f"  Total Transit Gateways: {inventory['summary']['total_transit_gateways']}")
    logger.info(f"  Total TGW VPC Attachments: {inventory['summary']['total_tgw_attachments']}")


if __name__ == "__main__":
    run_with_timer(main)
