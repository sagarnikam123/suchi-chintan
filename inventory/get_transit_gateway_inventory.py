#!/usr/bin/env python3
"""
AWS Transit Gateway Inventory Scanner
Scans all configured AWS accounts/regions for Transit Gateways and their attachments.

Usage:
    python get_transit_gateway_inventory.py
    python get_transit_gateway_inventory.py -a "TQ Primary"
    python get_transit_gateway_inventory.py -r us-east-1
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

SERVICE = "transit-gateway"


def scan_transit_gateways(session, regions, writer):
    """Scan Transit Gateways and attachments across all specified regions."""
    total_tgws = 0
    total_attachments = 0

    for region in regions:
        try:
            client = session.client('ec2', region_name=region, config=BOTO_CONFIG)
            region_data = {"transit_gateways": [], "attachments": []}

            # Transit Gateways
            try:
                paginator = client.get_paginator('describe_transit_gateways')
                for page in paginator.paginate():
                    for tgw in page.get('TransitGateways', []):
                        region_data["transit_gateways"].append({
                            "tgw_id": tgw['TransitGatewayId'],
                            "state": tgw.get('State', 'N/A'),
                            "owner_id": tgw.get('OwnerId', 'N/A'),
                            "description": tgw.get('Description', ''),
                            "amazon_side_asn": tgw.get('Options', {}).get('AmazonSideAsn', 0),
                            "auto_accept_shared": tgw.get('Options', {}).get('AutoAcceptSharedAttachments', 'disable'),
                            "default_route_table_association": tgw.get('Options', {}).get('DefaultRouteTableAssociation', 'N/A'),
                            "dns_support": tgw.get('Options', {}).get('DnsSupport', 'N/A'),
                            "created_at": tgw.get('CreationTime', ''),
                            "tags": {t['Key']: t['Value'] for t in tgw.get('Tags', [])},
                        })
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: TGW error — {e}")

            # Attachments
            try:
                paginator = client.get_paginator('describe_transit_gateway_attachments')
                for page in paginator.paginate():
                    for att in page.get('TransitGatewayAttachments', []):
                        region_data["attachments"].append({
                            "attachment_id": att['TransitGatewayAttachmentId'],
                            "tgw_id": att.get('TransitGatewayId', 'N/A'),
                            "resource_type": att.get('ResourceType', 'N/A'),
                            "resource_id": att.get('ResourceId', 'N/A'),
                            "resource_owner_id": att.get('ResourceOwnerId', 'N/A'),
                            "state": att.get('State', 'N/A'),
                            "tags": {t['Key']: t['Value'] for t in att.get('Tags', [])},
                        })
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: Attachments error — {e}")

            writer.set_nested("regions", region, value=region_data)
            total_tgws += len(region_data["transit_gateways"])
            total_attachments += len(region_data["attachments"])

            if region_data["transit_gateways"] or region_data["attachments"]:
                logger.info(f"  {region}: {len(region_data['transit_gateways'])} TGWs, "
                           f"{len(region_data['attachments'])} attachments")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value={})

    return total_tgws, total_attachments


def main():
    parser = argparse.ArgumentParser(description='Transit Gateway Inventory Scanner')
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

        tgws, attachments = scan_transit_gateways(session, regions, writer)
        writer.set("total_transit_gateways", tgws)
        writer.set("total_attachments", attachments)
        writer.set("status", "ok")

        logger.info(f"  Total: {tgws} transit gateways, {attachments} attachments")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
