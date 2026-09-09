#!/usr/bin/env python3
"""
AWS Direct Connect Inventory Scanner
Scans all configured AWS accounts/regions for Direct Connect connections and virtual interfaces.

Usage:
    python get_direct_connect_inventory.py
    python get_direct_connect_inventory.py -a "TQ Primary"
    python get_direct_connect_inventory.py -r us-east-1
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

SERVICE = "direct-connect"


def scan_direct_connect(session, regions, writer):
    """Scan Direct Connect connections and virtual interfaces across all specified regions."""
    total_connections = 0
    total_vifs = 0

    for region in regions:
        try:
            client = session.client('directconnect', region_name=region, config=BOTO_CONFIG)
            region_data = {"connections": [], "virtual_interfaces": []}

            # Connections
            try:
                resp = client.describe_connections()
                for conn in resp.get('connections', []):
                    region_data["connections"].append({
                        "connection_id": conn.get('connectionId', 'N/A'),
                        "connection_name": conn.get('connectionName', 'N/A'),
                        "state": conn.get('connectionState', 'N/A'),
                        "bandwidth": conn.get('bandwidth', 'N/A'),
                        "location": conn.get('location', 'N/A'),
                        "vlan": conn.get('vlan', 0),
                        "partner_name": conn.get('partnerName', ''),
                        "has_logical_redundancy": conn.get('hasLogicalRedundancy', 'N/A'),
                        "aws_device_v2": conn.get('awsDeviceV2', ''),
                    })
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: Connections error — {e}")

            # Virtual interfaces
            try:
                resp = client.describe_virtual_interfaces()
                for vif in resp.get('virtualInterfaces', []):
                    region_data["virtual_interfaces"].append({
                        "vif_id": vif.get('virtualInterfaceId', 'N/A'),
                        "vif_name": vif.get('virtualInterfaceName', 'N/A'),
                        "vif_type": vif.get('virtualInterfaceType', 'N/A'),
                        "state": vif.get('virtualInterfaceState', 'N/A'),
                        "connection_id": vif.get('connectionId', 'N/A'),
                        "vlan": vif.get('vlan', 0),
                        "amazon_side_asn": vif.get('amazonSideAsn', 0),
                        "bgp_peers": len(vif.get('bgpPeers', [])),
                    })
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: VIFs error — {e}")

            writer.set_nested("regions", region, value=region_data)
            total_connections += len(region_data["connections"])
            total_vifs += len(region_data["virtual_interfaces"])

            if region_data["connections"] or region_data["virtual_interfaces"]:
                logger.info(f"  {region}: {len(region_data['connections'])} connections, "
                           f"{len(region_data['virtual_interfaces'])} VIFs")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value={})

    return total_connections, total_vifs


def main():
    parser = argparse.ArgumentParser(description='Direct Connect Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('directconnect')
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

        connections, vifs = scan_direct_connect(session, regions, writer)
        writer.set("total_connections", connections)
        writer.set("total_virtual_interfaces", vifs)
        writer.set("status", "ok")

        logger.info(f"  Total: {connections} connections, {vifs} VIFs")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
