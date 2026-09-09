#!/usr/bin/env python3
"""
Amazon EBS & Elastic IP Inventory Scanner
Scans all configured AWS accounts/regions for:
  - EBS volumes (highlights unattached — pure waste)
  - EBS snapshots (old snapshots = storage cost)
  - Elastic IPs (unassociated = $3.65/mo each)

Usage:
    python get_ebs_inventory.py
    python get_ebs_inventory.py -a "Production"
    python get_ebs_inventory.py -r us-east-1
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

SERVICE = "ebs"


def scan_ebs(session, regions, writer):
    """Scan EBS volumes, snapshots, and Elastic IPs across all specified regions."""
    totals = {
        "volumes": 0, "unattached_volumes": 0, "unattached_volume_gb": 0,
        "snapshots": 0,
        "elastic_ips": 0, "unassociated_eips": 0,
    }

    for region in regions:
        try:
            ec2 = session.client('ec2', region_name=region, config=BOTO_CONFIG)
            region_data = {"volumes": [], "unattached_volumes": [], "snapshots_summary": {}, "elastic_ips": []}

            # EBS Volumes
            paginator = ec2.get_paginator('describe_volumes')
            all_volumes = []
            unattached = []
            for page in paginator.paginate():
                for vol in page.get('Volumes', []):
                    tags = {t['Key']: t['Value'] for t in vol.get('Tags', [])}
                    entry = {
                        "volume_id": vol['VolumeId'],
                        "name": tags.get('Name', ''),
                        "state": vol.get('State', 'N/A'),
                        "size_gb": vol.get('Size', 0),
                        "volume_type": vol.get('VolumeType', 'N/A'),
                        "iops": vol.get('Iops', 0),
                        "throughput": vol.get('Throughput', 0),
                        "encrypted": vol.get('Encrypted', False),
                        "az": vol.get('AvailabilityZone', 'N/A'),
                        "attached_to": "",
                        "attached": False,
                        "created_at": vol.get('CreateTime', ''),
                    }
                    attachments = vol.get('Attachments', [])
                    if attachments:
                        entry["attached"] = True
                        entry["attached_to"] = attachments[0].get('InstanceId', '')
                    else:
                        unattached.append(entry)

                    all_volumes.append(entry)

            region_data["volumes"] = all_volumes
            region_data["unattached_volumes"] = unattached
            totals["volumes"] += len(all_volumes)
            totals["unattached_volumes"] += len(unattached)
            totals["unattached_volume_gb"] += sum(v["size_gb"] for v in unattached)

            # Snapshots — just summary (can be thousands)
            snapshot_count = 0
            snapshot_total_gb = 0
            try:
                paginator = ec2.get_paginator('describe_snapshots')
                for page in paginator.paginate(OwnerIds=['self']):
                    for snap in page.get('Snapshots', []):
                        snapshot_count += 1
                        snapshot_total_gb += snap.get('VolumeSize', 0)
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: Snapshots error — {e}")

            region_data["snapshots_summary"] = {
                "count": snapshot_count,
                "total_gb": snapshot_total_gb,
            }
            totals["snapshots"] += snapshot_count

            # Elastic IPs
            try:
                eip_resp = ec2.describe_addresses()
                for eip in eip_resp.get('Addresses', []):
                    entry = {
                        "public_ip": eip.get('PublicIp', 'N/A'),
                        "allocation_id": eip.get('AllocationId', 'N/A'),
                        "associated": bool(eip.get('AssociationId')),
                        "instance_id": eip.get('InstanceId', ''),
                        "network_interface_id": eip.get('NetworkInterfaceId', ''),
                        "domain": eip.get('Domain', 'vpc'),
                        "tags": {t['Key']: t['Value'] for t in eip.get('Tags', [])},
                    }
                    region_data["elastic_ips"].append(entry)
                    totals["elastic_ips"] += 1
                    if not entry["associated"]:
                        totals["unassociated_eips"] += 1
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: EIP error — {e}")

            writer.set_nested("regions", region, value=region_data)

            # Log summary for this region
            if all_volumes or region_data["elastic_ips"]:
                logger.info(f"  {region}: {len(all_volumes)} volumes ({len(unattached)} unattached, "
                           f"{sum(v['size_gb'] for v in unattached)} GB waste), "
                           f"{snapshot_count} snapshots, "
                           f"{len(region_data['elastic_ips'])} EIPs "
                           f"({sum(1 for e in region_data['elastic_ips'] if not e['associated'])} unassociated)")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value={})

    return totals


def main():
    parser = argparse.ArgumentParser(description='EBS & Elastic IP Inventory Scanner')
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

        totals = scan_ebs(session, regions, writer)
        writer.set("totals", totals)
        writer.set("status", "ok")

        # Cost estimate
        # ponytail: gp3 ~$0.08/GB/mo, unassociated EIP ~$3.65/mo
        ebs_waste = totals["unattached_volume_gb"] * 0.08
        eip_waste = totals["unassociated_eips"] * 3.65
        total_waste = ebs_waste + eip_waste
        writer.set("estimated_monthly_waste_usd", round(total_waste, 2))

        logger.info(f"  Summary: {totals['volumes']} volumes, "
                   f"{totals['unattached_volumes']} unattached ({totals['unattached_volume_gb']} GB), "
                   f"{totals['snapshots']} snapshots, "
                   f"{totals['elastic_ips']} EIPs ({totals['unassociated_eips']} unassociated)")
        if total_waste > 0:
            logger.info(f"  💰 Estimated waste: ${total_waste:,.2f}/mo "
                       f"(EBS: ${ebs_waste:,.2f} + EIP: ${eip_waste:,.2f})")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
