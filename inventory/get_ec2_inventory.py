#!/usr/bin/env python3
"""
EC2 Instance Inventory Scanner
Scans all configured AWS accounts/regions and produces a JSON inventory.

Usage:
    python get_ec2_inventory.py                     # All accounts, all regions
    python get_ec2_inventory.py -a "TQ Primary"     # Single account
    python get_ec2_inventory.py -r us-east-1        # Single region
    python get_ec2_inventory.py --tag Service=loki  # Filter by tag
"""

import sys
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional

# Add parent directory for common imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, get_regions, create_session,
    get_output_dir, get_timestamp, add_common_args,
    create_session_with_identity, is_region_unsupported_error, log_region_skip,
    run_with_timer, make_output_filename, IncrementalWriter,
)


TERMINATED_STATES = ['terminated', 'shutting-down']


def scan_ec2_instances(session, regions, writer, tag_filter=None):
    """Scan EC2 instances across all specified regions."""
    total_instances = 0

    filters = []
    if tag_filter:
        key, value = tag_filter.split('=', 1)
        filters = [{'Name': f'tag:{key}', 'Values': [value]}]

    for region in regions:
        try:
            ec2_client = session.client('ec2', region_name=region, config=BOTO_CONFIG)
            kwargs = {'Filters': filters} if filters else {}

            instances = []
            paginator = ec2_client.get_paginator('describe_instances')
            for page in paginator.paginate(**kwargs):
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        # Extract tags into a flat dict
                        tags = {}
                        for tag in instance.get('Tags', []):
                            tags[tag['Key']] = tag['Value']

                        instance_info = {
                            "instance_id": instance['InstanceId'],
                            "name": tags.get('Name', 'N/A'),
                            "state": instance['State']['Name'],
                            "type": instance.get('InstanceType', 'N/A'),
                            "private_ip": instance.get('PrivateIpAddress', 'N/A'),
                            "public_ip": instance.get('PublicIpAddress', 'N/A'),
                            "private_dns": instance.get('PrivateDnsName', 'N/A'),
                            "key_name": instance.get('KeyName', 'N/A'),
                            "launch_time": instance.get('LaunchTime', ''),
                            "az": instance.get('Placement', {}).get('AvailabilityZone', 'N/A'),
                            "vpc_id": instance.get('VpcId', 'N/A'),
                            "tags": tags,
                            # --- Fields below not in original get_ec2_details.py ---
                            # Uncomment as needed for deeper analysis
                            # "architecture": instance.get('Architecture', 'N/A'),
                            # "platform": instance.get('PlatformDetails', 'N/A'),
                            # "public_dns": instance.get('PublicDnsName', ''),
                            # "subnet_id": instance.get('SubnetId', 'N/A'),
                            # "ami_id": instance.get('ImageId', 'N/A'),
                            # "ebs_optimized": instance.get('EbsOptimized', False),
                            # "root_device_type": instance.get('RootDeviceType', 'N/A'),
                            # "iam_profile": instance.get('IamInstanceProfile', {}).get('Arn', 'N/A'),
                            # "security_groups": [sg['GroupName'] for sg in instance.get('SecurityGroups', [])],
                            # "ebs_volumes": len(instance.get('BlockDeviceMappings', [])),
                            # "cpu_cores": instance.get('CpuOptions', {}).get('CoreCount', 'N/A'),
                            # "cpu_threads_per_core": instance.get('CpuOptions', {}).get('ThreadsPerCore', 'N/A'),
                        }
                        instances.append(instance_info)

            # Filter out terminated
            active_instances = [i for i in instances if i['state'] not in TERMINATED_STATES]
            total_instances += len(active_instances)

            # Flush per-region
            writer.set_nested("regions", region, value=active_instances)

            if active_instances:
                logger.info(f"  {region}: {len(active_instances)} instances")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, 'ec2', str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value=[])

    return total_instances


def main():
    parser = argparse.ArgumentParser(description='EC2 Instance Inventory Scanner')
    add_common_args(parser)
    parser.add_argument('--tag', '-t', help='Filter by tag (format: Key=Value)', default=None)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('ec2')
    timestamp = get_timestamp()

    # If --profile is used, bypass accounts.yaml entirely
    if args.profile:
        session, account_id, arn = create_session_with_identity(args.profile)
        if not session:
            sys.exit(1)
        accounts = [{"name": account_id, "account_id": account_id, "profile": args.profile, "_session": session}]

    logger.info(f"Scanning {len(accounts)} account(s) across {len(regions)} region(s)")
    if args.tag:
        logger.info(f"Tag filter: {args.tag}")
    logger.info("=" * 60)

    inventory = {
        "generated": timestamp,
        "accounts": {},
        "summary": {
            "total_accounts_scanned": len(accounts),
            "total_instances_found": 0,
            "instances_by_account": {}
        }
    }

    for account in accounts:
        name = account['name']
        account_id = account['account_id']
        profile = account['profile']

        logger.info(f"🔍 {name} ({account_id}) — profile: {profile}")

        # Reuse session from --profile if already authenticated
        session = account.get("_session") or create_session(profile)
        if not session:
            inventory["accounts"][account_id] = {
                "name": name, "status": "auth_failed", "total_instances": 0, "regions": {}
            }
            continue

        output_dir = get_output_dir(account_id, "ec2")
        writer = IncrementalWriter(output_dir, make_output_filename("ec2", account_id, timestamp))
        writer.update({"name": name, "profile_used": profile, "status": "in_progress", "regions": {}})

        total = scan_ec2_instances(session, regions, writer, args.tag)
        writer.set("total_instances", total)
        writer.set("status", "ok")

        inventory["accounts"][account_id] = {"name": name}
        inventory["summary"]["instances_by_account"][account_id] = total
        inventory["summary"]["total_instances_found"] += total

    # Summary
    logger.info("" + "=" * 60)
    logger.info("📊 SUMMARY")
    logger.info("=" * 60)
    for account_id, count in inventory["summary"]["instances_by_account"].items():
        acct_name = inventory["accounts"][account_id].get("name", account_id)
        logger.info(f"  {acct_name} ({account_id}): {count} instances")
    logger.info(f"  TOTAL: {inventory['summary']['total_instances_found']} instances")


if __name__ == "__main__":
    run_with_timer(main)
