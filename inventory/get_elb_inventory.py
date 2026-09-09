#!/usr/bin/env python3
"""
ELB (Elastic Load Balancer) Inventory Scanner
Scans ALBs, NLBs, and Classic LBs with target groups.

Usage:
    python get_elb_inventory.py                     # All accounts, all regions
    python get_elb_inventory.py -a "TQ Hosted"      # Single account
    python get_elb_inventory.py -p <profile> -r us-east-1
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


def scan_elb(session, regions, writer):
    """Scan ALBs, NLBs, and Classic LBs with target groups."""
    totals = {"alb_nlb": 0, "classic": 0, "target_groups": 0}

    for region in regions:
        region_data = {"load_balancers": [], "classic_lbs": [], "target_groups": []}

        try:
            # ALB/NLB (ELBv2)
            elbv2 = session.client('elbv2', region_name=region, config=BOTO_CONFIG)

            paginator = elbv2.get_paginator('describe_load_balancers')
            for page in paginator.paginate():
                for lb in page.get('LoadBalancers', []):
                    lb_info = {
                        "name": lb['LoadBalancerName'],
                        "arn": lb['LoadBalancerArn'],
                        "type": lb['Type'],  # application or network
                        "scheme": lb['Scheme'],  # internet-facing or internal
                        "state": lb['State']['Code'],
                        "dns_name": lb.get('DNSName', ''),
                        "vpc_id": lb.get('VpcId', ''),
                        "azs": [az['ZoneName'] for az in lb.get('AvailabilityZones', [])],
                        "created_at": lb.get('CreatedTime', ''),
                        "ip_address_type": lb.get('IpAddressType', ''),
                    }
                    region_data["load_balancers"].append(lb_info)

            # Target Groups
            tg_paginator = elbv2.get_paginator('describe_target_groups')
            for page in tg_paginator.paginate():
                for tg in page.get('TargetGroups', []):
                    tg_info = {
                        "name": tg['TargetGroupName'],
                        "arn": tg['TargetGroupArn'],
                        "protocol": tg.get('Protocol', 'N/A'),
                        "port": tg.get('Port', 0),
                        "target_type": tg.get('TargetType', ''),
                        "vpc_id": tg.get('VpcId', ''),
                        "health_check_path": tg.get('HealthCheckPath', ''),
                        "lb_arns": tg.get('LoadBalancerArns', []),
                    }
                    region_data["target_groups"].append(tg_info)

            # Classic LB (ELB)
            try:
                elb_classic = session.client('elb', region_name=region, config=BOTO_CONFIG)
                classic_resp = elb_classic.describe_load_balancers()
                for clb in classic_resp.get('LoadBalancerDescriptions', []):
                    clb_info = {
                        "name": clb['LoadBalancerName'],
                        "dns_name": clb.get('DNSName', ''),
                        "scheme": clb.get('Scheme', ''),
                        "vpc_id": clb.get('VPCId', ''),
                        "azs": clb.get('AvailabilityZones', []),
                        "instances": len(clb.get('Instances', [])),
                        "listeners": len(clb.get('ListenerDescriptions', [])),
                        "created_at": clb.get('CreatedTime', ''),
                    }
                    region_data["classic_lbs"].append(clb_info)
            except Exception:
                pass

        except Exception as e:
            if not is_region_unsupported_error(e):
                logger.warning(f"  {region}: Error — {e}")

        lb_count = len(region_data["load_balancers"])
        clb_count = len(region_data["classic_lbs"])
        tg_count = len(region_data["target_groups"])

        if lb_count > 0 or clb_count > 0:
            logger.info(f"  {region}: {lb_count} ALB/NLB, {clb_count} Classic, {tg_count} target groups")

        writer.set_nested("regions", region, value=region_data)
        totals["alb_nlb"] += lb_count
        totals["classic"] += clb_count
        totals["target_groups"] += tg_count

    return totals


def main():
    parser = argparse.ArgumentParser(description='ELB Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('elb')
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
        "summary": {"total_alb_nlb": 0, "total_classic": 0, "total_target_groups": 0}
    }

    for account in accounts:
        name = account['name']
        account_id = account['account_id']
        profile = account['profile']

        logger.info(f"🔍 {name} ({account_id})")

        # Reuse session from --profile if already authenticated
        session = account.get("_session") or create_session(profile)
        if not session:
            inventory["accounts"][account_id] = {"name": name, "status": "auth_failed", "regions": {}}
            continue

        output_dir = get_output_dir(account_id, "elb")
        writer = IncrementalWriter(output_dir, make_output_filename("elb", account_id, timestamp))
        writer.update({"name": name, "profile_used": profile, "status": "in_progress", "regions": {}})

        totals = scan_elb(session, regions, writer)

        writer.set("total_alb_nlb", totals["alb_nlb"])
        writer.set("total_classic", totals["classic"])
        writer.set("total_target_groups", totals["target_groups"])
        writer.set("status", "ok")

        inventory["accounts"][account_id] = {"name": name, "status": "ok"}
        inventory["summary"]["total_alb_nlb"] += totals["alb_nlb"]
        inventory["summary"]["total_classic"] += totals["classic"]
        inventory["summary"]["total_target_groups"] += totals["target_groups"]

    total_lbs = inventory['summary']['total_alb_nlb'] + inventory['summary']['total_classic']
    logger.info("" + "=" * 60)
    logger.info("📊 SUMMARY")
    logger.info("=" * 60)
    logger.info(f"  Total ALB/NLB: {inventory['summary']['total_alb_nlb']}")
    logger.info(f"  Total Classic LB: {inventory['summary']['total_classic']}")
    logger.info(f"  Total Target Groups: {inventory['summary']['total_target_groups']}")
    logger.info(f"  Estimated LB cost: ~${total_lbs * 16:.0f}/mo (base hourly charges only)")


if __name__ == "__main__":
    run_with_timer(main)
