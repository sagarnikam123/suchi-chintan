#!/usr/bin/env python3
"""
WAF (Web Application Firewall) Inventory Scanner
Scans WAFv2 Web ACLs, rules, and associated resources.

Usage:
    python get_waf_inventory.py                     # All accounts, all regions
    python get_waf_inventory.py -a "TQ Hosted"      # Single account
    python get_waf_inventory.py -p <profile> -r us-east-1
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


def scan_waf(session, regions, writer):
    """Scan WAFv2 Web ACLs across regional and CloudFront (global) scopes."""
    total_web_acls = 0

    # Regional WAFs
    for region in regions:
        try:
            waf = session.client('wafv2', region_name=region, config=BOTO_CONFIG)
            resp = waf.list_web_acls(Scope='REGIONAL')
            web_acls = []

            for acl in resp.get('WebACLs', []):
                # Get detail
                try:
                    detail = waf.get_web_acl(Name=acl['Name'], Scope='REGIONAL', Id=acl['Id'])
                    web_acl = detail['WebACL']
                    rule_count = len(web_acl.get('Rules', []))
                except Exception:
                    rule_count = 0

                web_acls.append({
                    "name": acl['Name'],
                    "id": acl['Id'],
                    "scope": "REGIONAL",
                    "rule_count": rule_count,
                    "arn": acl.get('ARN', ''),
                })

            writer.set_nested("regions", region, value=web_acls)
            total_web_acls += len(web_acls)

            if web_acls:
                logger.info(f"  {region}: {len(web_acls)} Web ACLs")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, "waf", str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value=[])

    # CloudFront (global) WAFs — must query from us-east-1
    try:
        waf_global = session.client('wafv2', region_name='us-east-1', config=BOTO_CONFIG)
        resp = waf_global.list_web_acls(Scope='CLOUDFRONT')
        cf_acls = []

        for acl in resp.get('WebACLs', []):
            try:
                detail = waf_global.get_web_acl(Name=acl['Name'], Scope='CLOUDFRONT', Id=acl['Id'])
                rule_count = len(detail['WebACL'].get('Rules', []))
            except Exception:
                rule_count = 0

            cf_acls.append({
                "name": acl['Name'],
                "id": acl['Id'],
                "scope": "CLOUDFRONT",
                "rule_count": rule_count,
                "arn": acl.get('ARN', ''),
            })

        if cf_acls:
            logger.info(f"  CLOUDFRONT (global): {len(cf_acls)} Web ACLs")
            writer.set_nested("regions", "cloudfront-global", value=cf_acls)
            total_web_acls += len(cf_acls)

    except Exception as e:
        logger.warning(f"  CLOUDFRONT scope: Error — {e}")

    return total_web_acls


def main():
    parser = argparse.ArgumentParser(description='WAF Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('wafv2')
    timestamp = get_timestamp()

    if args.profile:
        session, account_id, arn = create_session_with_identity(args.profile)
        if not session:
            sys.exit(1)
        accounts = [{"name": account_id, "account_id": account_id, "profile": args.profile, "_session": session}]

    logger.info(f"Scanning {len(accounts)} account(s) across {len(regions)} region(s) + CloudFront global")
    logger.info("=" * 60)

    inventory = {
        "generated": timestamp,
        "accounts": {},
        "summary": {"total_web_acls": 0}
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

        output_dir = get_output_dir(account_id, "waf")
        writer = IncrementalWriter(output_dir, make_output_filename("waf", account_id, timestamp))
        writer.update({"name": name, "profile_used": profile, "status": "in_progress", "regions": {}})

        total = scan_waf(session, regions, writer)

        writer.set("total_web_acls", total)
        writer.set("status", "ok")

        inventory["accounts"][account_id] = {"name": name, "status": "ok"}
        inventory["summary"]["total_web_acls"] += total

    logger.info("" + "=" * 60)
    logger.info("📊 SUMMARY")
    logger.info("=" * 60)
    logger.info(f"  Total Web ACLs: {inventory['summary']['total_web_acls']} (💰 ~${inventory['summary']['total_web_acls'] * 5:.0f}/mo base)")


if __name__ == "__main__":
    run_with_timer(main)
