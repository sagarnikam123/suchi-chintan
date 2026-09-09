#!/usr/bin/env python3
"""
Amazon CloudFront Inventory Scanner
Scans all configured AWS accounts for CloudFront distributions.

Note: CloudFront is a global service — no region iteration needed.

Usage:
    python get_cloudfront_inventory.py
    python get_cloudfront_inventory.py -a "TQ Primary"
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, create_session,
    get_output_dir, get_timestamp, add_common_args,
    create_session_with_identity,
    IncrementalWriter, make_output_filename,
    run_with_timer,
)

import argparse

SERVICE = "cloudfront"


def scan_cloudfront(session, writer):
    """Scan CloudFront distributions (global service)."""
    client = session.client('cloudfront', config=BOTO_CONFIG)
    distributions = []

    paginator = client.get_paginator('list_distributions')
    for page in paginator.paginate():
        dist_list = page.get('DistributionList', {})
        for dist in dist_list.get('Items', []):
            origins = [o.get('DomainName', '') for o in dist.get('Origins', {}).get('Items', [])]
            aliases = dist.get('Aliases', {}).get('Items', [])

            distributions.append({
                "distribution_id": dist['Id'],
                "domain_name": dist.get('DomainName', 'N/A'),
                "status": dist.get('Status', 'N/A'),
                "enabled": dist.get('Enabled', False),
                "aliases": aliases,
                "origins": origins,
                "price_class": dist.get('PriceClass', 'N/A'),
                "http_version": dist.get('HttpVersion', 'N/A'),
                "ipv6_enabled": dist.get('IsIPV6Enabled', False),
                "web_acl_id": dist.get('WebACLId', ''),
                "comment": dist.get('Comment', ''),
                "last_modified": dist.get('LastModifiedTime', ''),
            })

    writer.set("distributions", distributions)
    return len(distributions)


def main():
    parser = argparse.ArgumentParser(description='CloudFront Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    timestamp = get_timestamp()

    if args.profile:
        session, account_id, arn = create_session_with_identity(args.profile)
        if not session:
            sys.exit(1)
        accounts = [{"name": account_id, "account_id": account_id, "profile": args.profile, "_session": session}]

    logger.info(f"Scanning {len(accounts)} account(s)")
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

        total = scan_cloudfront(session, writer)
        writer.set("total_distributions", total)
        writer.set("status", "ok")

        logger.info(f"  Total: {total} distributions")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
