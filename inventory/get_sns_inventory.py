#!/usr/bin/env python3
"""
SNS Inventory Scanner
Scans SNS topics and subscriptions across all regions.

Usage:
    python get_sns_inventory.py -p <profile>
    python get_sns_inventory.py -p <profile> -r us-east-1
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

SERVICE = "sns"


def scan_region(session, region):
    """Scan SNS topics + subscriptions in one region. Returns (region_data, counts)."""
    counts = {"topics": 0, "subscriptions": 0}
    region_data = {"topics": []}
    try:
        sns = session.client('sns', region_name=region, config=BOTO_CONFIG)

        paginator = sns.get_paginator('list_topics')
        for page in paginator.paginate():
            for topic in page.get('Topics', []):
                topic_arn = topic['TopicArn']
                topic_name = topic_arn.split(':')[-1]

                try:
                    attrs = sns.get_topic_attributes(TopicArn=topic_arn).get('Attributes', {})
                except Exception:
                    attrs = {}

                subs = []
                try:
                    sub_paginator = sns.get_paginator('list_subscriptions_by_topic')
                    for sub_page in sub_paginator.paginate(TopicArn=topic_arn):
                        for sub in sub_page.get('Subscriptions', []):
                            subs.append({
                                "protocol": sub.get('Protocol', ''),
                                "endpoint": sub.get('Endpoint', ''),
                                "subscription_arn": sub.get('SubscriptionArn', ''),
                            })
                except Exception:
                    pass

                region_data["topics"].append({
                    "name": topic_name,
                    "arn": topic_arn,
                    "display_name": attrs.get('DisplayName', ''),
                    "subscriptions_confirmed": int(attrs.get('SubscriptionsConfirmed', 0)),
                    "subscriptions_pending": int(attrs.get('SubscriptionsPending', 0)),
                    "kms_key_id": attrs.get('KmsMasterKeyId', ''),
                    "fifo": attrs.get('FifoTopic', 'false') == 'true',
                    "subscriptions": subs,
                })
                counts["subscriptions"] += len(subs)

    except Exception as e:
        if is_region_unsupported_error(e):
            log_region_skip(region, SERVICE, str(e))
            return {}, counts
        logger.warning(f"  {region}: Error — {e}")
        return {}, counts

    counts["topics"] = len(region_data["topics"])
    if not region_data["topics"]:
        return {}, counts

    return region_data, counts


def scan_sns(session, regions, writer):
    """Scan SNS across all regions in parallel, writing incrementally per region."""
    return scan_regions_parallel(
        session, regions, writer, scan_region,
        log_fn=lambda region, c: logger.info(f"  {region}: {c['topics']} topic(s)") if c.get('topics', 0) > 0 else None,
    )


def main():
    parser = argparse.ArgumentParser(description='SNS Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    if args.profile:
        session, account_id, arn = create_session_with_identity(args.profile)
        if not session:
            sys.exit(1)
        accounts = [{"name": account_id, "account_id": account_id, "profile": args.profile, "_session": session}]
    else:
        accounts = get_accounts(args.account)

    regions = [args.region] if args.region else get_regions('sns')
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
        writer = IncrementalWriter(output_dir, make_output_filename(SERVICE, account_id, timestamp))
        writer.update({"name": name, "profile_used": profile, "status": "in_progress", "regions": {}})

        totals = scan_sns(session, regions, writer)
        writer.set("total_topics", totals.get("topics", 0))
        writer.set("total_subscriptions", totals.get("subscriptions", 0))
        writer.set("status", "ok")

        logger.info(f"  Total: {totals.get('topics', 0)} topics, {totals.get('subscriptions', 0)} subscriptions")

    logger.info("=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
