#!/usr/bin/env python3
"""
AWS Health Inventory Scanner
Lists recent/upcoming AWS Health events affecting the account — scheduled
maintenance, service degradations, and issues needing action.

NOT a resource inventory: AWS Health is an event feed. This captures open and
recent events so you can see what AWS says is (or will be) affecting you.

Requires AWS Business or Enterprise Support. On Basic/Developer support the
Health API returns SubscriptionRequiredException — handled gracefully (the
report records access=false rather than erroring).

The Health API is global and served only from us-east-1.

Usage:
    python get_health_inventory.py                     # All accounts
    python get_health_inventory.py -a "TQ Hosted"      # Single account
    python get_health_inventory.py -p <profile>
"""

import sys
import argparse
from pathlib import Path
from datetime import datetime, timezone, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, create_session,
    get_output_dir, get_timestamp, add_common_args,
    create_session_with_identity,
    run_with_timer, make_output_filename, IncrementalWriter,
)

SERVICE = "health"

# Health API only lives in us-east-1 (global service, single endpoint)
HEALTH_REGION = "us-east-1"


def scan_health(session, writer):
    """List Health events from the last 90 days + all upcoming. Returns totals."""
    client = session.client('health', region_name=HEALTH_REGION, config=BOTO_CONFIG)

    start = datetime.now(timezone.utc) - timedelta(days=90)
    events = []
    counts = {"open": 0, "upcoming": 0, "closed": 0, "issue": 0,
              "scheduledChange": 0, "accountNotification": 0}

    try:
        paginator = client.get_paginator('describe_events')
        # lastUpdatedTime>=start captures anything recently active; we keep
        # upcoming/open events regardless of category.
        page_iter = paginator.paginate(
            filter={'lastUpdatedTimes': [{'from': start}]}
        )
        for page in page_iter:
            for ev in page.get('events', []):
                status = ev.get('statusCode', '')
                category = ev.get('eventTypeCategory', '')
                events.append({
                    "arn": ev.get('arn', ''),
                    "service": ev.get('service', ''),
                    "event_type_code": ev.get('eventTypeCode', ''),
                    "category": category,
                    "region": ev.get('region', 'global'),
                    "status": status,
                    "start_time": ev.get('startTime', ''),
                    "end_time": ev.get('endTime', ''),
                    "last_updated": ev.get('lastUpdatedTime', ''),
                })
                if status in counts:
                    counts[status] += 1
                if category in counts:
                    counts[category] += 1

    except Exception as e:
        # Basic/Developer support tier — API not available on this account
        if "SubscriptionRequiredException" in str(e):
            logger.warning("  AWS Health API requires Business/Enterprise Support — skipping")
            writer.set("access", False)
            writer.set("reason", "SubscriptionRequiredException (needs Business/Enterprise Support)")
            return {"total_events": 0, "access": False}
        logger.warning(f"  Health API error — {e}")
        writer.set("access", False)
        writer.set("reason", str(e)[:200])
        return {"total_events": 0, "access": False}

    writer.set("access", True)
    writer.set_nested("events", "all", value=events)
    writer.set("event_counts", counts)

    logger.info(f"  {len(events)} events (open={counts['open']}, "
                f"upcoming={counts['upcoming']}, issues={counts['issue']}, "
                f"scheduled={counts['scheduledChange']})")

    return {"total_events": len(events), "access": True, **counts}


def main():
    parser = argparse.ArgumentParser(description='AWS Health Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    timestamp = get_timestamp()

    if args.profile:
        session, account_id, arn = create_session_with_identity(args.profile)
        if not session:
            sys.exit(1)
        accounts = [{"name": account_id, "account_id": account_id, "profile": args.profile, "_session": session}]

    logger.info(f"Scanning {len(accounts)} account(s) — AWS Health (global)")
    logger.info("=" * 60)

    for account in accounts:
        name = account['name']
        account_id = account['account_id']
        profile = account['profile']

        logger.info(f"🔍 {name} ({account_id})")

        session = account.get("_session") or create_session(profile)
        if not session:
            continue

        output_dir = get_output_dir(account_id, SERVICE)
        writer = IncrementalWriter(output_dir, make_output_filename(SERVICE, account_id, timestamp))
        writer.update({"name": name, "profile_used": profile, "status": "in_progress"})

        totals = scan_health(session, writer)

        writer.set("total_events", totals.get("total_events", 0))
        writer.set("status", "ok")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
