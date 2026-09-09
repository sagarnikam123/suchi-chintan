#!/usr/bin/env python3
"""
Amazon SQS Inventory Scanner
Scans all configured AWS accounts/regions for SQS queues.

Usage:
    python get_sqs_inventory.py
    python get_sqs_inventory.py -a "TQ Primary"
    python get_sqs_inventory.py -r us-east-1
"""

import sys
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, get_regions, create_session,
    get_output_dir, get_timestamp, add_common_args,
    create_session_with_identity, is_region_unsupported_error, log_region_skip,
    IncrementalWriter, make_output_filename,
    run_with_timer, scan_regions_parallel,
)

import argparse

SERVICE = "sqs"


import json


def _to_int(value, default=0):
    """Coerce an SQS attribute to int without letting a bad value abort the worker."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _queue_detail(get_client, url):
    """Fetch attributes and tags for one queue using a thread-local client.

    attributes_available=False marks a transient get_queue_attributes failure so
    downstream audits don't read the empty defaults as real config (e.g. flagging
    the queue as unencrypted / DLQ-less when the attributes call simply failed).
    """
    attributes_available = True
    client = get_client()
    try:
        attrs = client.get_queue_attributes(
            QueueUrl=url, AttributeNames=['All']
        ).get('Attributes', {})
    except Exception:
        attrs = {}
        attributes_available = False

    tags = {}
    try:
        tags_resp = client.list_queue_tags(QueueUrl=url)
        tags = tags_resp.get('Tags', {})
    except Exception:
        tags = {}

    redrive_policy_raw = attrs.get('RedrivePolicy', '')
    dead_letter_target_arn = None
    max_receive_count = None
    if redrive_policy_raw:
        try:
            redrive_data = json.loads(redrive_policy_raw)
            dead_letter_target_arn = redrive_data.get('deadLetterTargetArn')
            max_receive_count = redrive_data.get('maxReceiveCount')
        except Exception:
            pass

    q_name = url.rsplit('/', 1)[-1]
    kms_key = attrs.get('KmsMasterKeyId', '')

    return {
        "queue_url": url,
        "queue_name": q_name,
        "name": q_name,
        "attributes_available": attributes_available,
        "arn": attrs.get('QueueArn', 'N/A'),
        "type": "FIFO" if url.endswith('.fifo') else "Standard",
        "approximate_messages": _to_int(attrs.get('ApproximateNumberOfMessages', 0)),
        "approximate_messages_delayed": _to_int(attrs.get('ApproximateNumberOfMessagesDelayed', 0)),
        "approximate_messages_not_visible": _to_int(attrs.get('ApproximateNumberOfMessagesNotVisible', 0)),
        "visibility_timeout_sec": _to_int(attrs.get('VisibilityTimeout', 0)),
        "message_retention_sec": _to_int(attrs.get('MessageRetentionPeriod', 0)),
        "max_message_size_bytes": _to_int(attrs.get('MaximumMessageSize', 0)),
        "delay_seconds": _to_int(attrs.get('DelaySeconds', 0)),
        "created_timestamp": attrs.get('CreatedTimestamp', ''),
        "last_modified_timestamp": attrs.get('LastModifiedTimestamp', ''),
        "redrive_policy": redrive_policy_raw,
        "dead_letter_target_arn": dead_letter_target_arn,
        "max_receive_count": max_receive_count,
        "kms_key_id": kms_key,
        "kms_master_key_id": kms_key,
        "sqs_managed_sse_enabled": attrs.get('SqsManagedSseEnabled', '').lower() == 'true',
        "tags": tags,
    }


def scan_region(session, region):
    """Scan SQS queues in one region. Returns (queues, counts).

    Per-queue get_queue_attributes calls run in an inner thread pool — a
    single busy region (e.g. 800+ queues) was the whole run's bottleneck.
    """
    client = None
    try:
        client = session.client('sqs', region_name=region, config=BOTO_CONFIG)

        urls = []
        paginator = client.get_paginator('list_queues')
        for page in paginator.paginate():
            urls.extend(page.get('QueueUrls', []))

        if not urls:
            return [], {"queues": 0}

        # botocore clients are not thread-safe to share, so give each worker
        # thread its own client (reused across that thread's queues).
        local = threading.local()

        def get_client():
            if not hasattr(local, "sqs"):
                local.sqs = session.client('sqs', region_name=region, config=BOTO_CONFIG)
            return local.sqs

        # ponytail: inner pool at 10 — 34 regions x 10 caps total connections.
        queues = []
        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(_queue_detail, get_client, url) for url in urls]
            for fut in as_completed(futures):
                queues.append(fut.result())

    except Exception as e:
        if is_region_unsupported_error(e):
            log_region_skip(region, SERVICE, str(e))
        else:
            logger.warning(f"  {region}: Error — {e}")
        return [], {"queues": 0}
    finally:
        if client:
            try:
                client.close()
            except Exception:
                pass

    return queues, {"queues": len(queues)}


def scan_sqs(session, regions, writer):
    """Scan SQS queues across all regions in parallel. Returns total queue count."""
    totals = scan_regions_parallel(
        session, regions, writer, scan_region,
        log_fn=lambda region, c: logger.info(f"  {region}: {c['queues']} queues"),
    )
    return totals.get("queues", 0)


def main():
    parser = argparse.ArgumentParser(description='SQS Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('sqs')
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

        if account.get("enabled") is False:
            logger.info(f"⏭️  {name} ({account_id}) — skipped (disabled)")
            continue

        logger.info(f"🔍 {name} ({account_id}) — profile: {profile}")

        session = account.get("_session") or create_session(profile)
        if not session:
            continue

        output_dir = get_output_dir(account_id, SERVICE)
        writer = IncrementalWriter(output_dir, make_output_filename(SERVICE, account_id, timestamp))
        writer.update({"name": name, "profile_used": profile, "status": "in_progress"})

        total = scan_sqs(session, regions, writer)
        writer.set("total_queues", total)
        writer.set("status", "ok")

        logger.info(f"  Total: {total} queues")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
