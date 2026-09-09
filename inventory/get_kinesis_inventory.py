#!/usr/bin/env python3
"""
Amazon Kinesis Inventory Scanner
Scans all configured AWS accounts/regions for Kinesis Data Streams and Firehose delivery streams.

Usage:
    python get_kinesis_inventory.py
    python get_kinesis_inventory.py -a "TQ Primary"
    python get_kinesis_inventory.py -r us-east-1
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

SERVICE = "kinesis"


def scan_kinesis(session, regions, writer):
    """Scan Kinesis Data Streams and Firehose across all specified regions."""
    total_streams = 0
    total_firehose = 0

    for region in regions:
        try:
            region_data = {"data_streams": [], "firehose_streams": []}

            # Kinesis Data Streams
            try:
                client = session.client('kinesis', region_name=region, config=BOTO_CONFIG)
                paginator = client.get_paginator('list_streams')
                for page in paginator.paginate():
                    for summary in page.get('StreamSummaries', []):
                        region_data["data_streams"].append({
                            "stream_name": summary.get('StreamName', 'N/A'),
                            "stream_arn": summary.get('StreamARN', 'N/A'),
                            "status": summary.get('StreamStatus', 'N/A'),
                            "mode": summary.get('StreamModeDetails', {}).get('StreamMode', 'PROVISIONED'),
                            "created_at": summary.get('StreamCreationTimestamp', ''),
                        })
            except Exception as e:
                if is_region_unsupported_error(e):
                    log_region_skip(region, SERVICE, str(e))
                    writer.set_nested("regions", region, value=region_data)
                    continue
                logger.warning(f"  {region}: Data Streams error — {e}")

            # Firehose Delivery Streams
            try:
                firehose = session.client('firehose', region_name=region, config=BOTO_CONFIG)
                resp = firehose.list_delivery_streams()
                for stream_name in resp.get('DeliveryStreamNames', []):
                    try:
                        desc = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)
                        ds = desc.get('DeliveryStreamDescription', {})
                        region_data["firehose_streams"].append({
                            "stream_name": stream_name,
                            "stream_arn": ds.get('DeliveryStreamARN', 'N/A'),
                            "status": ds.get('DeliveryStreamStatus', 'N/A'),
                            "stream_type": ds.get('DeliveryStreamType', 'N/A'),
                            "source": ds.get('Source', {}).get('KinesisStreamSourceDescription', {}).get('KinesisStreamARN', 'DirectPut'),
                            "created_at": ds.get('CreateTimestamp', ''),
                        })
                    except Exception:
                        region_data["firehose_streams"].append({"stream_name": stream_name, "status": "describe_failed"})
            except Exception as e:
                if not is_region_unsupported_error(e):
                    logger.warning(f"  {region}: Firehose error — {e}")

            writer.set_nested("regions", region, value=region_data)
            total_streams += len(region_data["data_streams"])
            total_firehose += len(region_data["firehose_streams"])

            if region_data["data_streams"] or region_data["firehose_streams"]:
                logger.info(f"  {region}: {len(region_data['data_streams'])} streams, {len(region_data['firehose_streams'])} firehose")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value={"data_streams": [], "firehose_streams": []})

    return total_streams, total_firehose


def main():
    parser = argparse.ArgumentParser(description='Kinesis Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('kinesis')
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

        streams, firehose = scan_kinesis(session, regions, writer)
        writer.set("total_data_streams", streams)
        writer.set("total_firehose_streams", firehose)
        writer.set("status", "ok")

        logger.info(f"  Total: {streams} data streams, {firehose} firehose")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
