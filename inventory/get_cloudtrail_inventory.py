#!/usr/bin/env python3
"""
AWS CloudTrail Inventory Scanner
Scans all configured AWS accounts/regions for CloudTrail trails and event data stores.

Usage:
    python get_cloudtrail_inventory.py
    python get_cloudtrail_inventory.py -a "TQ Primary"
    python get_cloudtrail_inventory.py -r us-east-1
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

SERVICE = "cloudtrail"


def scan_cloudtrail(session, regions, writer):
    """Scan CloudTrail trails and event data stores across all specified regions."""
    total_trails = 0
    total_event_stores = 0

    for region in regions:
        try:
            client = session.client('cloudtrail', region_name=region, config=BOTO_CONFIG)
            region_data = {"trails": [], "event_data_stores": []}

            # Trails
            try:
                resp = client.describe_trails(includeShadowTrails=False)
                for trail in resp.get('trailList', []):
                    # Only count trails homed in this region
                    if trail.get('HomeRegion', region) != region:
                        continue
                    status = {}
                    try:
                        status = client.get_trail_status(Name=trail['TrailARN'])
                    except Exception:
                        pass

                    region_data["trails"].append({
                        "name": trail.get('Name', 'N/A'),
                        "arn": trail.get('TrailARN', 'N/A'),
                        "is_multi_region": trail.get('IsMultiRegionTrail', False),
                        "is_organization_trail": trail.get('IsOrganizationTrail', False),
                        "s3_bucket": trail.get('S3BucketName', 'N/A'),
                        "log_file_validation": trail.get('LogFileValidationEnabled', False),
                        "cloudwatch_logs_arn": trail.get('CloudWatchLogsLogGroupArn', ''),
                        "kms_key_id": trail.get('KmsKeyId', ''),
                        "is_logging": status.get('IsLogging', False),
                        "latest_delivery_time": status.get('LatestDeliveryTime', ''),
                    })
            except Exception as e:
                if is_region_unsupported_error(e):
                    log_region_skip(region, SERVICE, str(e))
                    writer.set_nested("regions", region, value={})
                    continue
                logger.warning(f"  {region}: Trails error — {e}")

            # Event Data Stores (CloudTrail Lake)
            try:
                resp = client.list_event_data_stores()
                for eds in resp.get('EventDataStores', []):
                    region_data["event_data_stores"].append({
                        "name": eds.get('Name', 'N/A'),
                        "arn": eds.get('EventDataStoreArn', 'N/A'),
                        "status": eds.get('Status', 'N/A'),
                        "multi_region": eds.get('MultiRegionEnabled', False),
                        "organization_enabled": eds.get('OrganizationEnabled', False),
                        "retention_days": eds.get('RetentionPeriod', 0),
                        "created_at": eds.get('CreatedTimestamp', ''),
                    })
            except Exception as e:
                # Event data stores might not be available in all regions
                pass

            writer.set_nested("regions", region, value=region_data)
            total_trails += len(region_data["trails"])
            total_event_stores += len(region_data["event_data_stores"])

            if region_data["trails"] or region_data["event_data_stores"]:
                logger.info(f"  {region}: {len(region_data['trails'])} trails, "
                           f"{len(region_data['event_data_stores'])} event data stores")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value={})

    return total_trails, total_event_stores


def main():
    parser = argparse.ArgumentParser(description='CloudTrail Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('cloudtrail')
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

        trails, eds = scan_cloudtrail(session, regions, writer)
        writer.set("total_trails", trails)
        writer.set("total_event_data_stores", eds)
        writer.set("status", "ok")

        logger.info(f"  Total: {trails} trails, {eds} event data stores")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
