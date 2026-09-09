#!/usr/bin/env python3
"""
AWS Glue Inventory Scanner
Scans all configured AWS accounts/regions for Glue jobs, crawlers, and databases.

Usage:
    python get_glue_inventory.py
    python get_glue_inventory.py -a "TQ Primary"
    python get_glue_inventory.py -r us-east-1
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

SERVICE = "glue"


def scan_glue(session, regions, writer):
    """Scan Glue jobs, crawlers, and databases across all specified regions."""
    total_jobs = 0
    total_crawlers = 0
    total_databases = 0

    for region in regions:
        try:
            client = session.client('glue', region_name=region, config=BOTO_CONFIG)
            region_data = {"jobs": [], "crawlers": [], "databases": []}

            # Jobs
            try:
                paginator = client.get_paginator('get_jobs')
                for page in paginator.paginate():
                    for job in page.get('Jobs', []):
                        region_data["jobs"].append({
                            "name": job['Name'],
                            "role": job.get('Role', 'N/A'),
                            "glue_version": job.get('GlueVersion', 'N/A'),
                            "worker_type": job.get('WorkerType', 'N/A'),
                            "num_workers": job.get('NumberOfWorkers', 0),
                            "max_capacity": job.get('MaxCapacity', 0),
                            "timeout_min": job.get('Timeout', 0),
                            "max_retries": job.get('MaxRetries', 0),
                            "last_modified": job.get('LastModifiedOn', ''),
                            "created_at": job.get('CreatedOn', ''),
                        })
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: Jobs error — {e}")

            # Crawlers
            try:
                paginator = client.get_paginator('get_crawlers')
                for page in paginator.paginate():
                    for crawler in page.get('Crawlers', []):
                        region_data["crawlers"].append({
                            "name": crawler['Name'],
                            "state": crawler.get('State', 'N/A'),
                            "database_name": crawler.get('DatabaseName', 'N/A'),
                            "schedule": crawler.get('Schedule', {}).get('ScheduleExpression', ''),
                            "last_crawl_status": crawler.get('LastCrawl', {}).get('Status', 'N/A'),
                            "last_crawl_time": crawler.get('LastCrawl', {}).get('StartTime', ''),
                            "created_at": crawler.get('CreationTime', ''),
                        })
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: Crawlers error — {e}")

            # Databases (Data Catalog)
            try:
                paginator = client.get_paginator('get_databases')
                for page in paginator.paginate():
                    for db in page.get('DatabaseList', []):
                        region_data["databases"].append({
                            "name": db['Name'],
                            "description": db.get('Description', ''),
                            "location_uri": db.get('LocationUri', ''),
                            "created_at": db.get('CreateTime', ''),
                        })
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: Databases error — {e}")

            writer.set_nested("regions", region, value=region_data)
            total_jobs += len(region_data["jobs"])
            total_crawlers += len(region_data["crawlers"])
            total_databases += len(region_data["databases"])

            if any(region_data.values()):
                logger.info(f"  {region}: {len(region_data['jobs'])} jobs, "
                           f"{len(region_data['crawlers'])} crawlers, {len(region_data['databases'])} databases")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value={})

    return total_jobs, total_crawlers, total_databases


def main():
    parser = argparse.ArgumentParser(description='Glue Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('glue')
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

        jobs, crawlers, databases = scan_glue(session, regions, writer)
        writer.set("total_jobs", jobs)
        writer.set("total_crawlers", crawlers)
        writer.set("total_databases", databases)
        writer.set("status", "ok")

        logger.info(f"  Total: {jobs} jobs, {crawlers} crawlers, {databases} databases")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
