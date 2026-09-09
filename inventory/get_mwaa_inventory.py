#!/usr/bin/env python3
"""
Amazon MWAA (Managed Workflows for Apache Airflow) Inventory Scanner
Scans all configured AWS accounts/regions for MWAA environments.

Usage:
    python get_mwaa_inventory.py
    python get_mwaa_inventory.py -a "TQ Primary"
    python get_mwaa_inventory.py -r us-east-1
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

SERVICE = "mwaa"


def scan_mwaa(session, regions, writer):
    """Scan MWAA environments across all specified regions."""
    total = 0

    for region in regions:
        try:
            client = session.client('mwaa', region_name=region, config=BOTO_CONFIG)
            environments = []

            resp = client.list_environments()
            for env_name in resp.get('Environments', []):
                try:
                    detail = client.get_environment(Name=env_name)['Environment']
                    environments.append({
                        "name": env_name,
                        "arn": detail.get('Arn', 'N/A'),
                        "status": detail.get('Status', 'N/A'),
                        "environment_class": detail.get('EnvironmentClass', 'N/A'),
                        "airflow_version": detail.get('AirflowVersion', 'N/A'),
                        "max_workers": detail.get('MaxWorkers', 0),
                        "min_workers": detail.get('MinWorkers', 0),
                        "schedulers": detail.get('Schedulers', 0),
                        "source_bucket_arn": detail.get('SourceBucketArn', 'N/A'),
                        "dag_s3_path": detail.get('DagS3Path', ''),
                        "webserver_access_mode": detail.get('WebserverAccessMode', 'N/A'),
                        "webserver_url": detail.get('WebserverUrl', ''),
                        "kms_key": detail.get('KmsKey', ''),
                        "created_at": detail.get('CreatedAt', ''),
                    })
                except Exception as e:
                    if is_region_unsupported_error(e):
                        raise  # opt-in region — outer handler skips it once
                    logger.warning(f"  {region}: Error describing {env_name} — {e}")
                    environments.append({"name": env_name, "status": "describe_failed"})

            writer.set_nested("regions", region, value=environments)
            total += len(environments)

            if environments:
                logger.info(f"  {region}: {len(environments)} environments")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value=[])

    return total


def main():
    parser = argparse.ArgumentParser(description='MWAA Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('mwaa')
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

        total = scan_mwaa(session, regions, writer)
        writer.set("total_environments", total)
        writer.set("status", "ok")

        logger.info(f"  Total: {total} environments")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
