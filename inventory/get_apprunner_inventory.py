#!/usr/bin/env python3
"""
AWS App Runner Inventory Scanner
Scans all configured AWS accounts/regions for App Runner services.

Usage:
    python get_apprunner_inventory.py
    python get_apprunner_inventory.py -a "TQ Primary"
    python get_apprunner_inventory.py -r us-east-1
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

SERVICE = "apprunner"


def scan_apprunner(session, regions, writer):
    """Scan App Runner services across all specified regions."""
    total = 0

    for region in regions:
        try:
            client = session.client('apprunner', region_name=region, config=BOTO_CONFIG)
            services = []

            resp = client.list_services()
            for svc_summary in resp.get('ServiceSummaryList', []):
                svc_arn = svc_summary.get('ServiceArn', '')
                entry = {
                    "service_name": svc_summary.get('ServiceName', 'N/A'),
                    "service_arn": svc_arn,
                    "service_id": svc_summary.get('ServiceId', 'N/A'),
                    "status": svc_summary.get('Status', 'N/A'),
                    "service_url": svc_summary.get('ServiceUrl', 'N/A'),
                    "created_at": svc_summary.get('CreatedAt', ''),
                    "updated_at": svc_summary.get('UpdatedAt', ''),
                }

                # Get details
                try:
                    detail = client.describe_service(ServiceArn=svc_arn)['Service']
                    source = detail.get('SourceConfiguration', {})
                    instance = detail.get('InstanceConfiguration', {})
                    entry.update({
                        "cpu": instance.get('Cpu', 'N/A'),
                        "memory": instance.get('Memory', 'N/A'),
                        "instance_role_arn": instance.get('InstanceRoleArn', ''),
                        "auto_deployments_enabled": source.get('AutoDeploymentsEnabled', False),
                    })

                    # Source type
                    if 'ImageRepository' in source:
                        entry["source_type"] = "IMAGE"
                        entry["image_uri"] = source['ImageRepository'].get('ImageIdentifier', 'N/A')
                    elif 'CodeRepository' in source:
                        entry["source_type"] = "CODE"
                        entry["repo_url"] = source['CodeRepository'].get('RepositoryUrl', 'N/A')
                except Exception:
                    pass

                services.append(entry)

            writer.set_nested("regions", region, value=services)
            total += len(services)

            if services:
                logger.info(f"  {region}: {len(services)} services")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value=[])

    return total


def main():
    parser = argparse.ArgumentParser(description='App Runner Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('apprunner')
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

        total = scan_apprunner(session, regions, writer)
        writer.set("total_services", total)
        writer.set("status", "ok")

        logger.info(f"  Total: {total} services")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
