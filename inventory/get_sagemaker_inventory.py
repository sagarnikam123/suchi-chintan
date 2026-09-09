#!/usr/bin/env python3
"""
Amazon SageMaker Inventory Scanner
Scans all configured AWS accounts/regions for SageMaker endpoints, notebooks, and training jobs.

Usage:
    python get_sagemaker_inventory.py
    python get_sagemaker_inventory.py -a "TQ Primary"
    python get_sagemaker_inventory.py -r us-east-1
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

SERVICE = "sagemaker"


def scan_sagemaker(session, regions, writer):
    """Scan SageMaker resources across all specified regions."""
    total_endpoints = 0
    total_notebooks = 0
    total_domains = 0

    for region in regions:
        try:
            client = session.client('sagemaker', region_name=region, config=BOTO_CONFIG)
            region_data = {"endpoints": [], "notebook_instances": [], "domains": []}

            # Endpoints (inference — expensive if left running)
            try:
                paginator = client.get_paginator('list_endpoints')
                for page in paginator.paginate():
                    for ep in page.get('Endpoints', []):
                        region_data["endpoints"].append({
                            "endpoint_name": ep.get('EndpointName', 'N/A'),
                            "endpoint_arn": ep.get('EndpointArn', 'N/A'),
                            "status": ep.get('EndpointStatus', 'N/A'),
                            "created_at": ep.get('CreationTime', ''),
                            "last_modified": ep.get('LastModifiedTime', ''),
                        })
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: Endpoints error — {e}")

            # Notebook instances
            try:
                paginator = client.get_paginator('list_notebook_instances')
                for page in paginator.paginate():
                    for nb in page.get('NotebookInstances', []):
                        region_data["notebook_instances"].append({
                            "name": nb.get('NotebookInstanceName', 'N/A'),
                            "arn": nb.get('NotebookInstanceArn', 'N/A'),
                            "status": nb.get('NotebookInstanceStatus', 'N/A'),
                            "instance_type": nb.get('InstanceType', 'N/A'),
                            "created_at": nb.get('CreationTime', ''),
                            "last_modified": nb.get('LastModifiedTime', ''),
                        })
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: Notebooks error — {e}")

            # Studio Domains
            try:
                resp = client.list_domains()
                for domain in resp.get('Domains', []):
                    region_data["domains"].append({
                        "domain_id": domain.get('DomainId', 'N/A'),
                        "domain_name": domain.get('DomainName', 'N/A'),
                        "status": domain.get('Status', 'N/A'),
                        "created_at": domain.get('CreationTime', ''),
                    })
            except Exception as e:
                logger.debug(f"  {region}: Domains — {e}")

            writer.set_nested("regions", region, value=region_data)
            total_endpoints += len(region_data["endpoints"])
            total_notebooks += len(region_data["notebook_instances"])
            total_domains += len(region_data["domains"])

            if any(region_data.values()):
                logger.info(f"  {region}: {len(region_data['endpoints'])} endpoints, "
                           f"{len(region_data['notebook_instances'])} notebooks, "
                           f"{len(region_data['domains'])} domains")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value={})

    return total_endpoints, total_notebooks, total_domains


def main():
    parser = argparse.ArgumentParser(description='SageMaker Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('sagemaker')
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

        endpoints, notebooks, domains = scan_sagemaker(session, regions, writer)
        writer.set("total_endpoints", endpoints)
        writer.set("total_notebook_instances", notebooks)
        writer.set("total_domains", domains)
        writer.set("status", "ok")

        logger.info(f"  Total: {endpoints} endpoints, {notebooks} notebooks, {domains} domains")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
