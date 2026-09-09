#!/usr/bin/env python3
"""
Amazon EMR Inventory Scanner
Scans all configured AWS accounts/regions for EMR clusters.

Usage:
    python get_emr_inventory.py
    python get_emr_inventory.py -a "TQ Primary"
    python get_emr_inventory.py -r us-east-1
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

SERVICE = "emr"


def scan_emr(session, regions, writer):
    """Scan EMR clusters across all specified regions."""
    total = 0

    for region in regions:
        try:
            client = session.client('emr', region_name=region, config=BOTO_CONFIG)
            clusters = []

            paginator = client.get_paginator('list_clusters')
            # Include all states to get full picture
            for page in paginator.paginate(ClusterStates=[
                'STARTING', 'BOOTSTRAPPING', 'RUNNING', 'WAITING', 'TERMINATING', 'TERMINATED', 'TERMINATED_WITH_ERRORS'
            ]):
                for cluster_summary in page.get('Clusters', []):
                    cluster_id = cluster_summary['Id']
                    state = cluster_summary['Status']['State']

                    # Skip terminated clusters for brevity
                    if state in ('TERMINATED', 'TERMINATED_WITH_ERRORS'):
                        continue

                    entry = {
                        "cluster_id": cluster_id,
                        "name": cluster_summary.get('Name', 'N/A'),
                        "state": state,
                        "normalized_instance_hours": cluster_summary.get('NormalizedInstanceHours', 0),
                    }

                    # Get details for active clusters
                    try:
                        detail = client.describe_cluster(ClusterId=cluster_id)['Cluster']
                        entry.update({
                            "release_label": detail.get('ReleaseLabel', 'N/A'),
                            "applications": [a['Name'] for a in detail.get('Applications', [])],
                            "instance_collection_type": detail.get('InstanceCollectionType', 'N/A'),
                            "log_uri": detail.get('LogUri', ''),
                            "auto_terminate": detail.get('AutoTerminate', False),
                            "termination_protected": detail.get('TerminationProtected', False),
                            "created_at": detail.get('Status', {}).get('Timeline', {}).get('CreationDateTime', ''),
                        })
                    except Exception:
                        pass

                    clusters.append(entry)

            writer.set_nested("regions", region, value=clusters)
            total += len(clusters)

            if clusters:
                logger.info(f"  {region}: {len(clusters)} active clusters")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value=[])

    return total


def main():
    parser = argparse.ArgumentParser(description='EMR Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('emr')
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

        total = scan_emr(session, regions, writer)
        writer.set("total_clusters", total)
        writer.set("status", "ok")

        logger.info(f"  Total: {total} active clusters")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
