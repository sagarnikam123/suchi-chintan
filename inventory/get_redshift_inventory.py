#!/usr/bin/env python3
"""
Amazon Redshift Inventory Scanner
Scans all configured AWS accounts/regions for Redshift clusters and serverless workgroups.

Usage:
    python get_redshift_inventory.py
    python get_redshift_inventory.py -a "TQ Primary"
    python get_redshift_inventory.py -r us-east-1
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

SERVICE = "redshift"


def scan_redshift(session, regions, writer):
    """Scan Redshift clusters and serverless workgroups across all specified regions."""
    total_clusters = 0
    total_serverless = 0

    for region in regions:
        try:
            region_data = {"clusters": [], "serverless_workgroups": []}

            # Provisioned clusters
            try:
                client = session.client('redshift', region_name=region, config=BOTO_CONFIG)
                paginator = client.get_paginator('describe_clusters')
                for page in paginator.paginate():
                    for cluster in page.get('Clusters', []):
                        region_data["clusters"].append({
                            "cluster_id": cluster['ClusterIdentifier'],
                            "status": cluster.get('ClusterStatus', 'N/A'),
                            "node_type": cluster.get('NodeType', 'N/A'),
                            "num_nodes": cluster.get('NumberOfNodes', 0),
                            "db_name": cluster.get('DBName', 'N/A'),
                            "endpoint": cluster.get('Endpoint', {}).get('Address', 'N/A'),
                            "port": cluster.get('Endpoint', {}).get('Port', 5439),
                            "vpc_id": cluster.get('VpcId', 'N/A'),
                            "encrypted": cluster.get('Encrypted', False),
                            "publicly_accessible": cluster.get('PubliclyAccessible', False),
                            "automated_snapshot_retention": cluster.get('AutomatedSnapshotRetentionPeriod', 0),
                            "created_at": cluster.get('ClusterCreateTime', ''),
                        })
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: Clusters error — {e}")

            # Serverless workgroups
            try:
                serverless = session.client('redshift-serverless', region_name=region, config=BOTO_CONFIG)
                resp = serverless.list_workgroups()
                for wg in resp.get('workgroups', []):
                    region_data["serverless_workgroups"].append({
                        "workgroup_name": wg.get('workgroupName', 'N/A'),
                        "workgroup_id": wg.get('workgroupId', 'N/A'),
                        "status": wg.get('status', 'N/A'),
                        "namespace_name": wg.get('namespaceName', 'N/A'),
                        "base_capacity": wg.get('baseCapacity', 0),
                        "endpoint": wg.get('endpoint', {}).get('address', 'N/A'),
                        "publicly_accessible": wg.get('publiclyAccessible', False),
                        "created_at": wg.get('creationDate', ''),
                    })
            except Exception as e:
                if 'UnrecognizedClientException' not in str(e):
                    logger.debug(f"  {region}: Serverless — {e}")

            writer.set_nested("regions", region, value=region_data)
            total_clusters += len(region_data["clusters"])
            total_serverless += len(region_data["serverless_workgroups"])

            if region_data["clusters"] or region_data["serverless_workgroups"]:
                logger.info(f"  {region}: {len(region_data['clusters'])} clusters, "
                           f"{len(region_data['serverless_workgroups'])} serverless")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value={"clusters": [], "serverless_workgroups": []})

    return total_clusters, total_serverless


def main():
    parser = argparse.ArgumentParser(description='Redshift Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('redshift')
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

        clusters, serverless = scan_redshift(session, regions, writer)
        writer.set("total_clusters", clusters)
        writer.set("total_serverless_workgroups", serverless)
        writer.set("status", "ok")

        logger.info(f"  Total: {clusters} clusters, {serverless} serverless workgroups")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
