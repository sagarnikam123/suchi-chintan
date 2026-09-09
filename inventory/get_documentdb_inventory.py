#!/usr/bin/env python3
"""
Amazon DocumentDB Inventory Scanner
Scans all configured AWS accounts/regions for DocumentDB clusters and instances.

Usage:
    python get_documentdb_inventory.py
    python get_documentdb_inventory.py -a "TQ Primary"
    python get_documentdb_inventory.py -r us-east-1
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

SERVICE = "documentdb"


def scan_documentdb(session, regions, writer):
    """Scan DocumentDB clusters and instances across all specified regions."""
    total_clusters = 0
    total_instances = 0

    for region in regions:
        try:
            # DocumentDB uses the same RDS client with engine filter
            client = session.client('docdb', region_name=region, config=BOTO_CONFIG)
            region_data = {"clusters": [], "instances": []}

            # Clusters
            try:
                paginator = client.get_paginator('describe_db_clusters')
                for page in paginator.paginate(Filters=[{'Name': 'engine', 'Values': ['docdb']}]):
                    for cluster in page.get('DBClusters', []):
                        region_data["clusters"].append({
                            "cluster_id": cluster['DBClusterIdentifier'],
                            "engine_version": cluster.get('EngineVersion', 'N/A'),
                            "status": cluster.get('Status', 'N/A'),
                            "endpoint": cluster.get('Endpoint', 'N/A'),
                            "reader_endpoint": cluster.get('ReaderEndpoint', 'N/A'),
                            "multi_az": cluster.get('MultiAZ', False),
                            "num_members": len(cluster.get('DBClusterMembers', [])),
                            "storage_encrypted": cluster.get('StorageEncrypted', False),
                            "backup_retention_days": cluster.get('BackupRetentionPeriod', 0),
                            "created_at": cluster.get('ClusterCreateTime', ''),
                        })
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: Error listing clusters — {e}")

            # Instances
            try:
                paginator = client.get_paginator('describe_db_instances')
                for page in paginator.paginate(Filters=[{'Name': 'engine', 'Values': ['docdb']}]):
                    for instance in page.get('DBInstances', []):
                        region_data["instances"].append({
                            "instance_id": instance['DBInstanceIdentifier'],
                            "instance_class": instance.get('DBInstanceClass', 'N/A'),
                            "status": instance.get('DBInstanceStatus', 'N/A'),
                            "engine_version": instance.get('EngineVersion', 'N/A'),
                            "cluster_id": instance.get('DBClusterIdentifier', 'N/A'),
                            "az": instance.get('AvailabilityZone', 'N/A'),
                            "endpoint": instance.get('Endpoint', {}).get('Address', 'N/A'),
                            "created_at": instance.get('InstanceCreateTime', ''),
                        })
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: Error listing instances — {e}")

            writer.set_nested("regions", region, value=region_data)
            total_clusters += len(region_data["clusters"])
            total_instances += len(region_data["instances"])

            if region_data["clusters"] or region_data["instances"]:
                logger.info(f"  {region}: {len(region_data['clusters'])} clusters, {len(region_data['instances'])} instances")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value={"clusters": [], "instances": []})

    return total_clusters, total_instances


def main():
    parser = argparse.ArgumentParser(description='DocumentDB Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('docdb')
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

        clusters, instances = scan_documentdb(session, regions, writer)
        writer.set("total_clusters", clusters)
        writer.set("total_instances", instances)
        writer.set("status", "ok")

        logger.info(f"  Total: {clusters} clusters, {instances} instances")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
