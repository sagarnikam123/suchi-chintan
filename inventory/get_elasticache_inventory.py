#!/usr/bin/env python3
"""
Amazon ElastiCache Inventory Scanner
Scans all configured AWS accounts/regions for ElastiCache clusters and replication groups.

Usage:
    python get_elasticache_inventory.py
    python get_elasticache_inventory.py -a "TQ Primary"
    python get_elasticache_inventory.py -r us-east-1
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

SERVICE = "elasticache"


def scan_elasticache(session, regions, writer):
    """Scan ElastiCache clusters and replication groups across all specified regions."""
    total_clusters = 0
    total_replication_groups = 0

    for region in regions:
        try:
            client = session.client('elasticache', region_name=region, config=BOTO_CONFIG)
            region_data = {"clusters": [], "replication_groups": []}

            # Cache clusters
            paginator = client.get_paginator('describe_cache_clusters')
            for page in paginator.paginate(ShowCacheNodeInfo=True):
                for cluster in page.get('CacheClusters', []):
                    region_data["clusters"].append({
                        "cluster_id": cluster['CacheClusterId'],
                        "engine": cluster.get('Engine', 'N/A'),
                        "engine_version": cluster.get('EngineVersion', 'N/A'),
                        "node_type": cluster.get('CacheNodeType', 'N/A'),
                        "num_nodes": cluster.get('NumCacheNodes', 0),
                        "status": cluster.get('CacheClusterStatus', 'N/A'),
                        "az": cluster.get('PreferredAvailabilityZone', 'N/A'),
                        "replication_group_id": cluster.get('ReplicationGroupId', ''),
                        "created_at": cluster.get('CacheClusterCreateTime', ''),
                    })

            # Replication groups (Redis/Valkey)
            try:
                rg_paginator = client.get_paginator('describe_replication_groups')
                for page in rg_paginator.paginate():
                    for rg in page.get('ReplicationGroups', []):
                        region_data["replication_groups"].append({
                            "replication_group_id": rg['ReplicationGroupId'],
                            "description": rg.get('Description', ''),
                            "status": rg.get('Status', 'N/A'),
                            "member_clusters": rg.get('MemberClusters', []),
                            "num_node_groups": len(rg.get('NodeGroups', [])),
                            "automatic_failover": rg.get('AutomaticFailover', 'N/A'),
                            "multi_az": rg.get('MultiAZ', 'N/A'),
                            "cluster_mode": rg.get('ClusterEnabled', False),
                        })
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: Error listing replication groups — {e}")

            writer.set_nested("regions", region, value=region_data)
            total_clusters += len(region_data["clusters"])
            total_replication_groups += len(region_data["replication_groups"])

            if region_data["clusters"] or region_data["replication_groups"]:
                logger.info(f"  {region}: {len(region_data['clusters'])} clusters, {len(region_data['replication_groups'])} replication groups")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value={"clusters": [], "replication_groups": []})

    return total_clusters, total_replication_groups


def main():
    parser = argparse.ArgumentParser(description='ElastiCache Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('elasticache')
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

        clusters, rgs = scan_elasticache(session, regions, writer)
        writer.set("total_clusters", clusters)
        writer.set("total_replication_groups", rgs)
        writer.set("status", "ok")

        logger.info(f"  Total: {clusters} clusters, {rgs} replication groups")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
