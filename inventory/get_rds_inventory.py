#!/usr/bin/env python3
"""
RDS Inventory Scanner
Scans all configured AWS accounts/regions for RDS clusters and instances.

Usage:
    python get_rds_inventory.py                     # All accounts, all regions
    python get_rds_inventory.py -a "TQ OPS"         # Single account
    python get_rds_inventory.py -r us-east-1        # Single region
"""

import sys
import argparse
from pathlib import Path

# Add parent directory for common imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, get_regions, create_session,
    get_output_dir, get_timestamp, add_common_args,
    create_session_with_identity, is_region_unsupported_error, log_region_skip,
    run_with_timer, make_output_filename, IncrementalWriter,
)


def _extract_tags(tag_list) -> dict:
    """Convert RDS TagList to a key-value dictionary."""
    if not tag_list or not isinstance(tag_list, list):
        return {}
    return {t.get("Key", ""): t.get("Value", "") for t in tag_list if t.get("Key")}


def _extract_vpc_id(subnet_group) -> str:
    """Safely extract VpcId from DBSubnetGroup (can be dict, str, or None)."""
    if isinstance(subnet_group, dict):
        return subnet_group.get("VpcId", "")
    return ""


def scan_rds(session, regions, writer):
    """Scan RDS clusters and instances across all specified regions."""
    total_clusters = 0
    total_instances = 0

    for region in regions:
        rds_client = None
        try:
            rds_client = session.client('rds', region_name=region, config=BOTO_CONFIG)

            # Get clusters (paginated)
            clusters = []
            try:
                cluster_paginator = rds_client.get_paginator('describe_db_clusters')
                for page in cluster_paginator.paginate():
                    for cluster in page.get('DBClusters', []):
                        vpc_id = _extract_vpc_id(cluster.get('DBSubnetGroup'))
                        sg_ids = [sg.get('VpcSecurityGroupId') for sg in cluster.get('VpcSecurityGroups', []) if sg.get('VpcSecurityGroupId')]
                        clusters.append({
                            "identifier": cluster.get('DBClusterIdentifier', 'N/A'),
                            "engine": cluster.get('Engine', 'N/A'),
                            "engine_version": cluster.get('EngineVersion', 'N/A'),
                            "status": cluster.get('Status', 'N/A'),
                            "endpoint": cluster.get('Endpoint', 'N/A'),
                            "reader_endpoint": cluster.get('ReaderEndpoint', ''),
                            "multi_az": cluster.get('MultiAZ', False),
                            "publicly_accessible": cluster.get('PubliclyAccessible', False),
                            "storage_encrypted": cluster.get('StorageEncrypted', False),
                            "kms_key_id": cluster.get('KmsKeyId', ''),
                            "deletion_protection": cluster.get('DeletionProtection', False),
                            "backup_retention_days": cluster.get('BackupRetentionPeriod', 0),
                            "vpc_id": vpc_id,
                            "security_group_ids": sg_ids,
                            "iops": cluster.get('Iops', 0),
                            "allocated_storage": cluster.get('AllocatedStorage', 0),
                            "tags": _extract_tags(cluster.get('TagList', [])),
                            "created_at": str(cluster.get('ClusterCreateTime', '')) if cluster.get('ClusterCreateTime') else '',
                        })
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: Error listing clusters — {e}")

            # Get instances (paginated)
            instances = []
            try:
                instance_paginator = rds_client.get_paginator('describe_db_instances')
                for page in instance_paginator.paginate():
                    for instance in page.get('DBInstances', []):
                        vpc_id = _extract_vpc_id(instance.get('DBSubnetGroup'))
                        sg_ids = [sg.get('VpcSecurityGroupId') for sg in instance.get('VpcSecurityGroups', []) if sg.get('VpcSecurityGroupId')]
                        instances.append({
                            "identifier": instance.get('DBInstanceIdentifier', 'N/A'),
                            "engine": instance.get('Engine', 'N/A'),
                            "engine_version": instance.get('EngineVersion', 'N/A'),
                            "status": instance.get('DBInstanceStatus', 'N/A'),
                            "instance_class": instance.get('DBInstanceClass', 'N/A'),
                            "endpoint": instance.get('Endpoint', {}).get('Address', 'N/A'),
                            "port": instance.get('Endpoint', {}).get('Port', 0),
                            "db_cluster_identifier": instance.get('DBClusterIdentifier', ''),
                            "multi_az": instance.get('MultiAZ', False),
                            "publicly_accessible": instance.get('PubliclyAccessible', False),
                            "storage_type": instance.get('StorageType', 'gp2'),
                            "storage_gb": instance.get('AllocatedStorage', 0),
                            "max_allocated_storage": instance.get('MaxAllocatedStorage', 0),
                            "iops": instance.get('Iops', 0),
                            "storage_encrypted": instance.get('StorageEncrypted', False),
                            "kms_key_id": instance.get('KmsKeyId', ''),
                            "deletion_protection": instance.get('DeletionProtection', False),
                            "auto_minor_version_upgrade": instance.get('AutoMinorVersionUpgrade', False),
                            "backup_retention_days": instance.get('BackupRetentionPeriod', 0),
                            "ca_certificate_identifier": instance.get('CACertificateIdentifier', ''),
                            "enhanced_monitoring_interval": instance.get('MonitoringInterval', 0),
                            "performance_insights_enabled": instance.get('PerformanceInsightsEnabled', False),
                            "vpc_id": vpc_id,
                            "security_group_ids": sg_ids,
                            "tags": _extract_tags(instance.get('TagList', [])),
                            "created_at": str(instance.get('InstanceCreateTime', '')) if instance.get('InstanceCreateTime') else '',
                        })
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: Error listing instances — {e}")

            writer.set_nested("regions", region, value={"clusters": clusters, "instances": instances})
            total_clusters += len(clusters)
            total_instances += len(instances)

            if clusters or instances:
                logger.info(f"  {region}: {len(clusters)} clusters, {len(instances)} instances")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, 'rds', str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value={"clusters": [], "instances": []})
        finally:
            if rds_client:
                try:
                    rds_client.close()
                except Exception:
                    pass

    return total_clusters, total_instances


def main():
    parser = argparse.ArgumentParser(description='RDS Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('rds')
    timestamp = get_timestamp()

    # If --profile is used, bypass accounts.yaml entirely
    if args.profile:
        session, account_id, arn = create_session_with_identity(args.profile)
        if not session:
            sys.exit(1)
        accounts = [{"name": account_id, "account_id": account_id, "profile": args.profile, "_session": session}]

    logger.info(f"Scanning {len(accounts)} account(s) across {len(regions)} region(s)")
    logger.info("=" * 60)

    inventory = {
        "generated": timestamp,
        "accounts": {},
        "summary": {
            "total_accounts_scanned": len(accounts),
            "total_clusters": 0,
            "total_instances": 0,
        }
    }

    for account in accounts:
        name = account['name']
        account_id = account['account_id']
        profile = account['profile']

        if account.get('enabled') is False:
            logger.info(f"⏭️  {name} ({account_id}) — skipped (disabled)")
            continue

        logger.info(f"🔍 {name} ({account_id}) — profile: {profile}")

        # Reuse session from --profile if already authenticated
        session = account.get("_session") or create_session(profile)
        if not session:
            inventory["accounts"][account_id] = {
                "name": name, "status": "auth_failed", "regions": {}
            }
            continue

        output_dir = get_output_dir(account_id, "rds")
        writer = IncrementalWriter(output_dir, make_output_filename("rds", account_id, timestamp))
        writer.update({"name": name, "profile_used": profile, "status": "in_progress", "regions": {}})

        clusters, instances = scan_rds(session, regions, writer)
        writer.set("total_clusters", clusters)
        writer.set("total_instances", instances)
        writer.set("status", "ok")

        inventory["accounts"][account_id] = writer.get_data()
        inventory["summary"]["total_clusters"] += clusters
        inventory["summary"]["total_instances"] += instances

    # Summary
    logger.info("" + "=" * 60)
    logger.info("📊 SUMMARY")
    logger.info("=" * 60)
    logger.info(f"  Total RDS Clusters: {inventory['summary']['total_clusters']}")
    logger.info(f"  Total RDS Instances: {inventory['summary']['total_instances']}")


if __name__ == "__main__":
    run_with_timer(main)
