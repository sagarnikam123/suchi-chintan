#!/usr/bin/env python3
"""
EKS Cluster Inventory Scanner
Scans all configured AWS accounts/regions and produces a JSON inventory.

Usage:
    python get_eks_inventory.py                    # All accounts, all regions
    python get_eks_inventory.py -a "TQ Primary"    # Single account
    python get_eks_inventory.py -r us-east-1       # Single region across all accounts
"""

import sys
import argparse
from pathlib import Path

# Add parent directory for common imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, get_regions, create_session,
    get_output_dir, get_timestamp, get_disabled_regions, add_common_args,
    create_session_with_identity, is_region_unsupported_error, log_region_skip,
    IncrementalWriter, make_output_filename,
    run_with_timer,
)


def scan_cluster_details(eks_client, cluster_name: str, include_nodegroups: bool = False):
    """Get detailed info for a single EKS cluster using a shared region client."""
    try:
        response = eks_client.describe_cluster(name=cluster_name)
        cluster = response['cluster']

        # Extract logging info
        logging_types = []
        for log_setup in cluster.get('logging', {}).get('clusterLogging', []):
            if log_setup.get('enabled'):
                logging_types.extend(log_setup.get('types', []))

        # Extract encryption config
        encryption_configs = cluster.get('encryptionConfig', [])
        has_secrets_encryption = any(
            'secrets' in ec.get('resources', []) for ec in encryption_configs
        )

        vpc_id = cluster.get('resourcesVpcConfig', {}).get('vpcId', '')

        result = {
            "name": cluster['name'],
            "version": cluster.get('version', 'unknown'),
            "status": cluster.get('status', 'unknown'),
            "arn": cluster.get('arn', ''),
            "created_at": str(cluster.get('createdAt', '')),
            "platform_version": cluster.get('platformVersion', ''),
            "role_arn": cluster.get('roleArn', ''),
            "vpc_id": vpc_id,
            "vpc_config": {
                "vpc_id": vpc_id,
                "subnet_ids": cluster.get('resourcesVpcConfig', {}).get('subnetIds', []),
                "security_group_ids": cluster.get('resourcesVpcConfig', {}).get('securityGroupIds', []),
                "cluster_security_group_id": cluster.get('resourcesVpcConfig', {}).get('clusterSecurityGroupId', ''),
                "endpoint_public": cluster.get('resourcesVpcConfig', {}).get('endpointPublicAccess', False),
                "endpoint_private": cluster.get('resourcesVpcConfig', {}).get('endpointPrivateAccess', False),
                "public_access_cidrs": cluster.get('resourcesVpcConfig', {}).get('publicAccessCidrs', []),
            },
            "logging": {
                "enabled_types": logging_types,
                "all_enabled": set(logging_types) >= {"api", "audit", "authenticator", "controllerManager", "scheduler"},
            },
            "encryption": {
                "has_secrets_encryption": has_secrets_encryption,
                "configs": encryption_configs,
            },
            "kubernetes_network_config": {
                "service_ipv4_cidr": cluster.get('kubernetesNetworkConfig', {}).get('serviceIpv4Cidr', ''),
                "ip_family": cluster.get('kubernetesNetworkConfig', {}).get('ipFamily', ''),
            },
            "tags": cluster.get('tags', {}),
        }

        if include_nodegroups:
            try:
                ng_resp = eks_client.list_nodegroups(clusterName=cluster_name)
                result["nodegroups"] = ng_resp.get('nodegroups', [])
            except Exception:
                result["nodegroups"] = []

            try:
                addon_resp = eks_client.list_addons(clusterName=cluster_name)
                result["addons"] = addon_resp.get('addons', [])
            except Exception:
                result["addons"] = []

        return result

    except Exception as e:
        logger.warning(f"  Could not describe cluster {cluster_name}: {e}")
        return {"name": cluster_name, "version": "unknown", "vpc_id": "", "error": str(e)}


def main():
    parser = argparse.ArgumentParser(description='EKS Cluster Inventory Scanner')
    add_common_args(parser)
    parser.add_argument('--details', '-d', action='store_true',
                        help='Include deep cluster details (nodegroups, addons, logging, encryption, tags).')
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    # If --profile is used, bypass accounts.yaml entirely
    if args.profile:
        session, account_id, arn = create_session_with_identity(args.profile)
        if not session:
            sys.exit(1)
        accounts = [{"name": account_id, "account_id": account_id, "profile": args.profile, "_session": session}]

    regions = [args.region] if args.region else get_regions('eks')
    timestamp = get_timestamp()

    logger.info(f"Scanning {len(accounts)} account(s) across {len(regions)} region(s)")
    logger.info("=" * 60)

    summary_data = {
        "total_accounts_scanned": len(accounts),
        "accounts_with_clusters": 0,
        "total_eks_clusters_found": 0,
        "clusters_by_account": {},
        "accounts": {},
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
            summary_data["accounts"][account_id] = {"name": name, "clusters": 0, "status": "auth_failed"}
            summary_data["clusters_by_account"][account_id] = 0
            logger.warning(f"  ⚠️  {account_id}: authentication failed — skipping")
            continue

        # Per-account incremental writer
        account_output = get_output_dir(account_id, "eks")
        account_writer = IncrementalWriter(account_output, make_output_filename("eks", account_id, timestamp))
        account_writer.update({
            "name": name, "profile_used": profile, "status": "ok",
            "total_clusters": 0, "regions": {}
        })

        disabled = get_disabled_regions(session)
        total = 0

        for region in regions:
            if region in disabled:
                account_writer.set_nested("regions", region, value=[])
                continue

            eks_client = None
            try:
                # One client per region — reused for list + per-cluster describe.
                eks_client = session.client('eks', region_name=region, config=BOTO_CONFIG)

                # Paginate list_clusters
                paginator = eks_client.get_paginator('list_clusters')
                clusters = []
                for page in paginator.paginate():
                    clusters.extend(page.get('clusters', []))

                if clusters:
                    logger.info(f"  {region}: {len(clusters)} cluster(s)")

                if args.details and clusters:
                    detailed = [scan_cluster_details(eks_client, c, include_nodegroups=True) for c in clusters]
                    account_writer.set_nested("regions", region, value=detailed)
                else:
                    # Scan standard details (version, vpc_id, status, endpoint)
                    enriched = []
                    for c in clusters:
                        enriched.append(scan_cluster_details(eks_client, c, include_nodegroups=False))
                    account_writer.set_nested("regions", region, value=enriched)

                total += len(clusters)
                account_writer.set("total_clusters", total)

            except Exception as e:
                if is_region_unsupported_error(e):
                    log_region_skip(region, 'eks', str(e))
                else:
                    logger.warning(f"  {region}: Error — {e}")
                account_writer.set_nested("regions", region, value=[])
            finally:
                if eks_client:
                    try:
                        eks_client.close()
                    except Exception:
                        pass

        # Update summary totals
        summary_data["accounts"][account_id] = {"name": name, "clusters": total}
        summary_data["clusters_by_account"][account_id] = total
        summary_data["total_eks_clusters_found"] += total
        if total > 0:
            summary_data["accounts_with_clusters"] += 1

        logger.info(f"  📄 Flushed: {account_id} ({total} cluster(s))")

    # Print summary
    logger.info("" + "=" * 60)
    logger.info("📊 SUMMARY")
    logger.info("=" * 60)
    for acct_id, count in summary_data["clusters_by_account"].items():
        acct_name = summary_data["accounts"][acct_id].get("name", acct_id)
        logger.info(f"  {acct_name} ({acct_id}): {count} cluster(s)")
    logger.info(f"  TOTAL: {summary_data['total_eks_clusters_found']} cluster(s)")


if __name__ == "__main__":
    run_with_timer(main)
