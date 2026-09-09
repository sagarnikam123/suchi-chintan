#!/usr/bin/env python3
"""
OpenSearch Service Inventory Scanner
Scans all configured AWS accounts/regions for OpenSearch/Elasticsearch domains.

Usage:
    python get_opensearch_inventory.py                     # All accounts
    python get_opensearch_inventory.py -a "TQ Hosted"      # Single account
    python get_opensearch_inventory.py -p <profile> -r us-east-1
"""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, get_regions, create_session,
    get_output_dir, get_timestamp, add_common_args,
    create_session_with_identity, is_region_unsupported_error, log_region_skip,
    run_with_timer, make_output_filename, IncrementalWriter,
)


def scan_opensearch_domains(session, regions, writer):
    """Scan OpenSearch domains across all specified regions."""
    total_domains = 0

    for region in regions:
        try:
            os_client = session.client('opensearch', region_name=region, config=BOTO_CONFIG)
            list_resp = os_client.list_domain_names()
            domain_names = [d['DomainName'] for d in list_resp.get('DomainNames', [])]

            domains = []
            if domain_names:
                # Get detailed info for each domain
                desc_resp = os_client.describe_domains(DomainNames=domain_names)
                for domain in desc_resp.get('DomainStatusList', []):
                    cluster_config = domain.get('ClusterConfig', {})
                    ebs_config = domain.get('EBSOptions', {})

                    domain_info = {
                        "name": domain['DomainName'],
                        "arn": domain.get('ARN', ''),
                        "engine_version": domain.get('EngineVersion', 'N/A'),
                        "status": "processing" if domain.get('Processing', False) else "active",
                        "endpoint": domain.get('Endpoint', domain.get('Endpoints', {}).get('vpc', 'N/A')),
                        "instance_type": cluster_config.get('InstanceType', 'N/A'),
                        "instance_count": cluster_config.get('InstanceCount', 0),
                        "dedicated_master": cluster_config.get('DedicatedMasterEnabled', False),
                        "master_type": cluster_config.get('DedicatedMasterType', 'N/A'),
                        "master_count": cluster_config.get('DedicatedMasterCount', 0),
                        "zone_awareness": cluster_config.get('ZoneAwarenessEnabled', False),
                        "ebs_enabled": ebs_config.get('EBSEnabled', False),
                        "ebs_volume_type": ebs_config.get('VolumeType', 'N/A'),
                        "ebs_volume_size_gb": ebs_config.get('VolumeSize', 0),
                        "ebs_iops": ebs_config.get('Iops', 0),
                        "vpc_id": domain.get('VPCOptions', {}).get('VPCId', 'N/A'),
                        "encryption_at_rest": domain.get('EncryptionAtRestOptions', {}).get('Enabled', False),
                        "node_to_node_encryption": domain.get('NodeToNodeEncryptionOptions', {}).get('Enabled', False),
                        "automated_snapshot_hour": domain.get('SnapshotOptions', {}).get('AutomatedSnapshotStartHour', 0),
                        "tags": domain.get('Tags', []),
                    }
                    domains.append(domain_info)

            writer.set_nested("regions", region, value=domains)
            total_domains += len(domains)

            if domains:
                for d in domains:
                    total_storage = d['ebs_volume_size_gb'] * d['instance_count']
                    logger.info(f"  {region}: {d['name']} — {d['engine_version']}, "
                                f"{d['instance_count']}x {d['instance_type']}, "
                                f"{total_storage} GB storage")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, 'opensearch', str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value=[])

    return total_domains


def main():
    parser = argparse.ArgumentParser(description='OpenSearch Service Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('opensearch')
    timestamp = get_timestamp()

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
        "summary": {"total_accounts_scanned": len(accounts), "total_domains": 0}
    }

    for account in accounts:
        name = account['name']
        account_id = account['account_id']
        profile = account['profile']

        logger.info(f"🔍 {name} ({account_id})")

        # Reuse session from --profile if already authenticated
        session = account.get("_session") or create_session(profile)
        if not session:
            inventory["accounts"][account_id] = {"name": name, "status": "auth_failed", "regions": {}}
            continue

        output_dir = get_output_dir(account_id, "opensearch")
        writer = IncrementalWriter(output_dir, make_output_filename("opensearch", account_id, timestamp))
        writer.update({"name": name, "profile_used": profile, "status": "in_progress", "regions": {}})

        total = scan_opensearch_domains(session, regions, writer)

        writer.set("total_domains", total)
        writer.set("status", "ok")

        inventory["accounts"][account_id] = {"name": name, "status": "ok"}
        inventory["summary"]["total_domains"] += total

    logger.info("" + "=" * 60)
    logger.info("📊 SUMMARY")
    logger.info("=" * 60)
    logger.info(f"  Total OpenSearch Domains: {inventory['summary']['total_domains']}")


if __name__ == "__main__":
    run_with_timer(main)
