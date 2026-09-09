#!/usr/bin/env python3
"""
Amazon MSK (Managed Streaming for Apache Kafka) Inventory Scanner
Scans all configured AWS accounts/regions for MSK clusters.

Usage:
    python get_msk_inventory.py
    python get_msk_inventory.py -a "TQ Primary"
    python get_msk_inventory.py -r us-east-1
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

SERVICE = "msk"


def scan_msk(session, regions, writer):
    """Scan MSK clusters across all specified regions."""
    total = 0

    for region in regions:
        try:
            client = session.client('kafka', region_name=region, config=BOTO_CONFIG)
            clusters = []

            paginator = client.get_paginator('list_clusters_v2')
            for page in paginator.paginate():
                for cluster in page.get('ClusterInfoList', []):
                    entry = {
                        "cluster_name": cluster.get('ClusterName', 'N/A'),
                        "cluster_arn": cluster.get('ClusterArn', 'N/A'),
                        "cluster_type": cluster.get('ClusterType', 'N/A'),
                        "state": cluster.get('State', 'N/A'),
                        "created_at": cluster.get('CreationTime', ''),
                    }

                    # Provisioned cluster details
                    provisioned = cluster.get('Provisioned', {})
                    if provisioned:
                        broker_info = provisioned.get('BrokerNodeGroupInfo', {})
                        entry.update({
                            "broker_instance_type": broker_info.get('InstanceType', 'N/A'),
                            "num_brokers": provisioned.get('NumberOfBrokerNodes', 0),
                            "storage_gb_per_broker": broker_info.get('StorageInfo', {}).get('EbsStorageInfo', {}).get('VolumeSize', 0),
                            "kafka_version": provisioned.get('CurrentBrokerSoftwareInfo', {}).get('KafkaVersion', 'N/A'),
                            "enhanced_monitoring": provisioned.get('EnhancedMonitoring', 'N/A'),
                        })

                    # Serverless cluster details
                    serverless = cluster.get('Serverless', {})
                    if serverless:
                        entry["serverless_vpc_configs"] = len(serverless.get('VpcConfigs', []))

                    clusters.append(entry)

            writer.set_nested("regions", region, value=clusters)
            total += len(clusters)

            if clusters:
                logger.info(f"  {region}: {len(clusters)} clusters")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value=[])

    return total


def main():
    parser = argparse.ArgumentParser(description='MSK Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('kafka')
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

        total = scan_msk(session, regions, writer)
        writer.set("total_clusters", total)
        writer.set("status", "ok")

        logger.info(f"  Total: {total} clusters")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
