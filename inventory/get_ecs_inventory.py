#!/usr/bin/env python3
"""
Amazon ECS Inventory Scanner
Scans all configured AWS accounts/regions for ECS clusters, services, and task definitions.

Usage:
    python get_ecs_inventory.py
    python get_ecs_inventory.py -a "TQ Primary"
    python get_ecs_inventory.py -r us-east-1
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

SERVICE = "ecs"


def scan_ecs(session, regions, writer):
    """Scan ECS clusters and services across all specified regions."""
    total_clusters = 0
    total_services = 0

    for region in regions:
        try:
            client = session.client('ecs', region_name=region, config=BOTO_CONFIG)
            clusters_data = []

            # List clusters
            cluster_arns = []
            paginator = client.get_paginator('list_clusters')
            for page in paginator.paginate():
                cluster_arns.extend(page.get('clusterArns', []))

            if not cluster_arns:
                writer.set_nested("regions", region, value=[])
                continue

            # Describe clusters in batches of 100
            for i in range(0, len(cluster_arns), 100):
                batch = cluster_arns[i:i+100]
                desc = client.describe_clusters(
                    clusters=batch,
                    include=['STATISTICS', 'SETTINGS']
                )

                for cluster in desc.get('clusters', []):
                    cluster_name = cluster['clusterName']
                    cluster_entry = {
                        "cluster_name": cluster_name,
                        "cluster_arn": cluster['clusterArn'],
                        "status": cluster.get('status', 'N/A'),
                        "running_tasks": cluster.get('runningTasksCount', 0),
                        "pending_tasks": cluster.get('pendingTasksCount', 0),
                        "active_services": cluster.get('activeServicesCount', 0),
                        "registered_instances": cluster.get('registeredContainerInstancesCount', 0),
                        "capacity_providers": cluster.get('capacityProviders', []),
                        "services": [],
                    }

                    # List services for this cluster
                    try:
                        svc_arns = []
                        svc_paginator = client.get_paginator('list_services')
                        for svc_page in svc_paginator.paginate(cluster=cluster_name):
                            svc_arns.extend(svc_page.get('serviceArns', []))

                        # Describe services in batches of 10
                        for j in range(0, len(svc_arns), 10):
                            svc_batch = svc_arns[j:j+10]
                            svc_desc = client.describe_services(cluster=cluster_name, services=svc_batch)
                            for svc in svc_desc.get('services', []):
                                cluster_entry["services"].append({
                                    "service_name": svc.get('serviceName', 'N/A'),
                                    "status": svc.get('status', 'N/A'),
                                    "desired_count": svc.get('desiredCount', 0),
                                    "running_count": svc.get('runningCount', 0),
                                    "launch_type": svc.get('launchType', 'N/A'),
                                    "task_definition": svc.get('taskDefinition', 'N/A'),
                                    "deployment_controller": svc.get('deploymentController', {}).get('type', 'N/A'),
                                })
                                total_services += 1
                    except Exception as e:
                        if is_region_unsupported_error(e):
                            raise  # opt-in region — outer handler skips it once
                        logger.warning(f"  {region}: Error listing services for {cluster_name} — {e}")

                    clusters_data.append(cluster_entry)

            writer.set_nested("regions", region, value=clusters_data)
            total_clusters += len(clusters_data)

            if clusters_data:
                logger.info(f"  {region}: {len(clusters_data)} clusters, {total_services} services")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value=[])

    return total_clusters, total_services


def main():
    parser = argparse.ArgumentParser(description='ECS Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('ecs')
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

        clusters, services = scan_ecs(session, regions, writer)
        writer.set("total_clusters", clusters)
        writer.set("total_services", services)
        writer.set("status", "ok")

        logger.info(f"  Total: {clusters} clusters, {services} services")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
