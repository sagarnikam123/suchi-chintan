#!/usr/bin/env python3
"""
AWS Database Migration Service (DMS) Inventory Scanner
Scans all configured AWS accounts/regions for DMS replication instances and tasks.

Usage:
    python get_dms_inventory.py
    python get_dms_inventory.py -a "TQ Primary"
    python get_dms_inventory.py -r us-east-1
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

SERVICE = "dms"


def scan_dms(session, regions, writer):
    """Scan DMS replication instances and tasks across all specified regions."""
    total_instances = 0
    total_tasks = 0

    for region in regions:
        try:
            client = session.client('dms', region_name=region, config=BOTO_CONFIG)
            region_data = {"replication_instances": [], "replication_tasks": []}

            # Replication instances
            try:
                paginator = client.get_paginator('describe_replication_instances')
                for page in paginator.paginate():
                    for ri in page.get('ReplicationInstances', []):
                        region_data["replication_instances"].append({
                            "identifier": ri.get('ReplicationInstanceIdentifier', 'N/A'),
                            "arn": ri.get('ReplicationInstanceArn', 'N/A'),
                            "instance_class": ri.get('ReplicationInstanceClass', 'N/A'),
                            "status": ri.get('ReplicationInstanceStatus', 'N/A'),
                            "engine_version": ri.get('EngineVersion', 'N/A'),
                            "multi_az": ri.get('MultiAZ', False),
                            "allocated_storage_gb": ri.get('AllocatedStorage', 0),
                            "publicly_accessible": ri.get('PubliclyAccessible', False),
                            "az": ri.get('AvailabilityZone', 'N/A'),
                            "created_at": ri.get('InstanceCreateTime', ''),
                        })
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: Instances error — {e}")

            # Replication tasks
            try:
                paginator = client.get_paginator('describe_replication_tasks')
                for page in paginator.paginate():
                    for task in page.get('ReplicationTasks', []):
                        region_data["replication_tasks"].append({
                            "identifier": task.get('ReplicationTaskIdentifier', 'N/A'),
                            "arn": task.get('ReplicationTaskArn', 'N/A'),
                            "status": task.get('Status', 'N/A'),
                            "migration_type": task.get('MigrationType', 'N/A'),
                            "source_endpoint_arn": task.get('SourceEndpointArn', 'N/A'),
                            "target_endpoint_arn": task.get('TargetEndpointArn', 'N/A'),
                            "replication_instance_arn": task.get('ReplicationInstanceArn', 'N/A'),
                            "cdc_start_position": task.get('CdcStartPosition', ''),
                            "created_at": task.get('ReplicationTaskCreationDate', ''),
                        })
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: Tasks error — {e}")

            writer.set_nested("regions", region, value=region_data)
            total_instances += len(region_data["replication_instances"])
            total_tasks += len(region_data["replication_tasks"])

            if region_data["replication_instances"] or region_data["replication_tasks"]:
                logger.info(f"  {region}: {len(region_data['replication_instances'])} instances, "
                           f"{len(region_data['replication_tasks'])} tasks")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value={})

    return total_instances, total_tasks


def main():
    parser = argparse.ArgumentParser(description='DMS Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('dms')
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

        instances, tasks = scan_dms(session, regions, writer)
        writer.set("total_replication_instances", instances)
        writer.set("total_replication_tasks", tasks)
        writer.set("status", "ok")

        logger.info(f"  Total: {instances} instances, {tasks} tasks")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
