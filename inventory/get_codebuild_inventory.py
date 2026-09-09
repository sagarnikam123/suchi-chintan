#!/usr/bin/env python3
"""
AWS CodeBuild Inventory Scanner
Scans all configured AWS accounts/regions for CodeBuild projects.

Usage:
    python get_codebuild_inventory.py
    python get_codebuild_inventory.py -a "TQ Primary"
    python get_codebuild_inventory.py -r us-east-1
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

SERVICE = "codebuild"


def scan_codebuild(session, regions, writer):
    """Scan CodeBuild projects across all specified regions."""
    total = 0

    for region in regions:
        try:
            client = session.client('codebuild', region_name=region, config=BOTO_CONFIG)
            projects = []

            # List project names
            project_names = []
            paginator = client.get_paginator('list_projects')
            for page in paginator.paginate():
                project_names.extend(page.get('projects', []))

            # Batch describe (max 100 per call)
            for i in range(0, len(project_names), 100):
                batch = project_names[i:i+100]
                resp = client.batch_get_projects(names=batch)
                for proj in resp.get('projects', []):
                    env = proj.get('environment', {})
                    projects.append({
                        "name": proj.get('name', 'N/A'),
                        "arn": proj.get('arn', 'N/A'),
                        "source_type": proj.get('source', {}).get('type', 'N/A'),
                        "source_location": proj.get('source', {}).get('location', ''),
                        "compute_type": env.get('computeType', 'N/A'),
                        "image": env.get('image', 'N/A'),
                        "environment_type": env.get('type', 'N/A'),
                        "privileged_mode": env.get('privilegedMode', False),
                        "timeout_min": proj.get('timeoutInMinutes', 0),
                        "badge_enabled": proj.get('badge', {}).get('badgeEnabled', False),
                        "last_modified": proj.get('lastModified', ''),
                        "created_at": proj.get('created', ''),
                    })

            writer.set_nested("regions", region, value=projects)
            total += len(projects)

            if projects:
                logger.info(f"  {region}: {len(projects)} projects")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value=[])

    return total


def main():
    parser = argparse.ArgumentParser(description='CodeBuild Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('codebuild')
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

        total = scan_codebuild(session, regions, writer)
        writer.set("total_projects", total)
        writer.set("status", "ok")

        logger.info(f"  Total: {total} projects")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
