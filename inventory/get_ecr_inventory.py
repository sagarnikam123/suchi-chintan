#!/usr/bin/env python3
"""
ECR Repository Inventory Scanner
Scans all configured AWS accounts/regions for ECR repositories and image counts.

Usage:
    python get_ecr_inventory.py                     # All accounts, all regions
    python get_ecr_inventory.py -a "TQ Hosted"      # Single account
    python get_ecr_inventory.py -p <profile> -r us-east-1
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


def scan_ecr_repositories(session, regions, writer):
    """Scan ECR repositories across all specified regions."""
    total_repos = 0
    total_images = 0

    for region in regions:
        try:
            ecr_client = session.client('ecr', region_name=region, config=BOTO_CONFIG)
            repos = []

            paginator = ecr_client.get_paginator('describe_repositories')
            for page in paginator.paginate():
                for repo in page['repositories']:
                    # Get image count (paginated — describe_images caps at
                    # 100 details/page; a single call undercounts big repos)
                    try:
                        image_count = 0
                        img_paginator = ecr_client.get_paginator('describe_images')
                        for img_page in img_paginator.paginate(
                            repositoryName=repo['repositoryName'],
                            filter={'tagStatus': 'ANY'}
                        ):
                            image_count += len(img_page.get('imageDetails', []))
                    except Exception:
                        image_count = 0

                    repo_info = {
                        "name": repo['repositoryName'],
                        "uri": repo.get('repositoryUri', ''),
                        "created_at": repo.get('createdAt', ''),
                        "image_tag_mutability": repo.get('imageTagMutability', 'MUTABLE'),
                        "scan_on_push": repo.get('imageScanningConfiguration', {}).get('scanOnPush', False),
                        "encryption_type": repo.get('encryptionConfiguration', {}).get('encryptionType', 'AES256'),
                        "image_count": image_count,
                    }
                    repos.append(repo_info)

            writer.set_nested("regions", region, value=repos)
            total_repos += len(repos)
            total_images += sum(r['image_count'] for r in repos)

            if repos:
                logger.info(f"  {region}: {len(repos)} repositories, {sum(r['image_count'] for r in repos)} images")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, 'ecr', str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value=[])

    return total_repos, total_images


def main():
    parser = argparse.ArgumentParser(description='ECR Repository Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('ecr')
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
        "summary": {"total_accounts_scanned": len(accounts), "total_repositories": 0, "total_images": 0}
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

        output_dir = get_output_dir(account_id, "ecr")
        writer = IncrementalWriter(output_dir, make_output_filename("ecr", account_id, timestamp))
        writer.update({"name": name, "profile_used": profile, "status": "in_progress", "regions": {}})

        repos, images = scan_ecr_repositories(session, regions, writer)
        writer.set("total_repositories", repos)
        writer.set("total_images", images)
        writer.set("status", "ok")

        inventory["summary"]["total_repositories"] += repos
        inventory["summary"]["total_images"] += images

    logger.info("" + "=" * 60)
    logger.info("📊 SUMMARY")
    logger.info("=" * 60)
    logger.info(f"  Total ECR Repositories: {inventory['summary']['total_repositories']}")
    logger.info(f"  Total Images: {inventory['summary']['total_images']}")


if __name__ == "__main__":
    run_with_timer(main)
