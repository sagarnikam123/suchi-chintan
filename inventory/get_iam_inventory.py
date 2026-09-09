#!/usr/bin/env python3
"""
AWS IAM Inventory Scanner
Scans all configured AWS accounts for IAM users, roles, and policies.

Note: IAM is a global service — no region iteration needed.

Usage:
    python get_iam_inventory.py
    python get_iam_inventory.py -a "TQ Primary"
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, create_session,
    get_output_dir, get_timestamp, add_common_args,
    create_session_with_identity,
    IncrementalWriter, make_output_filename,
    run_with_timer,
)

import argparse

SERVICE = "iam"


def scan_iam(session, writer):
    """Scan IAM users, roles, and policies (global service)."""
    client = session.client('iam', config=BOTO_CONFIG)

    # Users
    users = []
    logger.info("  Scanning IAM users...")
    paginator = client.get_paginator('list_users')
    for page in paginator.paginate():
        for user in page.get('Users', []):
            users.append({
                "user_name": user['UserName'],
                "user_id": user['UserId'],
                "arn": user['Arn'],
                "created_at": user.get('CreateDate', ''),
                "password_last_used": user.get('PasswordLastUsed', ''),
                "path": user.get('Path', '/'),
            })
    writer.set("users", users)

    # Roles
    roles = []
    logger.info("  Scanning IAM roles...")
    paginator = client.get_paginator('list_roles')
    for page in paginator.paginate():
        for role in page.get('Roles', []):
            roles.append({
                "role_name": role['RoleName'],
                "role_id": role['RoleId'],
                "arn": role['Arn'],
                "created_at": role.get('CreateDate', ''),
                "path": role.get('Path', '/'),
                "max_session_duration": role.get('MaxSessionDuration', 3600),
                "description": role.get('Description', ''),
            })
    writer.set("roles", roles)

    # Policies (customer-managed only)
    policies = []
    logger.info("  Scanning IAM policies (customer-managed)...")
    paginator = client.get_paginator('list_policies')
    for page in paginator.paginate(Scope='Local'):
        for policy in page.get('Policies', []):
            policies.append({
                "policy_name": policy['PolicyName'],
                "policy_id": policy['PolicyId'],
                "arn": policy['Arn'],
                "attachment_count": policy.get('AttachmentCount', 0),
                "is_attachable": policy.get('IsAttachable', True),
                "created_at": policy.get('CreateDate', ''),
                "updated_at": policy.get('UpdateDate', ''),
            })
    writer.set("policies", policies)

    # Groups
    groups = []
    logger.info("  Scanning IAM groups...")
    paginator = client.get_paginator('list_groups')
    for page in paginator.paginate():
        for group in page.get('Groups', []):
            groups.append({
                "group_name": group['GroupName'],
                "group_id": group['GroupId'],
                "arn": group['Arn'],
                "created_at": group.get('CreateDate', ''),
                "path": group.get('Path', '/'),
            })
    writer.set("groups", groups)

    return len(users), len(roles), len(policies), len(groups)


def main():
    parser = argparse.ArgumentParser(description='IAM Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    timestamp = get_timestamp()

    if args.profile:
        session, account_id, arn = create_session_with_identity(args.profile)
        if not session:
            sys.exit(1)
        accounts = [{"name": account_id, "account_id": account_id, "profile": args.profile, "_session": session}]

    logger.info(f"Scanning {len(accounts)} account(s)")
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

        users, roles, policies, groups = scan_iam(session, writer)
        writer.set("total_users", users)
        writer.set("total_roles", roles)
        writer.set("total_policies", policies)
        writer.set("total_groups", groups)
        writer.set("status", "ok")

        logger.info(f"  Total: {users} users, {roles} roles, {policies} policies, {groups} groups")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
