#!/usr/bin/env python3
"""
Amazon Managed Grafana (AMG) Permissions Scanner
Scans all AMG workspaces and resolves SSO user/group permissions to human-readable names.

Output per workspace:
  { workspace_id, workspace_name, region, users: [...], groups: [...], summary: {...} }

Flushes each workspace result to disk immediately.

Usage:
    python get_amg_permissions.py -p <profile>
    python get_amg_permissions.py -p <profile> -r us-east-1
    python get_amg_permissions.py -p <profile> --workspace g-abc1234567
"""

import sys
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, get_regions, create_session,
    get_output_dir, get_timestamp, add_common_args,
    create_session_with_identity, is_region_unsupported_error,
    IncrementalWriter,
    run_with_timer,
)

SERVICE = "amg-permissions"


def get_identity_store_id(session):
    """Find the IAM Identity Center identity store ID. Tries us-east-2 first (common), then us-east-1."""
    for region in ["us-east-2", "us-east-1"]:
        try:
            sso = session.client("sso-admin", region_name=region, config=BOTO_CONFIG)
            resp = sso.list_instances()
            instances = resp.get("Instances", [])
            if instances:
                return instances[0]["IdentityStoreId"], region
        except Exception:
            continue
    return None, None


def resolve_user(ids_client, identity_store_id, user_id):
    """Resolve an SSO user ID to name/email. Returns (name, email)."""
    try:
        user = ids_client.describe_user(IdentityStoreId=identity_store_id, UserId=user_id)
        return user.get("DisplayName", "UNKNOWN"), user.get("UserName", user_id)
    except Exception:
        return "NOT_FOUND", user_id


def resolve_group(ids_client, identity_store_id, group_id):
    """Resolve an SSO group ID to display name."""
    try:
        group = ids_client.describe_group(IdentityStoreId=identity_store_id, GroupId=group_id)
        return group.get("DisplayName", group_id)
    except Exception:
        return group_id


def scan_workspace_permissions(grafana_client, ids_client, identity_store_id, workspace_id, workspace_name, region):
    """Get permissions for a single workspace and resolve all SSO IDs."""
    logger.info(f"    Resolving permissions for {workspace_name} ({workspace_id})")

    # Paginate permissions
    all_perms = []
    try:
        paginator = grafana_client.get_paginator("list_permissions")
        for page in paginator.paginate(workspaceId=workspace_id):
            all_perms.extend(page.get("permissions", []))
    except Exception as e:
        logger.warning(f"    {workspace_id}: list-permissions failed — {e}")
        return {"workspace_id": workspace_id, "workspace_name": workspace_name, "region": region,
                "status": "error", "error": str(e)}

    users = []
    groups = []

    # Resolve in parallel (10 workers) to speed up the many identitystore calls
    def resolve_entry(perm):
        entry_type = perm["user"]["type"]
        entry_id = perm["user"]["id"]
        role = perm["role"]

        if entry_type == "SSO_GROUP":
            name = resolve_group(ids_client, identity_store_id, entry_id)
            return "group", {"name": name, "role": role, "sso_id": entry_id}
        else:
            name, email = resolve_user(ids_client, identity_store_id, entry_id)
            return "user", {"name": name, "email": email, "role": role}

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(resolve_entry, p) for p in all_perms]
        for f in as_completed(futures):
            try:
                kind, entry = f.result()
                if kind == "group":
                    groups.append(entry)
                else:
                    users.append(entry)
            except Exception:
                pass

    users.sort(key=lambda x: (x["role"], x["name"]))
    groups.sort(key=lambda x: x["name"])

    admins = sum(1 for u in users if u["role"] == "ADMIN")
    editors = sum(1 for u in users if u["role"] == "EDITOR")
    viewers = sum(1 for u in users if u["role"] == "VIEWER")
    stale = sum(1 for u in users if u["name"] == "NOT_FOUND")

    logger.info(f"      {admins} admins, {editors} editors, {viewers} viewers, "
                f"{len(groups)} groups, {stale} stale/deleted")

    return {
        "workspace_id": workspace_id,
        "workspace_name": workspace_name,
        "region": region,
        "users": users,
        "groups": groups,
        "summary": {
            "admins": admins,
            "editors": editors,
            "viewers": viewers,
            "groups": len(groups),
            "stale_users": stale,
            "total_entries": len(all_perms),
        }
    }


def main():
    parser = argparse.ArgumentParser(description='Amazon Managed Grafana Permissions Scanner')
    add_common_args(parser)
    parser.add_argument('--workspace', '-w', default=None,
                        help='Scan only this workspace ID (e.g. g-cccbe09412)')
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    if args.profile:
        session, account_id, arn = create_session_with_identity(args.profile)
        if not session:
            sys.exit(1)
        accounts = [{"name": account_id, "account_id": account_id, "profile": args.profile, "_session": session}]

    regions = [args.region] if args.region else get_regions('grafana')
    timestamp = get_timestamp()

    logger.info(f"Scanning {len(accounts)} account(s) across {len(regions)} region(s)")
    logger.info("=" * 60)

    for account in accounts:
        name = account['name']
        account_id = account['account_id']
        profile = account['profile']

        logger.info(f"🔍 {name} ({account_id})")

        # Reuse session from --profile if already authenticated
        session = account.get("_session") or create_session(profile)
        if not session:
            continue

        # Discover identity store
        identity_store_id, ids_region = get_identity_store_id(session)
        if not identity_store_id:
            logger.error(f"  Could not find IAM Identity Center instance for {account_id}")
            continue
        logger.info(f"  Identity Store: {identity_store_id} ({ids_region})")

        ids_client = session.client("identitystore", region_name=ids_region, config=BOTO_CONFIG)

        output_dir = get_output_dir(account_id, SERVICE)
        combined_writer = IncrementalWriter(output_dir, f"{SERVICE}-{timestamp}.json")
        combined_writer.update({
            "generated": timestamp,
            "account_id": account_id,
            "identity_store_id": identity_store_id,
            "workspaces": {},
        })

        for region in regions:
            try:
                grafana_client = session.client('grafana', region_name=region, config=BOTO_CONFIG)
                paginator = grafana_client.get_paginator('list_workspaces')
                workspaces = []
                for page in paginator.paginate():
                    workspaces.extend(page.get('workspaces', []))
            except Exception as e:
                if is_region_unsupported_error(e):
                    continue
                logger.warning(f"  {region}: list workspaces error — {e}")
                continue

            if not workspaces:
                continue

            if args.workspace:
                workspaces = [w for w in workspaces if w['id'] == args.workspace]
                if not workspaces:
                    continue

            logger.info(f"  {region}: {len(workspaces)} workspace(s)")

            for ws in workspaces:
                ws_id = ws['id']
                ws_name = ws.get('name', ws_id)

                result = scan_workspace_permissions(
                    grafana_client, ids_client, identity_store_id,
                    ws_id, ws_name, region
                )

                # Flush immediately per workspace
                combined_writer.set_nested("workspaces", ws_id, value=result)

        # Final summary
        all_ws = combined_writer.get_data().get("workspaces", {})
        total_stale = sum(w.get("summary", {}).get("stale_users", 0) for w in all_ws.values())
        total_entries = sum(w.get("summary", {}).get("total_entries", 0) for w in all_ws.values())
        combined_writer.set("summary", {
            "total_workspaces": len(all_ws),
            "total_permission_entries": total_entries,
            "total_stale_users": total_stale,
        })

        logger.info(f"  📄 Flushed: {output_dir / f'{SERVICE}-{timestamp}.json'}")

    logger.info("" + "=" * 60)
    logger.info("Done.")


if __name__ == "__main__":
    run_with_timer(main)
