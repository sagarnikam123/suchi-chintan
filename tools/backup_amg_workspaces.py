#!/usr/bin/env python3
"""
Amazon Managed Grafana (AMG) Backup Tool — pre-upgrade safety net.

Exports everything AMG will NOT roll back for you when you bump a workspace
version (e.g. 9.4 -> 10.4): dashboards, folders, data sources, and Grafana-managed
alerting (rules, contact points, notification policies, templates, mute timings).

AMG version upgrades are one-way and there is no in-place snapshot, so run this
and commit the output BEFORE upgrading. Restore is manual via the same HTTP API.

Auth model:
  AMG workspaces here use AWS SSO, not static API keys. This script mints a
  SHORT-LIVED Grafana service-account token via the AWS `grafana` API, uses it
  for the HTTP export, then deletes the service account. Nothing is persisted.
  Your AWS role needs grafana:* on the workspace (AdministratorAccess covers it).

Usage:
    # Back up every 9.4 workspace found in the latest amg inventory (primary path):
    python tools/backup_amg_workspaces.py -p 123456789012_AdministratorAccess --only-version 9.4

    # Back up specific workspace IDs:
    python tools/backup_amg_workspaces.py -p <profile> -w g-1234567890 -w g-0987654321

    # Back up ALL workspaces regardless of version:
    python tools/backup_amg_workspaces.py -p <profile>

    # Resolve the account/profile via accounts.yaml instead of a raw profile:
    python tools/backup_amg_workspaces.py -a 123456789012 --only-version 9.4

Output:
    output/<account_id>/amg-backup/<timestamp>/<workspace_id>/
        workspace.json            # AMG describe_workspace metadata
        dashboards/<uid>.json     # full dashboard model, one file per dashboard
        dashboards-index.json     # [{uid,title,folderUid,folderTitle}] for restore placement
        folders.json
        datasources.json          # secrets are NOT returned by Grafana (secureJsonData)
        alerting/*.json           # rules, contact points, policies, templates, mute-timings
        MANIFEST.json             # summary + any per-item errors
"""

import sys
import json
import time
import argparse
import glob
from pathlib import Path

import requests

ROOT_DIR = Path(__file__).parent.parent
OUTPUT_DIR = ROOT_DIR / "output"

# Make `common` importable whether run as a script or imported as a library.
sys.path.insert(0, str(ROOT_DIR))

from common import (  # noqa: E402
    BOTO_CONFIG,
    get_accounts,
    create_session,
    create_session_with_identity,
    get_timestamp,
    run_with_timer,
    logger,
)

# Service-account token lifetime. Kept short — we delete the SA right after,
# but this bounds exposure if the script crashes before cleanup.
TOKEN_TTL_SECONDS = 1800  # 30 min

# HTTP timeouts (connect, read). Dashboards can be large, so read is generous.
HTTP_TIMEOUT = (5, 60)

# ponytail: sequential per-workspace export. Backups are I/O-light and run
# rarely; parallelism would add token-lifecycle race complexity for no real
# win at this scale. Upgrade path: wrap _backup_workspace in a ThreadPool if
# you ever back up dozens of workspaces at once.


def find_latest_amg_inventory(account_dir: Path):
    """Locate the most recent amg inventory JSON for an account, if present."""
    patterns = [
        account_dir / "amg" / "amg-inventory-*.json",
        account_dir / "amg" / "*.json",
    ]
    for p in patterns:
        files = sorted(glob.glob(str(p)), key=lambda f: Path(f).stat().st_mtime, reverse=True)
        if files:
            return files[0]
    return None


def workspaces_from_inventory(inventory_path: Path):
    """Yield {id, name, region, grafana_version, endpoint} from an amg inventory file."""
    try:
        with open(inventory_path) as f:
            data = json.load(f)
    except Exception as error:
        logger.error(f"Could not read amg inventory {inventory_path}: {error}")
        return []

    result = []
    for region, workspaces in (data.get("regions") or {}).items():
        if not isinstance(workspaces, list):
            continue
        for ws in workspaces:
            result.append({
                "id": ws.get("id"),
                "name": ws.get("name"),
                "region": region,
                "grafana_version": str(ws.get("grafana_version", "")),
                "endpoint": ws.get("endpoint"),
            })
    return result


def _grafana_base_url(endpoint: str) -> str:
    """Endpoint in inventory has no scheme; the HTTP API lives at https://<endpoint>."""
    endpoint = endpoint.strip().rstrip("/")
    if endpoint.startswith("http"):
        return endpoint
    return f"https://{endpoint}"


def _create_temp_token(grafana_client, workspace_id: str):
    """Mint a short-lived admin service-account token for HTTP API access.

    Returns (token, service_account_id). Caller MUST delete the service account.
    Uses the modern service-account API; AMG deprecated raw workspace API keys.
    """
    sa_name = f"amg-backup-{int(time.time())}"
    sa = grafana_client.create_workspace_service_account(
        workspaceId=workspace_id,
        grafanaRole="ADMIN",
        name=sa_name,
    )
    sa_id = sa["id"]
    token = grafana_client.create_workspace_service_account_token(
        workspaceId=workspace_id,
        serviceAccountId=sa_id,
        name=f"{sa_name}-token",
        secondsToLive=TOKEN_TTL_SECONDS,
    )
    return token["serviceAccountToken"]["key"], sa_id


def _delete_temp_token(grafana_client, workspace_id: str, sa_id: str):
    """Best-effort cleanup of the temporary service account (revokes its tokens)."""
    try:
        grafana_client.delete_workspace_service_account(
            workspaceId=workspace_id,
            serviceAccountId=sa_id,
        )
    except Exception as error:
        logger.warning(f"  ⚠️  could not delete temp service account {sa_id}: {error}")


class _NotFound(Exception):
    """Raised when a Grafana endpoint returns 404 — treated as 'absent/empty',
    not a real backup failure (some provisioning endpoints 404 when unused)."""


def _api_get(base_url: str, path: str, token: str, retries: int = 1):
    """GET a Grafana HTTP API path with bearer auth. Returns parsed JSON or None.

    Retries once on transient network/5xx errors. Raises _NotFound on 404 so
    callers can distinguish 'feature not present' from a genuine failure.
    """
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    last_error = None
    for attempt in range(retries + 1):
        try:
            resp = requests.get(f"{base_url}{path}", headers=headers, timeout=HTTP_TIMEOUT)
            if resp.status_code == 404:
                raise _NotFound(path)
            resp.raise_for_status()
            if not resp.content:
                return None
            return resp.json()
        except _NotFound:
            raise
        except (requests.ConnectionError, requests.Timeout) as error:
            last_error = error  # transient — retry
        except requests.HTTPError as error:
            # Retry 5xx (server-side/transient); surface 4xx immediately.
            if error.response is not None and 500 <= error.response.status_code < 600:
                last_error = error
            else:
                raise
        if attempt < retries:
            time.sleep(1)
    raise last_error


def _api_get_paginated(base_url: str, path: str, token: str, page_size: int = 1000):
    """Page through a Grafana list endpoint that supports &page=N&limit=.

    Grafana caps /api/search at ~1000 per page, so a single large limit
    silently truncates — the worst failure mode for a backup. Loops until a
    short page is returned.
    """
    sep = "&" if "?" in path else "?"
    results = []
    page = 1
    while True:
        batch = _api_get(base_url, f"{path}{sep}limit={page_size}&page={page}", token) or []
        if not isinstance(batch, list):
            return batch  # non-list endpoint; nothing to paginate
        results.extend(batch)
        if len(batch) < page_size:
            break
        page += 1
    return results


def _dump(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def _backup_dashboards(base_url: str, token: str, out_dir: Path, errors: list) -> list:
    """Export every dashboard's full model, one file per UID.

    Returns a list of {uid, title, folderUid, folderTitle} so restore can
    recreate folder placement — the create API takes folderUid in the request
    body, which is lost if you only keep the raw dashboard model.
    """
    # /api/search returns lightweight entries; dash-db type filters out folders.
    items = _api_get_paginated(base_url, "/api/search?type=dash-db", token)
    dash_dir = out_dir / "dashboards"
    index = []
    for item in items:
        uid = item.get("uid")
        if not uid:
            continue
        try:
            full = _api_get(base_url, f"/api/dashboards/uid/{uid}", token)
            _dump(dash_dir / f"{uid}.json", full)
            meta = (full or {}).get("meta", {}) if isinstance(full, dict) else {}
            index.append({
                "uid": uid,
                "title": item.get("title"),
                "folderUid": meta.get("folderUid") or item.get("folderUid"),
                "folderTitle": meta.get("folderTitle") or item.get("folderTitle"),
            })
        except Exception as error:
            errors.append(f"dashboard {uid}: {error}")
    return index


def _backup_simple(base_url: str, token: str, api_path: str, out_file: Path, errors: list):
    """GET one API path and dump it; record error but never abort the workspace.

    A 404 means the feature is absent/unused (common for provisioning endpoints
    on workspaces with no alerting configured) — that is dumped as empty, not
    recorded as an error, so error counts stay actionable.
    """
    try:
        data = _api_get(base_url, api_path, token)
    except _NotFound:
        _dump(out_file, [])
        return []
    except Exception as error:
        errors.append(f"{api_path}: {error}")
        return []
    _dump(out_file, data)
    return data if isinstance(data, list) else [data] if data else []


def _backup_workspace(grafana_client, ws: dict, run_dir: Path) -> dict:
    """Export one workspace. Returns a manifest dict (also written to disk)."""
    ws_id = ws["id"]
    name = ws.get("name") or ws_id
    logger.info(f"📦 {ws_id} ({name}) [{ws.get('grafana_version', '?')}] in {ws['region']}")

    out_dir = run_dir / ws_id
    manifest = {
        "workspace_id": ws_id,
        "name": name,
        "region": ws["region"],
        "grafana_version": ws.get("grafana_version"),
        "counts": {},
        "errors": [],
    }
    errors = manifest["errors"]

    # Full AMG metadata (auth providers, data sources enabled, etc.)
    try:
        desc = grafana_client.describe_workspace(workspaceId=ws_id)["workspace"]
        _dump(out_dir / "workspace.json", desc)
        endpoint = ws.get("endpoint") or desc.get("endpoint")
    except Exception as error:
        logger.error(f"  ❌ describe_workspace failed for {ws_id}: {error}")
        manifest["errors"].append(f"describe_workspace: {error}")
        _dump(out_dir / "MANIFEST.json", manifest)
        return manifest

    if not endpoint:
        manifest["errors"].append("no endpoint available; cannot reach HTTP API")
        _dump(out_dir / "MANIFEST.json", manifest)
        return manifest

    base_url = _grafana_base_url(endpoint)

    sa_id = None
    try:
        token, sa_id = _create_temp_token(grafana_client, ws_id)

        dash_index = _backup_dashboards(base_url, token, out_dir, errors)
        # Folder placement per dashboard — needed to rebuild the tree on restore.
        _dump(out_dir / "dashboards-index.json", dash_index)
        manifest["counts"]["dashboards"] = len(dash_index)

        folders = _backup_simple(base_url, token, "/api/folders",
                                 out_dir / "folders.json", errors)
        manifest["counts"]["folders"] = len(folders)

        datasources = _backup_simple(base_url, token, "/api/datasources",
                                     out_dir / "datasources.json", errors)
        manifest["counts"]["datasources"] = len(datasources)

        # Grafana-managed alerting objects. Endpoints exist in v9+ and v10.
        alert_dir = out_dir / "alerting"
        alert_targets = {
            "rules": "/api/v1/provisioning/alert-rules",
            "contact-points": "/api/v1/provisioning/contact-points",
            "notification-policies": "/api/v1/provisioning/policies",
            "templates": "/api/v1/provisioning/templates",
            "mute-timings": "/api/v1/provisioning/mute-timings",
        }
        for label, api_path in alert_targets.items():
            items = _backup_simple(base_url, token, api_path,
                                   alert_dir / f"{label}.json", errors)
            manifest["counts"][f"alerting/{label}"] = len(items)

    finally:
        if sa_id is not None:
            _delete_temp_token(grafana_client, ws_id, sa_id)

    _dump(out_dir / "MANIFEST.json", manifest)
    summary = ", ".join(f"{v} {k}" for k, v in manifest["counts"].items() if v)
    logger.info(f"  ✅ {summary or 'nothing exported'}"
                + (f" ({len(errors)} errors)" if errors else ""))
    return manifest


def _select_workspaces(all_ws, wanted_ids, only_version):
    """Filter inventory workspaces by explicit IDs and/or grafana version."""
    selected = all_ws
    if wanted_ids:
        wanted = set(wanted_ids)
        selected = [w for w in selected if w["id"] in wanted]
        missing = wanted - {w["id"] for w in selected}
        for m in missing:
            logger.warning(f"⚠️  workspace {m} not found in inventory — skipping")
    if only_version:
        selected = [w for w in selected if w["grafana_version"] == only_version]
    return selected


def _resolve_session_and_account(args):
    """Return (session, account_id) from either -p profile or -a accounts.yaml."""
    if args.profile:
        session, account_id, _ = create_session_with_identity(args.profile)
        return session, account_id
    accounts = get_accounts(args.account)
    if len(accounts) != 1:
        logger.error("Specify exactly one account with -a <account_id> (or use -p <profile>).")
        sys.exit(1)
    acct = accounts[0]
    session = create_session(acct["profile"])
    return session, acct["account_id"]


def main():
    parser = argparse.ArgumentParser(
        description="Back up AMG workspaces (dashboards, data sources, alerting) before a version upgrade."
    )
    parser.add_argument("-a", "--account",
                        help="Account ID / name / profile from accounts.yaml.")
    parser.add_argument("-p", "--profile",
                        help="AWS profile directly (bypasses accounts.yaml).")
    parser.add_argument("-r", "--region",
                        help="AWS region (used when specifying -w without inventory, or to override).")
    parser.add_argument("-w", "--workspace", action="append", dest="workspaces",
                        help="Workspace ID to back up (repeatable). Omit to use inventory.")
    parser.add_argument("--only-version",
                        help="Only back up workspaces on this grafana version (e.g. 9.4).")
    parser.add_argument("-o", "--output-dir",
                        help="Custom output root (default: output/<account_id>/amg-backup).")
    args = parser.parse_args()

    if not args.account and not args.profile:
        logger.error("Provide -a <account> or -p <profile>.")
        sys.exit(1)

    session, account_id = _resolve_session_and_account(args)
    if session is None or not account_id:
        sys.exit(1)

    # Discover workspaces. Prefer explicit IDs; otherwise read the latest inventory.
    account_dir = OUTPUT_DIR / account_id
    inventory_path = find_latest_amg_inventory(account_dir)
    all_ws = workspaces_from_inventory(Path(inventory_path)) if inventory_path else []

    if inventory_path:
        logger.info(f"Using inventory: {inventory_path}")
    elif not args.workspaces:
        logger.error(f"No amg inventory under {account_dir}/amg and no -w given. "
                     "Run the amg inventory scan first, or pass -w <workspace_id>.")
        sys.exit(1)

    # If explicit workspace IDs were given but aren't in inventory, still back them up
    # (region comes from --region or describe_workspace via the grafana client region).
    selected = _select_workspaces(all_ws, args.workspaces, args.only_version)
    if args.workspaces:
        known = {w["id"] for w in all_ws}
        for wid in args.workspaces:
            if wid not in known:
                selected.append({"id": wid, "name": wid, "region": args.region,
                                 "grafana_version": "", "endpoint": None})

    if not selected:
        logger.error("No workspaces matched the given filters. Nothing to back up.")
        sys.exit(1)

    timestamp = get_timestamp()
    out_root = Path(args.output_dir) if args.output_dir else account_dir / "amg-backup"
    run_dir = out_root / timestamp
    run_dir.mkdir(parents=True, exist_ok=True)
    logger.info(f"Backing up {len(selected)} workspace(s) to {run_dir}")

    run_manifest = {"account_id": account_id, "timestamp": timestamp, "workspaces": []}

    for ws in selected:
        region = ws.get("region") or args.region
        if not region:
            logger.error(f"  ❌ {ws['id']}: region unknown (not in inventory and no -r given); "
                         "pass -r <region> or re-run the amg inventory scan. Skipping.")
            run_manifest["workspaces"].append({"workspace_id": ws["id"],
                                                "errors": ["region unknown"]})
            continue
        grafana_client = session.client("grafana", region_name=region, config=BOTO_CONFIG)
        try:
            ws_manifest = _backup_workspace(grafana_client, ws, run_dir)
        except Exception as error:
            logger.error(f"  ❌ {ws['id']} failed: {error}")
            ws_manifest = {"workspace_id": ws["id"], "errors": [str(error)]}
        finally:
            try:
                grafana_client.close()
            except Exception:
                pass
        run_manifest["workspaces"].append(ws_manifest)

    _dump(run_dir / "MANIFEST.json", run_manifest)

    total_err = sum(len(w.get("errors", [])) for w in run_manifest["workspaces"])
    logger.info(f"📄 Backup manifest: {run_dir / 'MANIFEST.json'}")
    if total_err:
        logger.warning(f"⚠️  Completed with {total_err} error(s) — review MANIFEST.json files.")
    else:
        logger.info("✅ Backup complete with no errors.")


if __name__ == "__main__":
    run_with_timer(main)
