#!/usr/bin/env python3
"""
Amazon Bedrock AgentCore Inventory Scanner
Scans all configured AWS accounts/regions for AgentCore resources:
  - Agent Runtimes (+ endpoints per runtime)
  - Gateways (MCP protocol)
  - Memories
  - Registries
  - API Key Credential Providers

Usage:
    python get_agentcore_inventory.py                    # All accounts, all regions
    python get_agentcore_inventory.py -a "Dev-Engineering"
    python get_agentcore_inventory.py -r us-east-1
"""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, create_session,
    get_output_dir, get_timestamp, get_disabled_regions, add_common_args,
    create_session_with_identity, is_region_unsupported_error, log_region_skip,
    IncrementalWriter, make_output_filename,
    run_with_timer,
)

SERVICE = "agentcore"

# AgentCore is only available in these regions (as of July 2026)
AGENTCORE_REGIONS = [
    "us-east-1", "us-east-2", "us-west-2",
    "eu-central-1", "eu-west-1", "eu-west-2", "eu-south-1", "eu-west-3", "eu-south-2", "eu-north-1",
    "ap-southeast-3", "ap-south-1", "ap-southeast-1", "ap-southeast-2", "ap-southeast-7", "ap-northeast-1", "ap-northeast-2",
    "ca-central-1", "sa-east-1",
    "us-gov-west-1",
]


def paginate(client, method, result_key, **kwargs):
    """Generic paginator for bedrock-agentcore-control list APIs."""
    items = []
    next_token = None
    while True:
        params = {**kwargs, "maxResults": 50}
        if next_token:
            params["nextToken"] = next_token
        response = getattr(client, method)(**params)
        items.extend(response.get(result_key, []))
        next_token = response.get("nextToken")
        if not next_token:
            break
    return items


def scan_region(session, region):
    """Scan a single region for all AgentCore resources."""
    result = {
        "agent_runtimes": [],
        "gateways": [],
        "memories": [],
        "registries": [],
        "credential_providers": [],
    }

    try:
        client = session.client('bedrock-agentcore-control', region_name=region, config=BOTO_CONFIG)
    except Exception as e:
        return {"status": "client_error", "error": str(e), **result}

    # Agent Runtimes
    try:
        runtimes = paginate(client, "list_agent_runtimes", "agentRuntimes")
        # For each runtime, get its endpoints
        for rt in runtimes:
            try:
                endpoints = paginate(
                    client, "list_agent_runtime_endpoints", "agentRuntimeEndpoints",
                    agentRuntimeId=rt["agentRuntimeId"]
                )
                rt["endpoints"] = endpoints
            except Exception:
                rt["endpoints"] = []
        result["agent_runtimes"] = runtimes
    except Exception as e:
        if not is_region_unsupported_error(e):
            result["agent_runtimes_error"] = str(e)

    # Gateways
    try:
        result["gateways"] = paginate(client, "list_gateways", "items")
    except Exception as e:
        if not is_region_unsupported_error(e):
            result["gateways_error"] = str(e)

    # Memories
    try:
        result["memories"] = paginate(client, "list_memories", "memories")
    except Exception as e:
        if not is_region_unsupported_error(e):
            result["memories_error"] = str(e)

    # Registries
    try:
        result["registries"] = paginate(client, "list_registries", "registries")
    except Exception as e:
        if not is_region_unsupported_error(e):
            result["registries_error"] = str(e)

    # API Key Credential Providers
    try:
        result["credential_providers"] = paginate(client, "list_api_key_credential_providers", "credentialProviders")
    except Exception as e:
        if not is_region_unsupported_error(e):
            result["credential_providers_error"] = str(e)

    # Count totals
    total = sum(len(result[k]) for k in ["agent_runtimes", "gateways", "memories", "registries", "credential_providers"])
    result["status"] = "ok"
    result["total_resources"] = total
    return result


def main():
    parser = argparse.ArgumentParser(description='Amazon Bedrock AgentCore Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    if args.profile:
        session, account_id, arn = create_session_with_identity(args.profile)
        if not session:
            sys.exit(1)
        accounts = [{"name": account_id, "account_id": account_id, "profile": args.profile, "_session": session}]

    regions = [args.region] if args.region else AGENTCORE_REGIONS
    timestamp = get_timestamp()

    logger.info(f"Scanning {len(accounts)} account(s) across {len(regions)} AgentCore region(s)")
    logger.info("=" * 60)

    combined_data = {
        "generated": timestamp,
        "note": "Amazon Bedrock AgentCore resources per account per region.",
        "accounts": {},
        "summary": {
            "total_accounts_scanned": len(accounts),
            "total_agent_runtimes": 0,
            "total_gateways": 0,
            "total_memories": 0,
            "total_registries": 0,
            "total_credential_providers": 0,
        }
    }

    for account in accounts:
        name = account['name']
        account_id = account['account_id']
        profile = account['profile']

        # Skip disabled accounts
        if account.get('enabled') is False:
            logger.info(f"⏭️  {name} ({account_id}) — skipped (no credentials)")
            continue

        logger.info(f"🔍 {name} ({account_id}) — profile: {profile}")

        # Reuse session from --profile if already authenticated
        session = account.get("_session") or create_session(profile)
        if not session:
            combined_data["accounts"][account_id] = {
                "name": name, "status": "auth_failed", "regions": {}
            }
            continue

        account_output = get_output_dir(account_id, SERVICE)
        account_writer = IncrementalWriter(account_output, make_output_filename(SERVICE, account_id, timestamp))
        account_writer.update({"name": name, "profile_used": profile, "status": "ok", "regions": {}})

        disabled = get_disabled_regions(session)
        acct_totals = {"agent_runtimes": 0, "gateways": 0, "memories": 0, "registries": 0, "credential_providers": 0}

        for region in regions:
            if region in disabled:
                account_writer.set_nested("regions", region, value={"status": "disabled"})
                continue

            region_data = scan_region(session, region)
            account_writer.set_nested("regions", region, value=region_data)

            if region_data.get("total_resources", 0) > 0:
                logger.info(f"  {region}: {region_data['total_resources']} resources "
                            f"(runtimes={len(region_data['agent_runtimes'])}, "
                            f"gateways={len(region_data['gateways'])}, "
                            f"memories={len(region_data['memories'])}, "
                            f"registries={len(region_data['registries'])}, "
                            f"cred_providers={len(region_data['credential_providers'])})")

            for k in acct_totals:
                acct_totals[k] += len(region_data.get(k, []))

        account_writer.set("totals", acct_totals)
        combined_data["accounts"][account_id] = account_writer.get_data()

        # Update summary
        summary = combined_data["summary"]
        for k in acct_totals:
            summary[f"total_{k}"] += acct_totals[k]

        total_for_account = sum(acct_totals.values())
        logger.info(f"  📄 {name}: {total_for_account} total AgentCore resources")

    # Final summary
    logger.info("" + "=" * 60)
    logger.info("📊 SUMMARY")
    logger.info("=" * 60)
    final = combined_data["summary"]
    logger.info(f"  Agent Runtimes:       {final['total_agent_runtimes']}")
    logger.info(f"  Gateways:             {final['total_gateways']}")
    logger.info(f"  Memories:             {final['total_memories']}")
    logger.info(f"  Registries:           {final['total_registries']}")
    logger.info(f"  Credential Providers: {final['total_credential_providers']}")
    total_all = sum(v for k, v in final.items() if k.startswith("total_") and k != "total_accounts_scanned")
    logger.info(f"  TOTAL:                {total_all}")


if __name__ == "__main__":
    run_with_timer(main)
