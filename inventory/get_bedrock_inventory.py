#!/usr/bin/env python3
"""
Amazon Bedrock Inventory Scanner
Scans all configured AWS accounts/regions for Bedrock resources:
  - Custom models
  - Provisioned model throughput
  - Agents (AgentCore)
  - Knowledge bases
  - Guardrails

Usage:
    python get_bedrock_inventory.py
    python get_bedrock_inventory.py -a "TQ Primary"
    python get_bedrock_inventory.py -r us-east-1
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, create_session,
    get_output_dir, get_timestamp, add_common_args,
    create_session_with_identity, is_region_unsupported_error, log_region_skip,
    IncrementalWriter, make_output_filename,
    run_with_timer,
)

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

SERVICE = "bedrock"

# Regions where Amazon Bedrock is actually available (as of 2026).
# ponytail: pinned list avoids probing 33 regions where Bedrock doesn't exist.
# Upgrade path: if AWS adds a region, add it here or pass -r explicitly.
BEDROCK_REGIONS = [
    "us-east-1", "us-east-2", "us-west-2",
    "ap-south-1", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
    "ap-southeast-1", "ap-southeast-2",
    "ca-central-1",
    "eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3", "eu-north-1",
    "sa-east-1",
]


def scan_region(session, region):
    """Scan Bedrock resources in a single region. Returns (region_data, counts)."""
    counts = {"custom_models": 0, "provisioned_throughputs": 0, "agents": 0, "knowledge_bases": 0, "guardrails": 0}
    region_data = {}
    try:
        client = session.client('bedrock', region_name=region, config=BOTO_CONFIG)

        # Custom models
        custom_models = []
        try:
            resp = client.list_custom_models()
            for m in resp.get('modelSummaries', []):
                custom_models.append({
                    "model_name": m.get('modelName', 'N/A'),
                    "model_arn": m.get('modelArn', 'N/A'),
                    "base_model_id": m.get('baseModelIdentifier', 'N/A'),
                    "creation_time": m.get('creationTime', ''),
                })
        except Exception:
            pass
        region_data["custom_models"] = custom_models
        counts["custom_models"] = len(custom_models)

        # Provisioned throughputs
        provisioned = []
        try:
            resp = client.list_provisioned_model_throughputs()
            for pt in resp.get('provisionedModelSummaries', []):
                provisioned.append({
                    "name": pt.get('provisionedModelName', 'N/A'),
                    "arn": pt.get('provisionedModelArn', 'N/A'),
                    "model_arn": pt.get('modelArn', 'N/A'),
                    "status": pt.get('status', 'N/A'),
                    "model_units": pt.get('desiredModelUnits', 0),
                    "creation_time": pt.get('creationTime', ''),
                })
        except Exception:
            pass
        region_data["provisioned_throughputs"] = provisioned
        counts["provisioned_throughputs"] = len(provisioned)

        # Agents + Knowledge bases (both use bedrock-agent client — create once)
        agents = []
        knowledge_bases = []
        try:
            agent_client = session.client('bedrock-agent', region_name=region, config=BOTO_CONFIG)
            try:
                resp = agent_client.list_agents()
                for a in resp.get('agentSummaries', []):
                    agents.append({
                        "agent_id": a.get('agentId', 'N/A'),
                        "agent_name": a.get('agentName', 'N/A'),
                        "status": a.get('agentStatus', 'N/A'),
                        "updated_at": a.get('updatedAt', ''),
                    })
            except Exception:
                pass
            try:
                resp = agent_client.list_knowledge_bases()
                for kb in resp.get('knowledgeBaseSummaries', []):
                    knowledge_bases.append({
                        "knowledge_base_id": kb.get('knowledgeBaseId', 'N/A'),
                        "name": kb.get('name', 'N/A'),
                        "status": kb.get('status', 'N/A'),
                        "updated_at": kb.get('updatedAt', ''),
                    })
            except Exception:
                pass
        except Exception:
            pass
        region_data["agents"] = agents
        counts["agents"] = len(agents)
        region_data["knowledge_bases"] = knowledge_bases
        counts["knowledge_bases"] = len(knowledge_bases)

        # Guardrails
        guardrails = []
        try:
            resp = client.list_guardrails()
            for g in resp.get('guardrails', []):
                guardrails.append({
                    "guardrail_id": g.get('id', 'N/A'),
                    "name": g.get('name', 'N/A'),
                    "status": g.get('status', 'N/A'),
                    "version": g.get('version', 'N/A'),
                    "created_at": g.get('createdAt', ''),
                })
        except Exception:
            pass
        region_data["guardrails"] = guardrails
        counts["guardrails"] = len(guardrails)

    except Exception as e:
        if is_region_unsupported_error(e):
            log_region_skip(region, SERVICE, str(e))
        else:
            logger.warning(f"  {region}: Error — {e}")
        return {}, counts

    return region_data, counts


def scan_bedrock(session, regions, writer):
    """Scan Bedrock resources across all regions in parallel."""
    total = {"custom_models": 0, "provisioned_throughputs": 0, "agents": 0, "knowledge_bases": 0, "guardrails": 0}

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(scan_region, session, region): region for region in regions}
        for future in as_completed(futures):
            region = futures[future]
            try:
                region_data, counts = future.result()
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: worker error — {e}")
                continue

            for k in total:
                total[k] += counts.get(k, 0)

            # Flush per-region (thread-safe: single writer, one call)
            writer.set_nested("regions", region, value=region_data)

            count = sum(counts.values())
            if count:
                logger.info(f"  {region}: {counts['custom_models']} models, {counts['provisioned_throughputs']} provisioned, "
                           f"{counts['agents']} agents, {counts['knowledge_bases']} KBs, {counts['guardrails']} guardrails")

    return total


def main():
    parser = argparse.ArgumentParser(description='Bedrock Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else BEDROCK_REGIONS
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

        totals = scan_bedrock(session, regions, writer)
        writer.set("totals", totals)
        writer.set("status", "ok")

        logger.info(f"  Totals: {totals}")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
