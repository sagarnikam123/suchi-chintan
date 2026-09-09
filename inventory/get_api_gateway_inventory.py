#!/usr/bin/env python3
"""
Amazon API Gateway Inventory Scanner
Scans all configured AWS accounts/regions for REST APIs (v1) and HTTP/WebSocket APIs (v2).

Usage:
    python get_api_gateway_inventory.py
    python get_api_gateway_inventory.py -a "TQ Primary"
    python get_api_gateway_inventory.py -r us-east-1
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

SERVICE = "api-gateway"


def scan_api_gateway(session, regions, writer):
    """Scan API Gateway REST and HTTP APIs across all specified regions."""
    total_rest = 0
    total_http = 0

    for region in regions:
        try:
            region_data = {"rest_apis": [], "http_apis": []}

            # REST APIs (API Gateway v1)
            try:
                apigw = session.client('apigateway', region_name=region, config=BOTO_CONFIG)
                paginator = apigw.get_paginator('get_rest_apis')
                for page in paginator.paginate():
                    for api in page.get('items', []):
                        region_data["rest_apis"].append({
                            "api_id": api['id'],
                            "name": api.get('name', 'N/A'),
                            "description": api.get('description', ''),
                            "endpoint_type": api.get('endpointConfiguration', {}).get('types', []),
                            "created_date": api.get('createdDate', ''),
                        })
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — let the outer handler skip it once
                logger.warning(f"  {region}: REST APIs error — {e}")

            # HTTP & WebSocket APIs (API Gateway v2)
            try:
                apigwv2 = session.client('apigatewayv2', region_name=region, config=BOTO_CONFIG)
                resp = apigwv2.get_apis()
                for api in resp.get('Items', []):
                    region_data["http_apis"].append({
                        "api_id": api['ApiId'],
                        "name": api.get('Name', 'N/A'),
                        "protocol_type": api.get('ProtocolType', 'N/A'),
                        "api_endpoint": api.get('ApiEndpoint', 'N/A'),
                        "description": api.get('Description', ''),
                        "created_date": api.get('CreatedDate', ''),
                    })
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — let the outer handler skip it once
                logger.warning(f"  {region}: HTTP APIs error — {e}")

            writer.set_nested("regions", region, value=region_data)
            total_rest += len(region_data["rest_apis"])
            total_http += len(region_data["http_apis"])

            if region_data["rest_apis"] or region_data["http_apis"]:
                logger.info(f"  {region}: {len(region_data['rest_apis'])} REST, {len(region_data['http_apis'])} HTTP/WS APIs")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value={"rest_apis": [], "http_apis": []})

    return total_rest, total_http


def main():
    parser = argparse.ArgumentParser(description='API Gateway Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('apigateway')
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

        rest, http = scan_api_gateway(session, regions, writer)
        writer.set("total_rest_apis", rest)
        writer.set("total_http_apis", http)
        writer.set("status", "ok")

        logger.info(f"  Total: {rest} REST APIs, {http} HTTP/WS APIs")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
