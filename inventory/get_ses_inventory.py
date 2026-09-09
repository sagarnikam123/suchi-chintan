#!/usr/bin/env python3
"""
Amazon SES (Simple Email Service) Inventory Scanner
Scans all configured AWS accounts/regions for SES identities and configuration sets.

Usage:
    python get_ses_inventory.py
    python get_ses_inventory.py -a "TQ Primary"
    python get_ses_inventory.py -r us-east-1
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

SERVICE = "ses"


def scan_ses(session, regions, writer):
    """Scan SES identities and configuration sets across all specified regions."""
    total_identities = 0
    total_config_sets = 0

    for region in regions:
        try:
            client = session.client('sesv2', region_name=region, config=BOTO_CONFIG)
            region_data = {"identities": [], "configuration_sets": []}

            # Email identities
            try:
                resp = client.list_email_identities()
                for identity in resp.get('EmailIdentities', []):
                    region_data["identities"].append({
                        "identity_name": identity.get('IdentityName', 'N/A'),
                        "identity_type": identity.get('IdentityType', 'N/A'),
                        "sending_enabled": identity.get('SendingEnabled', False),
                        "verification_status": identity.get('VerificationStatus', 'N/A'),
                    })
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: Identities error — {e}")

            # Configuration sets
            try:
                resp = client.list_configuration_sets()
                for cs_name in resp.get('ConfigurationSets', []):
                    region_data["configuration_sets"].append({"name": cs_name})
            except Exception as e:
                if is_region_unsupported_error(e):
                    raise  # opt-in region — outer handler skips it once
                logger.warning(f"  {region}: Config sets error — {e}")

            writer.set_nested("regions", region, value=region_data)
            total_identities += len(region_data["identities"])
            total_config_sets += len(region_data["configuration_sets"])

            if region_data["identities"] or region_data["configuration_sets"]:
                logger.info(f"  {region}: {len(region_data['identities'])} identities, "
                           f"{len(region_data['configuration_sets'])} config sets")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value={})

    return total_identities, total_config_sets


def main():
    parser = argparse.ArgumentParser(description='SES Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('sesv2')
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

        identities, config_sets = scan_ses(session, regions, writer)
        writer.set("total_identities", identities)
        writer.set("total_configuration_sets", config_sets)
        writer.set("status", "ok")

        logger.info(f"  Total: {identities} identities, {config_sets} config sets")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
