#!/usr/bin/env python3
"""
AWS Certificate Manager (ACM) Inventory Scanner
Scans all configured AWS accounts/regions for SSL/TLS certificates.

Usage:
    python get_acm_inventory.py
    python get_acm_inventory.py -a "TQ Primary"
    python get_acm_inventory.py -r us-east-1
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

SERVICE = "acm"


def scan_acm(session, regions, writer):
    """Scan ACM certificates across all specified regions."""
    total = 0

    for region in regions:
        try:
            client = session.client('acm', region_name=region, config=BOTO_CONFIG)
            certs = []

            paginator = client.get_paginator('list_certificates')
            for page in paginator.paginate(Includes={'keyTypes': [
                'RSA_1024', 'RSA_2048', 'RSA_3072', 'RSA_4096',
                'EC_prime256v1', 'EC_secp384r1', 'EC_secp521r1'
            ]}):
                for cert_summary in page.get('CertificateSummaryList', []):
                    cert_arn = cert_summary['CertificateArn']
                    entry = {
                        "domain_name": cert_summary.get('DomainName', 'N/A'),
                        "arn": cert_arn,
                        "status": cert_summary.get('Status', 'N/A'),
                        "type": cert_summary.get('Type', 'N/A'),
                        "key_algorithm": cert_summary.get('KeyAlgorithm', 'N/A'),
                        "in_use": bool(cert_summary.get('InUse', False)),
                        "renewal_eligibility": cert_summary.get('RenewalEligibility', 'N/A'),
                    }

                    # Get details for expiry and SANs
                    try:
                        desc = client.describe_certificate(CertificateArn=cert_arn)['Certificate']
                        entry.update({
                            "subject_alternative_names": desc.get('SubjectAlternativeNames', []),
                            "issued_at": desc.get('IssuedAt', ''),
                            "not_after": desc.get('NotAfter', ''),
                            "not_before": desc.get('NotBefore', ''),
                            "issuer": desc.get('Issuer', 'N/A'),
                            "imported": desc.get('Type') == 'IMPORTED',
                        })
                    except Exception:
                        pass

                    certs.append(entry)

            writer.set_nested("regions", region, value=certs)
            total += len(certs)

            if certs:
                logger.info(f"  {region}: {len(certs)} certificates")

        except Exception as e:
            if is_region_unsupported_error(e):
                log_region_skip(region, SERVICE, str(e))
            else:
                logger.warning(f"  {region}: Error — {e}")
            writer.set_nested("regions", region, value=[])

    return total


def main():
    parser = argparse.ArgumentParser(description='ACM Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    regions = [args.region] if args.region else get_regions('acm')
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

        total = scan_acm(session, regions, writer)
        writer.set("total_certificates", total)
        writer.set("status", "ok")

        logger.info(f"  Total: {total} certificates")

    logger.info("" + "=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
