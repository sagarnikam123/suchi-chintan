#!/usr/bin/env python3
"""
GuardDuty Inventory Scanner
Scans detectors, findings summary, and coverage in parallel across enabled regions.

Usage:
    python get_guardduty_inventory.py -p <profile>
    python get_guardduty_inventory.py -p <profile> -r us-east-1
"""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, get_regions, create_session,
    get_output_dir, get_timestamp, add_common_args,
    create_session_with_identity, is_region_unsupported_error, log_region_skip,
    IncrementalWriter, make_output_filename,
    run_with_timer, scan_regions_parallel,
)

SERVICE = "guardduty"


def scan_region(session, region):
    """Scan GuardDuty detectors and findings in one region. Returns (region_data, counts)."""
    region_data = {"detectors": []}
    counts = {"detectors": 0, "findings_high": 0, "findings_medium": 0, "findings_low": 0}

    try:
        gd = session.client('guardduty', region_name=region, config=BOTO_CONFIG)
        detector_ids = gd.list_detectors().get('DetectorIds', [])

        for det_id in detector_ids:
            det = gd.get_detector(DetectorId=det_id)

            # Get findings statistics
            severity_counts = {}
            try:
                stats = gd.get_findings_statistics(
                    DetectorId=det_id,
                    FindingStatisticTypes=['COUNT_BY_SEVERITY']
                )
                severity_counts = stats.get('FindingStatistics', {}).get('CountBySeverity', {})
            except Exception:
                pass

            detector_info = {
                "detector_id": det_id,
                "status": det.get('Status', ''),
                "service_role": det.get('ServiceRole', ''),
                "created_at": det.get('CreatedAt', ''),
                "updated_at": det.get('UpdatedAt', ''),
                "features": [f.get('Name') for f in det.get('Features', []) if f.get('Status') == 'ENABLED'],
                "findings_by_severity": severity_counts,
            }
            region_data["detectors"].append(detector_info)

            # Tally findings
            for sev, count in severity_counts.items():
                try:
                    sev_val = float(sev)
                    if sev_val >= 7.0:
                        counts["findings_high"] += count
                    elif sev_val >= 4.0:
                        counts["findings_medium"] += count
                    else:
                        counts["findings_low"] += count
                except (ValueError, TypeError):
                    pass

        counts["detectors"] = len(region_data["detectors"])

    except Exception as e:
        if is_region_unsupported_error(e):
            log_region_skip(region, SERVICE, str(e))
            return {}, counts
        logger.warning(f"  {region}: Error — {e}")
        return {}, counts

    if not region_data["detectors"]:
        return {}, counts

    return region_data, counts


def scan_guardduty(session, regions, writer):
    """Scan GuardDuty across all regions in parallel."""
    totals = scan_regions_parallel(
        session, regions, writer, scan_region,
        log_fn=lambda region, c: logger.info(f"  {region}: {c['detectors']} detector(s)") if c.get('detectors', 0) > 0 else None,
    )
    return totals


def main():
    parser = argparse.ArgumentParser(description='GuardDuty Inventory Scanner')
    add_common_args(parser)
    args = parser.parse_args()

    if args.profile:
        session, account_id, arn = create_session_with_identity(args.profile)
        if not session:
            sys.exit(1)
        accounts = [{"name": account_id, "account_id": account_id, "profile": args.profile, "_session": session}]
    else:
        accounts = get_accounts(args.account)

    regions = [args.region] if args.region else get_regions('guardduty')
    timestamp = get_timestamp()

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
        writer.update({"name": name, "profile_used": profile, "status": "in_progress", "regions": {}})

        totals = scan_guardduty(session, regions, writer)

        writer.set("total_detectors", totals.get("detectors", 0))
        writer.set("findings_high", totals.get("findings_high", 0))
        writer.set("findings_medium", totals.get("findings_medium", 0))
        writer.set("findings_low", totals.get("findings_low", 0))
        writer.set("status", "ok")

        logger.info("=" * 60)
        logger.info("📊 SUMMARY")
        logger.info("=" * 60)
        logger.info(f"  Total Detectors : {totals.get('detectors', 0)}")
        logger.info(f"  High Findings   : {totals.get('findings_high', 0)}")
        logger.info(f"  Medium Findings : {totals.get('findings_medium', 0)}")
        logger.info(f"  Low Findings    : {totals.get('findings_low', 0)}")

    logger.info("=" * 60)
    logger.info("📊 Done")


if __name__ == "__main__":
    run_with_timer(main)
