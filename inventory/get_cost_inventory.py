#!/usr/bin/env python3
"""
AWS Cost Explorer Inventory
Queries Cost Explorer for service-level spend across all configured accounts.

Reports:
  - Current month (MTD) cost per service
  - Prior month (last full calendar month) cost per service
  - Year-to-date (Jan 1 → today) cost per service
  - Month-by-month breakdown per service
  - Grouped by: Linked Account, Region, Usage Type, Purchase Option

Usage:
    python get_cost_inventory.py                     # All accounts
    python get_cost_inventory.py -a "TQ Primary"     # Single account
    python get_cost_inventory.py --profile myprofile  # Direct profile
"""

import sys
import argparse
from pathlib import Path
from datetime import datetime, date, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, create_session,
    get_output_dir, save_json, get_timestamp, add_common_args,
    create_session_with_identity, run_with_timer, IncrementalWriter,
    make_output_filename,
)


# ponytail: Cost Explorer is a global service (us-east-1 only), no region iteration needed.
CE_REGION = "us-east-1"


def _first_of_month(d: date) -> str:
    return d.replace(day=1).isoformat()


def _prior_month_range(d: date) -> tuple:
    """Returns (start_str, end_str) for the previous calendar month."""
    first_of_current = d.replace(day=1)
    if d.month == 1:
        first_of_prior = d.replace(year=d.year - 1, month=12, day=1)
    else:
        first_of_prior = d.replace(month=d.month - 1, day=1)
    return first_of_prior.isoformat(), first_of_current.isoformat()


def _today_str() -> str:
    return date.today().isoformat()


def _get_cost(ce_client, start: str, end: str, granularity: str, group_by: list) -> list:
    """Page through Cost Explorer GetCostAndUsage results."""
    results = []
    kwargs = {
        "TimePeriod": {"Start": start, "End": end},
        "Granularity": granularity,
        "Metrics": ["UnblendedCost", "BlendedCost"],
        "GroupBy": group_by,
    }

    while True:
        resp = ce_client.get_cost_and_usage(**kwargs)
        results.extend(resp.get("ResultsByTime", []))
        token = resp.get("NextPageToken")
        if not token:
            break
        kwargs["NextPageToken"] = token

    return results


def query_cost_by_service(ce_client, start: str, end: str, granularity: str = "MONTHLY") -> list:
    """Cost grouped by SERVICE."""
    return _get_cost(ce_client, start, end, granularity, [
        {"Type": "DIMENSION", "Key": "SERVICE"}
    ])


def query_cost_by_region(ce_client, start: str, end: str) -> list:
    """Cost grouped by SERVICE + REGION."""
    return _get_cost(ce_client, start, end, "MONTHLY", [
        {"Type": "DIMENSION", "Key": "SERVICE"},
        {"Type": "DIMENSION", "Key": "REGION"},
    ])


def query_cost_by_usage_type(ce_client, start: str, end: str) -> list:
    """Cost grouped by SERVICE + USAGE_TYPE."""
    return _get_cost(ce_client, start, end, "MONTHLY", [
        {"Type": "DIMENSION", "Key": "SERVICE"},
        {"Type": "DIMENSION", "Key": "USAGE_TYPE"},
    ])


def query_cost_by_purchase_option(ce_client, start: str, end: str) -> list:
    """Cost grouped by SERVICE + PURCHASE_TYPE."""
    return _get_cost(ce_client, start, end, "MONTHLY", [
        {"Type": "DIMENSION", "Key": "SERVICE"},
        {"Type": "DIMENSION", "Key": "PURCHASE_TYPE"},
    ])


def query_cost_by_linked_account(ce_client, start: str, end: str) -> list:
    """Cost grouped by LINKED_ACCOUNT + SERVICE."""
    return _get_cost(ce_client, start, end, "MONTHLY", [
        {"Type": "DIMENSION", "Key": "LINKED_ACCOUNT"},
        {"Type": "DIMENSION", "Key": "SERVICE"},
    ])


def _parse_groups(results_by_time: list) -> list:
    """Flatten Cost Explorer grouped results into a simple list of dicts."""
    rows = []
    for period in results_by_time:
        start = period["TimePeriod"]["Start"]
        end = period["TimePeriod"]["End"]
        for group in period.get("Groups", []):
            keys = group["Keys"]
            metrics = group.get("Metrics", {})
            unblended_metric = metrics.get("UnblendedCost", {})
            blended_metric = metrics.get("BlendedCost", {})
            unblended = float(unblended_metric.get("Amount", 0) or 0)
            blended = float(blended_metric.get("Amount", 0) or 0)
            currency = unblended_metric.get("Unit", "USD")
            if unblended == 0.0 and blended == 0.0:
                continue
            rows.append({
                "period_start": start,
                "period_end": end,
                "keys": keys,
                "unblended_cost": round(unblended, 4),
                "blended_cost": round(blended, 4),
                "currency": currency,
            })
    return rows


def _total_unblended(rows: list) -> float:
    return round(sum(r["unblended_cost"] for r in rows), 2)


def scan_costs(session, writer: IncrementalWriter):
    """Run all cost queries for a single account/session.
    Flushes to disk after each query via IncrementalWriter — crash-safe."""
    ce_client = session.client("ce", region_name=CE_REGION, config=BOTO_CONFIG)

    today = date.today()
    ytd_start = f"{today.year}-01-01"
    mtd_start = _first_of_month(today)
    prior_month_start, prior_month_end = _prior_month_range(today)
    # Cost Explorer 'End' is exclusive, so use tomorrow to include today and avoid start == end on the 1st of month
    end = (today + timedelta(days=1)).isoformat()

    writer.set("period", {
        "ytd_start": ytd_start,
        "mtd_start": mtd_start,
        "prior_month_start": prior_month_start,
        "prior_month_end": prior_month_end,
        "end": end,
    })

    # 1. MTD by service
    logger.info("  Querying MTD cost by service...")
    mtd_raw = query_cost_by_service(ce_client, mtd_start, end, "MONTHLY")
    mtd_rows = _parse_groups(mtd_raw)
    writer.set("mtd_by_service", mtd_rows)
    writer.set("mtd_total", _total_unblended(mtd_rows))

    # 2. Prior Month by service
    logger.info("  Querying Prior Month cost by service...")
    prior_raw = query_cost_by_service(ce_client, prior_month_start, prior_month_end, "MONTHLY")
    prior_rows = _parse_groups(prior_raw)
    writer.set("prior_month_by_service", prior_rows)
    writer.set("prior_month_total", _total_unblended(prior_rows))

    # 3. YTD by service (monthly breakdown)
    logger.info("  Querying YTD cost by service (monthly breakdown)...")
    ytd_raw = query_cost_by_service(ce_client, ytd_start, end, "MONTHLY")
    ytd_rows = _parse_groups(ytd_raw)
    writer.set("ytd_by_service_monthly", ytd_rows)
    writer.set("ytd_total", _total_unblended(ytd_rows))

    # 4. By region
    logger.info("  Querying cost by service + region...")
    region_raw = query_cost_by_region(ce_client, ytd_start, end)
    writer.set("by_region", _parse_groups(region_raw))

    # 5. By usage type
    logger.info("  Querying cost by service + usage type...")
    usage_raw = query_cost_by_usage_type(ce_client, ytd_start, end)
    writer.set("by_usage_type", _parse_groups(usage_raw))

    # 6. By purchase option
    logger.info("  Querying cost by service + purchase option...")
    purchase_raw = query_cost_by_purchase_option(ce_client, ytd_start, end)
    writer.set("by_purchase_option", _parse_groups(purchase_raw))

    # 7. By linked account
    logger.info("  Querying cost by linked account + service...")
    account_raw = query_cost_by_linked_account(ce_client, ytd_start, end)
    writer.set("by_linked_account", _parse_groups(account_raw))

    return writer.get_data()


def _get_region_summary(rows: list, top_n: int = 10) -> dict:
    """Aggregate regional costs from by_region rows and return summary dict."""
    totals = {}
    for r in rows:
        keys = r.get("keys", [])
        reg = keys[1] if len(keys) > 1 else (keys[0] if keys else "Unknown")
        totals[reg] = totals.get(reg, 0.0) + r.get("unblended_cost", 0.0)

    sorted_regs = sorted(totals.items(), key=lambda x: x[1], reverse=True)
    top_list = [
        {"region": reg, "unblended_cost": round(cost, 2)}
        for reg, cost in sorted_regs[:top_n]
    ]
    return {
        "total_regions_with_spend": len(sorted_regs),
        "top_regions": top_list,
    }


def _print_top_regions(rows: list, label: str, top_n: int = 5):
    """Print top N spending regions."""
    summary = _get_region_summary(rows, top_n)
    if summary["top_regions"]:
        logger.info(f"  🌍 Top {top_n} regions ({label}):")
        for entry in summary["top_regions"]:
            logger.info(f"    ${entry['unblended_cost']:>12,.2f}  {entry['region']}")


def _get_service_summary(rows: list, top_n: int = 15) -> dict:
    """Aggregate service costs and return a summary dict."""
    totals = {}
    for r in rows:
        svc = r["keys"][0] if r["keys"] else "Unknown"
        totals[svc] = totals.get(svc, 0.0) + r["unblended_cost"]

    sorted_svcs = sorted(totals.items(), key=lambda x: x[1], reverse=True)
    top_list = [
        {"service": svc, "unblended_cost": round(cost, 2)}
        for svc, cost in sorted_svcs[:top_n]
    ]
    return {
        "total_services_used": len(sorted_svcs),
        "all_service_names": [s[0] for s in sorted_svcs],
        "top_15_services": top_list,
    }


def _print_top_services(rows: list, label: str, top_n: int = 15):
    """Print top N services by unblended cost."""
    summary = _get_service_summary(rows, top_n)
    logger.info(f"  📊 Top {top_n} services ({label}):")
    for entry in summary["top_15_services"]:
        logger.info(f"    ${entry['unblended_cost']:>12,.2f}  {entry['service']}")
    logger.info(f"    {'─' * 30}")
    total = sum(e["unblended_cost"] for e in summary["top_15_services"])
    logger.info(f"    ${total:>12,.2f}  (top {len(summary['top_15_services'])} total)")


def main():
    parser = argparse.ArgumentParser(description="AWS Cost Explorer Inventory")
    add_common_args(parser)
    args = parser.parse_args()

    accounts = get_accounts(args.account)
    timestamp = get_timestamp()

    if args.profile:
        session, account_id, arn = create_session_with_identity(args.profile)
        if not session:
            sys.exit(1)
        accounts = [{"name": account_id, "account_id": account_id, "profile": args.profile, "_session": session}]

    logger.info(f"Scanning costs for {len(accounts)} account(s)")
    logger.info("=" * 60)

    inventory = {
        "generated": timestamp,
        "glossary": {
            "unblended_cost": "Actual rate charged to the specific account for each line item",
            "blended_cost": "Averaged rate across the AWS Organization (mixes RI/SP discounts across members)",
            "MTD": "Month-To-Date — spend from 1st of current month to today",
            "Prior Month": "Spend for the previous complete calendar month",
            "YTD": "Year-To-Date — spend from Jan 1 to today",
        },
        "accounts": {},
        "summary": {
            "total_accounts_scanned": len(accounts),
            "currency": "USD",
            "grand_total_mtd": 0.0,
            "grand_total_prior_month": 0.0,
            "grand_total_ytd": 0.0,
        }
    }

    for account in accounts:
        name = account["name"]
        account_id = account["account_id"]
        profile = account["profile"]

        if account.get("enabled") is False:
            logger.info(f"⏭️  {name} ({account_id}) — skipped (disabled)")
            continue

        logger.info(f"🔍 {name} ({account_id}) — profile: {profile}")

        session = account.get("_session") or create_session(profile)
        if not session:
            inventory["accounts"][account_id] = {"name": name, "status": "auth_failed"}
            continue

        try:
            output_dir = get_output_dir(account_id, "cost")
            writer = IncrementalWriter(output_dir, make_output_filename("cost", account_id, timestamp))
            writer.set("name", name)
            writer.set("profile_used", profile)
            writer.set("status", "in_progress")

            cost_data = scan_costs(session, writer)
            writer.set("status", "ok")

            # Add service and regional summaries to per-account file
            svc_summary_mtd = _get_service_summary(cost_data.get("mtd_by_service", []))
            svc_summary_prior = _get_service_summary(cost_data.get("prior_month_by_service", []))
            region_summary = _get_region_summary(cost_data.get("by_region", []))
            writer.set("service_summary", svc_summary_mtd)
            writer.set("prior_month_service_summary", svc_summary_prior)
            writer.set("region_summary", region_summary)
        except Exception as e:
            logger.error(f"  ❌ Cost Explorer query failed: {e}")
            inventory["accounts"][account_id] = {"name": name, "status": "error", "error": str(e)}
            continue

        account_entry = writer.get_data()

        inventory["accounts"][account_id] = account_entry
        inventory["summary"]["grand_total_mtd"] += cost_data.get("mtd_total", 0.0)
        inventory["summary"]["grand_total_prior_month"] += cost_data.get("prior_month_total", 0.0)
        inventory["summary"]["grand_total_ytd"] += cost_data.get("ytd_total", 0.0)

        # Console summary
        logger.info(f"  MTD total: ${cost_data.get('mtd_total', 0):,.2f}")
        logger.info(f"  Prior Month total: ${cost_data.get('prior_month_total', 0):,.2f}")
        logger.info(f"  YTD total: ${cost_data.get('ytd_total', 0):,.2f}")
        if cost_data.get("mtd_total", 0) > 0:
            _print_top_services(cost_data.get("mtd_by_service", []), "MTD")
        _print_top_services(cost_data.get("prior_month_by_service", []), "Prior Month")
        _print_top_regions(cost_data.get("by_region", []), "YTD")

    # Grand summary — aggregate across successfully scanned accounts only
    all_mtd_rows = []
    all_prior_rows = []
    for acct_data in inventory["accounts"].values():
        if acct_data.get("status") != "ok":
            continue
        all_mtd_rows.extend(acct_data.get("mtd_by_service", []))
        all_prior_rows.extend(acct_data.get("prior_month_by_service", []))
    grand_svc_summary = _get_service_summary(all_mtd_rows)
    grand_prior_summary = _get_service_summary(all_prior_rows)

    inventory["summary"]["grand_total_mtd"] = round(inventory["summary"]["grand_total_mtd"], 2)
    inventory["summary"]["grand_total_prior_month"] = round(inventory["summary"]["grand_total_prior_month"], 2)
    inventory["summary"]["grand_total_ytd"] = round(inventory["summary"]["grand_total_ytd"], 2)
    inventory["summary"]["total_services_used"] = grand_svc_summary["total_services_used"]
    inventory["summary"]["all_service_names"] = grand_svc_summary["all_service_names"]
    inventory["summary"]["top_15_services_mtd"] = grand_svc_summary["top_15_services"]
    inventory["summary"]["top_15_services_prior_month"] = grand_prior_summary["top_15_services"]

    logger.info("" + "=" * 60)
    logger.info("📊 GRAND SUMMARY")
    logger.info("=" * 60)
    logger.info(f"  MTD (all accounts): ${inventory['summary']['grand_total_mtd']:,.2f}")
    logger.info(f"  Prior Month (all accounts): ${inventory['summary']['grand_total_prior_month']:,.2f}")
    logger.info(f"  YTD (all accounts): ${inventory['summary']['grand_total_ytd']:,.2f}")
    logger.info(f"  Total services (Prior Month): {grand_prior_summary['total_services_used']}")
    _print_top_services(all_prior_rows, "Grand Total - Prior Month")


if __name__ == "__main__":
    run_with_timer(main)
