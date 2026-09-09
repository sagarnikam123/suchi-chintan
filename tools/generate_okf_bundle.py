#!/usr/bin/env python3
"""
OKF Bundle Generator for AWS Inventory

Reads the inventory scanner's output/ tree (inventory + cost + audit reports) and
emits an Open Knowledge Format (OKF) v0.2 bundle of markdown concepts, then
(optionally) renders a self-contained viz.html via the OKF reference-agent
visualizer.

Each AWS service concept shows:
  1. Resource summary  — count + per-region breakdown (from latest inventory)
  2. Cost              — MTD unblended cost (from cost inventory)
  3. Anomaly/Drift/Cost-reduction — waste + quick wins (from audit report)

Layouts:
  --account-wise (default)   bundle/accounts/<id>/<service>.md
  --service-wise             bundle/services/<service>/<id>.md

Usage:
    # Single account, account-wise, then visualize -> /tmp/okf/viz.html
    python tools/generate_okf_bundle.py -a 111111111111 -o /tmp/okf

    # All accounts, service-wise
    python tools/generate_okf_bundle.py --all --service-wise -o /tmp/okf

    # By name / profile
    python tools/generate_okf_bundle.py --name my-dev-account -o /tmp/okf
    python tools/generate_okf_bundle.py -p 111111111111_AdministratorAccess -o /tmp/okf

    # Skip visualization (bundle only)
    python tools/generate_okf_bundle.py -a 111111111111 -o /tmp/okf --no-visualize

    # Self-check (no AWS, no writes)
    python tools/generate_okf_bundle.py --self-check
"""

import os
import re
import sys
import glob
import json
import argparse
import subprocess
from pathlib import Path
from datetime import datetime, timezone

# Reuse the inventory-locating + JSON-loading helpers from the audit tool.
# Import is safe: audit_aws_resources only mutates sys.path at import time and
# guards main() behind __name__ == "__main__" (verified).
sys.path.insert(0, str(Path(__file__).parent))
from audit_aws_resources import find_latest_inventory, load_json  # noqa: E402

ROOT_DIR = Path(__file__).parent.parent
DEFAULT_INPUT_DIR = ROOT_DIR / "output"
DEFAULT_OKF_SRC = ROOT_DIR.parent / "knowledge-catalog" / "okf" / "src"

# Service directories that are not real AWS services to emit as concepts.
_SKIP_SERVICE_DIRS = {"cost", "k8s-workloads"}

# ponytail: heuristic maps covering the common services seen in output/. They
# cover the high-signal, high-cost services. Long-tail upgrade path: add the
# service dir key here (audit label from service_waste_breakdown[].service,
# cost keys from cost-inventory mtd_by_service[].keys). Unmatched services fall
# back to case-insensitive substring matching, then to "no match" notes (3a).
SERVICE_META = {
    # service_dir: (display, audit_label, [cost_keys])
    "ec2":              ("EC2", "EC2", ["Amazon Elastic Compute Cloud - Compute", "EC2 - Other"]),
    "ebs":              ("EBS", "EBS", ["Amazon Elastic Compute Cloud - Compute"]),
    "rds":              ("RDS", "RDS", ["Amazon Relational Database Service"]),
    "s3":               ("S3", "S3", ["Amazon Simple Storage Service"]),
    "lambda":           ("Lambda", "Lambda", ["AWS Lambda"]),
    "eks":              ("EKS", "EKS", ["Amazon Elastic Container Service for Kubernetes"]),
    "ecs":              ("ECS", "ECS", ["Amazon Elastic Container Service"]),
    "ecr":              ("ECR", "ECR", ["Amazon EC2 Container Registry (ECR)"]),
    "elb":              ("ELB", "ELB", ["Amazon Elastic Load Balancing"]),
    "efs":              ("EFS", "EFS", ["Amazon Elastic File System"]),
    "dynamodb":         ("DynamoDB", "DynamoDB", ["Amazon DynamoDB"]),
    "elasticache":      ("ElastiCache", "ElastiCache", ["Amazon ElastiCache"]),
    "opensearch":       ("OpenSearch", "OpenSearch", ["Amazon OpenSearch Service"]),
    "cloudfront":       ("CloudFront", "CloudFront", ["Amazon CloudFront"]),
    "cloudtrail":       ("CloudTrail", "CloudTrail", ["AWS CloudTrail"]),
    "cloudwatch":       ("CloudWatch", "CloudWatch", ["AmazonCloudWatch", "CloudWatch Events"]),
    "acm":              ("ACM", "ACM", ["AWS Certificate Manager"]),
    "kms":              ("KMS", None, ["AWS Key Management Service"]),
    "secrets-manager":  ("Secrets Manager", "Secrets Manager", ["AWS Secrets Manager"]),
    "sns":              ("SNS", "SNS", ["Amazon Simple Notification Service"]),
    "sqs":              ("SQS", "SQS", ["Amazon Simple Queue Service"]),
    "glue":             ("Glue", "Glue", ["AWS Glue"]),
    "athena":           ("Athena", "Athena", ["Amazon Athena"]),
    "api-gateway":      ("API Gateway", "API Gateway", ["Amazon API Gateway"]),
    "step-functions":   ("Step Functions", "Step Functions", ["AWS Step Functions"]),
    "eventbridge":      ("EventBridge", "EventBridge", ["CloudWatch Events"]),
    "backup":           ("Backup", "Backup", ["AWS Backup"]),
    "config":           ("AWS Config", "AWS Config", ["AWS Config"]),
    "mwaa":             ("MWAA", "MWAA", ["Amazon Managed Workflows for Apache Airflow"]),
    "amg":              ("Amazon Managed Grafana", "AMG", ["Amazon Managed Grafana"]),
    "amp":              ("Amazon Managed Prometheus", None, ["Amazon Managed Service for Prometheus"]),
    "nat-gateways":     ("NAT Gateway", "NAT Gateway", ["Amazon Virtual Private Cloud"]),
    "vpc-endpoints":    ("VPC Endpoints", "VPC Endpoints", ["Amazon Virtual Private Cloud"]),
    "vpc":              ("VPC", None, ["Amazon Virtual Private Cloud"]),
    "transit-gateway":  ("Transit Gateway", "Transit Gateway", ["Amazon Virtual Private Cloud"]),
    "route53":          ("Route 53", None, ["Amazon Route 53"]),
    "quicksight":       ("QuickSight", "QuickSight", ["Amazon QuickSight"]),
    "timestream":       ("Timestream", "Timestream", ["Amazon Timestream"]),
    "sagemaker":        ("SageMaker", "SageMaker", ["Amazon SageMaker"]),
    "bedrock":          ("Bedrock", "Bedrock", ["Amazon Bedrock"]),
    "ses":              ("SES", "SES", ["Amazon Simple Email Service"]),
    "ssm":              ("SSM", "SSM", ["AWS Systems Manager"]),
    "documentdb":       ("DocumentDB", "DocumentDB", ["Amazon DocumentDB (with MongoDB compatibility)"]),
    "glacier":          ("Glacier", None, ["Amazon Glacier"]),
    "waf":              ("WAF", "WAF", ["AWS WAF"]),
    "security-hub":     ("Security Hub", None, ["AWS Security Hub"]),
    "security-lake":    ("Security Lake", "Security Lake", ["Amazon Security Lake"]),
    "guardduty":        ("GuardDuty", None, ["Amazon GuardDuty"]),
    "xray":             ("X-Ray", None, ["AWS X-Ray"]),
    "amplify":          ("Amplify", "Amplify", ["AWS Amplify"]),
    "apprunner":        ("App Runner", None, ["AWS App Runner"]),
}


# ============================================================
#  Account resolution
# ============================================================

def _account_dirs(input_dir):
    """Every output/<12-digit-account-id>/ directory."""
    out = []
    for p in sorted(Path(input_dir).iterdir()):
        if p.is_dir() and re.fullmatch(r"\d{12}", p.name):
            out.append(p)
    return out


def _read_account_identity(account_dir):
    """Return (name, profile_used) from any inventory JSON in the account dir."""
    for jf in glob.glob(str(account_dir / "*" / "*.json")):
        data = load_json(jf)
        if isinstance(data, dict) and (data.get("name") or data.get("profile_used")):
            return data.get("name"), data.get("profile_used")
    return None, None


def resolve_accounts(input_dir, *, account=None, name=None, profile=None, all_accounts=False):
    """Resolve the CLI selectors to a list of account directories.

    Exactly one selector mode must be active. Raises ValueError on ambiguous or
    empty selection (trust-boundary validation).
    """
    input_dir = Path(input_dir)
    if not input_dir.is_dir():
        raise ValueError(f"Input dir not found: {input_dir}")

    selectors = [bool(account), bool(name), bool(profile), bool(all_accounts)]
    if sum(selectors) != 1:
        raise ValueError(
            "Choose exactly one of: -a/--account, --name, -p/--profile, --all"
        )

    all_dirs = _account_dirs(input_dir)
    if all_accounts:
        if not all_dirs:
            raise ValueError(f"No account dirs (output/<12 digits>/) under {input_dir}")
        return all_dirs

    if account:
        d = input_dir / account
        if not d.is_dir():
            raise ValueError(f"Account dir not found: {d}")
        return [d]

    # name / profile require reading inventory identity
    matched = []
    for d in all_dirs:
        acct_name, prof = _read_account_identity(d)
        if name and acct_name == name:
            matched.append(d)
        elif profile and prof and prof.startswith(profile):
            matched.append(d)
    sel = f"name={name!r}" if name else f"profile={profile!r}"
    if not matched:
        raise ValueError(f"No account matched {sel} under {input_dir}")
    if len(matched) > 1:
        raise ValueError(
            f"{sel} matched multiple accounts: {', '.join(d.name for d in matched)}; "
            "use -a/--account for an unambiguous selection"
        )
    return matched


# ============================================================
#  Frontmatter + markdown emission
# ============================================================

def _yaml_scalar(v):
    """Emit a YAML-safe scalar for flat frontmatter values."""
    s = str(v)
    if s == "" or re.search(r'[:#\[\]{}",&*!|>%@`]', s) or s != s.strip():
        return json.dumps(s)  # double-quoted, JSON is a valid YAML 1.2 subset
    return s


def render_frontmatter(fm):
    """Render a flat/one-level frontmatter dict to a YAML block.

    Supports scalars, list-of-scalars, and one level of nested mapping
    (for `generated: {by, at}`). ponytail: intentionally handles only the shapes
    this generator emits — upgrade path: use pyyaml (available via OKF) if
    deeper nesting is ever needed.
    """
    lines = ["---"]
    for k, v in fm.items():
        if isinstance(v, dict):
            inner = ", ".join(f"{ik}: {_yaml_scalar(iv)}" for ik, iv in v.items())
            lines.append(f"{k}: {{ {inner} }}")
        elif isinstance(v, (list, tuple)):
            inner = ", ".join(_yaml_scalar(x) for x in v)
            lines.append(f"{k}: [{inner}]")
        else:
            lines.append(f"{k}: {_yaml_scalar(v)}")
    lines.append("---")
    return "\n".join(lines)


def write_concept(path, fm, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    text = render_frontmatter(fm) + "\n\n" + body.rstrip() + "\n"
    path.write_text(text, encoding="utf-8")


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fmt_usd(x):
    return f"${x:,.2f}"


def _as_float(value, default=0.0):
    """Normalize numeric source fields without failing the whole bundle."""
    try:
        return float(value) if value is not None else default
    except (TypeError, ValueError):
        return default


# ============================================================
#  Data extraction (inventory / cost / audit)
# ============================================================

def load_audit(input_dir, account_id):
    path = Path(input_dir) / "audit" / f"audit-report-{account_id}.json"
    return load_json(path) if path.exists() else None


def load_cost(account_dir):
    files = sorted(glob.glob(str(Path(account_dir) / "cost" / "cost-inventory-*.json")),
                   key=lambda f: Path(f).stat().st_mtime, reverse=True)
    return load_json(files[0]) if files else None


def count_resources_by_region(account_dir, service):
    """Return (total, {region: count}) from the latest inventory for a service."""
    path = find_latest_inventory(Path(account_dir), service)
    if not path:
        return None
    data = load_json(path)
    if not isinstance(data, dict):
        return None
    regions = data.get("regions")
    per_region = {}
    total = 0
    if isinstance(regions, dict):
        for region, items in regions.items():
            n = len(items) if isinstance(items, (list, dict)) else (1 if items else 0)
            per_region[region] = n
            total += n
    return total, per_region


def cost_for_service(cost_data, service):
    """Sum MTD unblended cost for a service's cost keys. Returns (usd, currency)
    or None when no key matched."""
    if not isinstance(cost_data, dict):
        return None
    rows = cost_data.get("mtd_by_service") or []
    if not isinstance(rows, list):
        return None
    meta = SERVICE_META.get(service)
    keys = set(meta[2]) if meta else set()
    total = 0.0
    currency = "USD"
    matched = False
    for row in rows:
        if not isinstance(row, dict):
            continue
        row_keys = row.get("keys") or []
        label = row_keys[0] if isinstance(row_keys, list) and row_keys else ""
        hit = label in keys
        if not hit and not meta:
            # Fallback: case-insensitive substring on the service dir name.
            hit = service.replace("-", " ").lower() in label.lower()
        if hit:
            total += _as_float(row.get("unblended_cost"))
            currency = row.get("currency") or currency
            matched = True
    return (total, currency) if matched else None


def audit_for_service(audit_data, service):
    """Return (waste_row_or_None, [quick_win_rows]) matched to a service dir."""
    if not isinstance(audit_data, dict):
        return None, []
    meta = SERVICE_META.get(service)
    label = meta[1] if meta else None
    display = meta[0] if meta else service

    def _match(svc_label):
        if not svc_label:
            return False
        if label and svc_label == label:
            return True
        # substring fallback both directions
        return (svc_label.lower() in display.lower()) or (display.lower() in svc_label.lower())

    waste = None
    waste_rows = audit_data.get("service_waste_breakdown") or []
    if not isinstance(waste_rows, list):
        waste_rows = []
    for row in waste_rows:
        if not isinstance(row, dict):
            continue
        if _match(row.get("service")):
            waste = row
            break
    quick_wins = audit_data.get("quick_wins") or []
    if not isinstance(quick_wins, list):
        quick_wins = []
    wins = [w for w in quick_wins if isinstance(w, dict) and _match(w.get("service"))]
    return waste, wins


# ============================================================
#  Concept builders
# ============================================================

def build_service_concept(account_dir, account_id, service, audit_data, cost_data,
                          hub_link=None):
    """Return (frontmatter, body) for one AWS service in one account.

    hub_link: optional relative link (display, path) back to the parent concept
    (account hub or service rollup) so the visualizer draws a graph edge.
    """
    display = SERVICE_META.get(service, (service.upper(), None, []))[0]

    fm = {
        "type": "AWS Service",
        "title": f"{display} — {account_id}",
        "description": f"{display} resources, cost, and findings for AWS account {account_id}.",
        "tags": [service, account_id, "aws"],
        "generated": {"by": "human:generate_okf_bundle", "at": _now_iso()},
        "status": "stable",
    }

    parts = [f"# {display} ({account_id})", ""]

    # (1) Resource summary
    parts.append("## Resource Summary")
    res = count_resources_by_region(account_dir, service)
    if res is None:
        parts.append("_No inventory file found for this service._")
    else:
        total, per_region = res
        parts.append(f"- **Total resources**: {total}")
        active = {r: n for r, n in per_region.items() if n}
        if active:
            parts.append("- **Per-region**:")
            for region in sorted(active):
                parts.append(f"  - `{region}`: {active[region]}")
        else:
            parts.append("- No resources found in any region.")
    parts.append("")

    # (2) Cost
    parts.append("## Cost (Month-to-Date)")
    cost = cost_for_service(cost_data, service)
    if cost is None:
        parts.append("_No cost matched for this service._")
    else:
        usd, currency = cost
        parts.append(f"- **MTD unblended cost**: {_fmt_usd(usd)} {currency}")
    parts.append("")

    # (3) Anomaly / Drift / Cost-reduction
    parts.append("## Anomaly / Drift / Cost-Reduction")
    waste, wins = audit_for_service(audit_data, service)
    if not waste and not wins:
        parts.append("_No findings for this service._")
    else:
        if waste:
            parts.append(
                f"- **Estimated waste**: {_fmt_usd(_as_float(waste.get('waste_monthly')))}/mo "
                f"({_fmt_usd(_as_float(waste.get('waste_annual')))}/yr) across "
                f"{waste.get('count', 0)} finding(s)."
            )
        if wins:
            parts.append("")
            parts.append("### Quick Wins")
            parts.append("| Est. Savings | Region | Resource | Issue | Action |")
            parts.append("| :--- | :--- | :--- | :--- | :--- |")
            for w in wins:
                save = w.get("est_monthly_waste_usd")
                save_s = f"${save}/mo" if save is not None else "—"
                parts.append(
                    f"| {save_s} | {w.get('region','—')} | {w.get('resource','—')} "
                    f"| {w.get('issue','—')} | {w.get('action','—')} |"
                )
    parts.append("")
    if hub_link:
        parts.append(f"[← {hub_link[0]}]({hub_link[1]})")
        parts.append("")
    return fm, "\n".join(parts)


# ponytail: the visualizer skips any file named index.md as a graph node, so the
# account hub is emitted as _account.md (a real typed node) and index.md is kept
# as a plain directory listing. Upgrade path: if OKF changes that rule, collapse
# these back into index.md.
_ACCOUNT_CONCEPT = "_account.md"
_ROLLUP_CONCEPT = "_rollup.md"


def build_account_concept(account_id, audit_data, service_links):
    """Return (frontmatter, body) for an AWS Account concept node.

    service_links: list of (display, relative_md_path).
    """
    fm = {
        "type": "AWS Account",
        "title": f"AWS Account {account_id}",
        "description": f"Inventory, cost, and audit summary for AWS account {account_id}.",
        "tags": [account_id, "aws", "account"],
        "generated": {"by": "human:generate_okf_bundle", "at": _now_iso()},
        "status": "stable",
    }
    parts = [f"# AWS Account `{account_id}`", ""]

    if isinstance(audit_data, dict):
        waste = _as_float(audit_data.get("estimated_monthly_waste_usd"))
        parts.append("## Summary")
        parts.append(f"- **Estimated monthly waste**: {_fmt_usd(waste)}/mo "
                     f"({_fmt_usd(waste * 12)}/yr)")
        parts.append(f"- **Total findings**: {audit_data.get('total_findings', 0)}")
        sev = audit_data.get("findings_by_severity") or {}
        if sev:
            parts.append("- **By severity**: " + " · ".join(
                f"{k}: {v}" for k, v in sev.items()))
        cat = audit_data.get("findings_by_category") or {}
        if cat:
            parts.append("- **By category**: " + " · ".join(
                f"{k}: {v}" for k, v in cat.items()))
        parts.append("")
    else:
        parts.append("_No audit report found for this account._")
        parts.append("")

    parts.append("## Services")
    if service_links:
        for display, rel in sorted(service_links):
            parts.append(f"- [{display}]({rel})")
    else:
        parts.append("_No service inventories found._")
    parts.append("")
    return fm, "\n".join(parts)


# ============================================================
#  Bundle writers
# ============================================================

def _services_in_account(account_dir):
    """Service dirs present in an account that hold at least one JSON."""
    out = []
    for p in sorted(Path(account_dir).iterdir()):
        if not p.is_dir() or p.name in _SKIP_SERVICE_DIRS:
            continue
        if glob.glob(str(p / "*.json")):
            out.append(p.name)
    return out


def generate_account_wise(bundle_root, input_dir, account_dirs):
    bundle_root = Path(bundle_root)
    account_entries = []  # (account_id, rel_account_concept_path)
    for account_dir in account_dirs:
        account_id = account_dir.name
        account_bundle_dir = bundle_root / "accounts" / account_id
        audit_data = load_audit(input_dir, account_id)
        cost_data = load_cost(account_dir)
        service_links = []
        for service in _services_in_account(account_dir):
            fm, body = build_service_concept(
                account_dir, account_id, service, audit_data, cost_data,
                hub_link=(f"AWS Account {account_id}", _ACCOUNT_CONCEPT))
            svc_path = account_bundle_dir / f"{service}.md"
            write_concept(svc_path, fm, body)
            display = SERVICE_META.get(service, (service.upper(),))[0]
            service_links.append((display, f"{service}.md"))

        # _account.md is a graph node; index.md remains reserved navigation.
        fm, body = build_account_concept(account_id, audit_data, service_links)
        write_concept(account_bundle_dir / _ACCOUNT_CONCEPT, fm, body)
        _write_directory_index(
            account_bundle_dir,
            f"AWS Account {account_id}",
            [(f"Account summary: {account_id}", _ACCOUNT_CONCEPT), *service_links],
        )
        account_entries.append((account_id, f"accounts/{account_id}/{_ACCOUNT_CONCEPT}"))
    _write_root_index(bundle_root, "AWS Accounts", account_entries)
    return account_entries


def generate_service_wise(bundle_root, input_dir, account_dirs):
    bundle_root = Path(bundle_root)
    # service -> list of (account_id, waste_monthly)
    service_accounts = {}
    for account_dir in account_dirs:
        account_id = account_dir.name
        audit_data = load_audit(input_dir, account_id)
        cost_data = load_cost(account_dir)
        for service in _services_in_account(account_dir):
            # The rollup concept is emitted after all account details but its
            # relative location is already known, so detail -> rollup edges work.
            fm, body = build_service_concept(
                account_dir, account_id, service, audit_data, cost_data,
                hub_link=(f"{SERVICE_META.get(service, (service.upper(),))[0]} rollup", _ROLLUP_CONCEPT))
            detail_path = bundle_root / "services" / service / f"{account_id}.md"
            write_concept(detail_path, fm, body)
            waste, _ = audit_for_service(audit_data, service)
            wm = _as_float(waste.get("waste_monthly")) if waste else 0.0
            service_accounts.setdefault(service, []).append((account_id, wm))

    service_entries = []  # (display, rel_rollup_concept_path)
    for service, accts in service_accounts.items():
        service_dir = bundle_root / "services" / service
        display = SERVICE_META.get(service, (service.upper(),))[0]
        fm = {
            "type": "AWS Service",
            "title": f"{display} (all accounts)",
            "description": f"Cross-account rollup for {display}.",
            "tags": [service, "aws", "rollup"],
            "generated": {"by": "human:generate_okf_bundle", "at": _now_iso()},
            "status": "stable",
        }
        total_waste = sum(w for _, w in accts)
        details = [(account_id, f"{account_id}.md") for account_id, _ in sorted(accts)]
        parts = [f"# {display} — All Accounts", ""]
        parts.append(f"- **Accounts with {display}**: {len(accts)}")
        parts.append(f"- **Total estimated waste**: {_fmt_usd(total_waste)}/mo")
        parts.append("")
        parts.append("## Per-Account Detail")
        for account_id, wm in sorted(accts):
            parts.append(f"- [{account_id}]({account_id}.md) — {_fmt_usd(wm)}/mo waste")
        parts.append("")
        write_concept(service_dir / _ROLLUP_CONCEPT, fm, "\n".join(parts))
        _write_directory_index(
            service_dir,
            f"{display} — All Accounts",
            [(f"Cross-account rollup: {display}", _ROLLUP_CONCEPT), *details],
        )
        service_entries.append((display, f"services/{service}/{_ROLLUP_CONCEPT}"))
    _write_root_index(bundle_root, "AWS Services", service_entries)
    return service_entries


def _write_directory_index(directory, heading, entries):
    """Write a navigation-only reserved index.md for one OKF directory."""
    parts = [f"# {heading}", ""]
    for label, rel in sorted(entries):
        parts.append(f"- [{label}]({rel})")
    parts.append("")
    Path(directory).mkdir(parents=True, exist_ok=True)
    (Path(directory) / "index.md").write_text("\n".join(parts) + "\n", encoding="utf-8")


def _write_root_index(bundle_root, heading, entries):
    parts = [f"# OKF Bundle: {heading}", ""]
    parts.append(f"Generated {_now_iso()} by `generate_okf_bundle.py`.")
    parts.append("")
    parts.append(f"## {heading}")
    for label, rel in sorted(entries):
        parts.append(f"- [{label}]({rel})")
    parts.append("")
    (Path(bundle_root)).mkdir(parents=True, exist_ok=True)
    (Path(bundle_root) / "index.md").write_text("\n".join(parts) + "\n", encoding="utf-8")


# ============================================================
#  Visualization
# ============================================================

def _resolve_okf_python(okf_python, okf_src):
    """Prefer the OKF repo venv python if present, else the given interpreter."""
    if okf_python and okf_python != sys.executable:
        return okf_python
    venv_py = Path(okf_src).parent / ".venv" / "bin" / "python"
    if venv_py.exists():
        return str(venv_py)
    return okf_python or sys.executable


def visualize(bundle_root, okf_src, okf_python, name=None):
    okf_src = Path(okf_src)
    if not (okf_src / "reference_agent").is_dir():
        raise ValueError(
            f"OKF source not found at {okf_src}. "
            f"Pass --okf-src pointing to knowledge-catalog/okf/src."
        )
    py = _resolve_okf_python(okf_python, okf_src)
    out_html = Path(bundle_root) / "viz.html"
    cmd = [py, "-m", "reference_agent", "visualize",
           "--bundle", str(bundle_root), "--out", str(out_html)]
    if name:
        cmd += ["--name", name]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(okf_src) + os.pathsep + env.get("PYTHONPATH", "")
    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"Visualization failed (exit {result.returncode}).\n"
            f"cmd: {' '.join(cmd)}\nstderr:\n{result.stderr}"
        )
    if not out_html.exists() or out_html.stat().st_size == 0:
        raise RuntimeError(f"Visualizer reported success but {out_html} is missing/empty.")
    return out_html


# ============================================================
#  CLI
# ============================================================

def build_parser():
    p = argparse.ArgumentParser(
        prog="generate_okf_bundle",
        description="Generate an OKF bundle (and viz.html) from AWS inventory output.",
    )
    sel = p.add_argument_group("account selection (choose exactly one)")
    sel.add_argument("-a", "--account", help="Single AWS account id (output dir name).")
    sel.add_argument("--name", help="Single AWS account name (inventory 'name').")
    sel.add_argument("-p", "--profile", help="Single AWS profile prefix (inventory 'profile_used').")
    sel.add_argument("--all", action="store_true", help="All AWS accounts under the input dir.")
    sel.add_argument("--max-accounts", type=int,
                     help="With --all, process the first N sorted account ids (useful for a sample bundle).")

    layout = p.add_mutually_exclusive_group()
    layout.add_argument("--account-wise", action="store_true",
                        help="Organize per account (default).")
    layout.add_argument("--service-wise", action="store_true",
                        help="Organize per service (each service lists accounts).")

    p.add_argument("-o", "--output-dir", help="Bundle output directory.")
    p.add_argument("--input-dir", default=str(DEFAULT_INPUT_DIR),
                   help=f"Inventory output dir (default: {DEFAULT_INPUT_DIR}).")
    p.add_argument("--visualize", dest="visualize", action="store_true", default=True,
                   help="Generate viz.html after writing the bundle (default).")
    p.add_argument("--no-visualize", dest="visualize", action="store_false",
                   help="Skip viz.html generation.")
    p.add_argument("--okf-src", default=str(DEFAULT_OKF_SRC),
                   help=f"Path to OKF reference-agent src (default: {DEFAULT_OKF_SRC}).")
    p.add_argument("--okf-python", default=sys.executable,
                   help="Python interpreter for the OKF visualizer (default: this one, "
                        "falling back to <okf>/.venv/bin/python if present).")
    p.add_argument("--self-check", action="store_true",
                   help="Run built-in assert-based checks and exit.")
    p.add_argument("--check-links", metavar="BUNDLE_DIR",
                   help="Verify every relative markdown link in a bundle resolves; exit.")
    return p


_LINK_RE = re.compile(r"\]\(([^)\s]+\.md)(?:#[^)]*)?\)")


def check_links(bundle_dir):
    """Assert every relative .md link in the bundle resolves to a real file.

    Returns the number of links checked. Raises AssertionError on the first
    broken link (trust-boundary check for the emitted cross-links).
    """
    bundle_dir = Path(bundle_dir)
    checked = 0
    for md in bundle_dir.rglob("*.md"):
        for m in _LINK_RE.finditer(md.read_text(encoding="utf-8")):
            target = m.group(1)
            if "://" in target or target.startswith("/"):
                continue
            resolved = (md.parent / target).resolve()
            assert resolved.exists(), f"broken link in {md}: {target} -> {resolved}"
            checked += 1
    return checked


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.self_check:
        return _self_check()

    if args.check_links:
        n = check_links(args.check_links)
        print(f"check-links: OK ({n} link(s) resolved)")
        return 0

    if not args.output_dir:
        print("ERROR: -o/--output-dir is required.", file=sys.stderr)
        return 2

    try:
        account_dirs = resolve_accounts(
            args.input_dir, account=args.account, name=args.name,
            profile=args.profile, all_accounts=args.all)
        if args.max_accounts is not None:
            if not args.all:
                raise ValueError("--max-accounts can only be used with --all")
            if args.max_accounts < 1:
                raise ValueError("--max-accounts must be at least 1")
            account_dirs = account_dirs[:args.max_accounts]
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    print(f"Resolved {len(account_dirs)} account(s): "
          + ", ".join(d.name for d in account_dirs), file=sys.stderr)

    bundle_root = Path(args.output_dir)
    if args.service_wise:
        entries = generate_service_wise(bundle_root, args.input_dir, account_dirs)
        layout = "service-wise"
    else:
        entries = generate_account_wise(bundle_root, args.input_dir, account_dirs)
        layout = "account-wise"
    print(f"Wrote {layout} bundle with {len(entries)} top-level entr(ies) → {bundle_root}",
          file=sys.stderr)

    if args.visualize:
        try:
            out_html = visualize(bundle_root, args.okf_src, args.okf_python,
                                 name=f"AWS Inventory ({layout})")
            print(f"Wrote visualization → {out_html}", file=sys.stderr)
        except (ValueError, RuntimeError) as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
    return 0


# ============================================================
#  Self-check (no framework, no fixtures)
# ============================================================

def _self_check():
    # Frontmatter rendering: scalar, list, nested, and a value needing quoting.
    fm = {"type": "AWS Service", "title": "EC2: prod", "tags": ["ec2", "aws"],
          "generated": {"by": "human:x", "at": "2026-01-01T00:00:00Z"}}
    rendered = render_frontmatter(fm)
    assert rendered.startswith("---\n") and rendered.endswith("\n---"), rendered
    assert "type: AWS Service" in rendered
    assert 'title: "EC2: prod"' in rendered, "colon-containing title must be quoted"
    assert "tags: [ec2, aws]" in rendered
    # Frontmatter must round-trip through a YAML parser to the original dict.
    body_yaml = "\n".join(rendered.splitlines()[1:-1])
    import yaml  # available via the OKF toolchain; stdlib-adjacent for this repo
    parsed = yaml.safe_load(body_yaml)
    assert parsed == fm, f"frontmatter did not round-trip: {parsed}"

    # cost matching by explicit key
    cost = {"mtd_by_service": [
        {"keys": ["AWS Lambda"], "unblended_cost": 1.5, "currency": "USD"},
        {"keys": ["Amazon Simple Storage Service"], "unblended_cost": 2.0, "currency": "USD"},
    ]}
    assert cost_for_service(cost, "lambda") == (1.5, "USD")
    assert cost_for_service(cost, "s3") == (2.0, "USD")
    assert cost_for_service(cost, "ec2") is None  # no matching key -> explicit None (3a)

    # audit matching + waste extraction
    audit = {
        "service_waste_breakdown": [{"service": "NAT Gateway", "count": 3,
                                     "waste_monthly": 96.0, "waste_annual": 1152.0}],
        "quick_wins": [{"category": "cost", "service": "NAT Gateway", "region": "us-east-1",
                        "resource": "nat-abc", "issue": "idle", "action": "delete",
                        "est_monthly_waste_usd": 32}],
    }
    waste, wins = audit_for_service(audit, "nat-gateways")
    assert waste and waste["waste_monthly"] == 96.0, waste
    assert len(wins) == 1 and wins[0]["resource"] == "nat-abc"

    # account concept body contains the waste total
    _, body = build_account_concept("123456789012",
                                  {"estimated_monthly_waste_usd": 100.0,
                                   "total_findings": 5,
                                   "findings_by_severity": {"high": 5},
                                   "findings_by_category": {"cost": 5}},
                                  [("EC2", "ec2.md")])
    assert "$100.00/mo" in body and "[EC2](ec2.md)" in body, body

    # resolver rejects ambiguous/empty selection
    for bad in (dict(), dict(account="x", all_accounts=True)):
        try:
            resolve_accounts(DEFAULT_INPUT_DIR, **bad)
            raise AssertionError(f"expected ValueError for {bad}")
        except ValueError:
            pass

    print("self-check: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
