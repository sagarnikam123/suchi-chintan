# tools/

Post-processing and utility scripts that run against the inventory JSON written
to `output/<account_id>/<service>/` by the scanners in `inventory/`. Most tools
read those files; a couple (AMG backup) also call live AWS APIs.

## Setup

Run from the **repo root** so the `common` module and `output/` paths resolve:

```bash
python -m venv .venv && source .venv/bin/activate
pip install boto3 pyyaml requests openpyxl
```

- `requests` — needed by `backup_amg_workspaces.py`
- `openpyxl` — needed by `get_eks_workloads_xls.py`

For tools that hit AWS live (`backup_amg_workspaces.py`), authenticate first, e.g.
`aws sso login --profile <profile>`.

## Scripts

| Script | Purpose |
|---|---|
| `audit_aws_resources.py` | Security / cost / reliability / drift findings from inventory JSON |
| `backup_amg_workspaces.py` | Back up Amazon Managed Grafana workspaces before a version upgrade (live API) |
| `check_eks_vpc_connectivity.py` | Map EKS clusters to VPCs and compute cross-cluster connectivity |
| `generate_okf_bundle.py` | Generate Open Knowledge Framework (OKF) documentation bundle and interactive knowledge graph |
| `generate_service_cost_breakdown.py` | Generate comprehensive per-service tabular charts and markdown reports from cost inventory |
| `get_eks_unique_deployments.py` | List unique deployment/service names from a k8s-workloads inventory |
| `get_eks_unique_namespaces.py` | List unique namespace names from a k8s-workloads inventory |
| `get_eks_workloads_xls.py` | Excel report of namespaces → deployments → clusters |
| `prune_inventory_files.py` | Keep the newest inventory file(s) per service folder, delete older |

## How to run — one example each

**audit_aws_resources.py** — audit a specific account or all accounts:
```bash
python tools/audit_aws_resources.py -a 123456789012
python tools/audit_aws_resources.py --all
```

**backup_amg_workspaces.py** — back up all 9.4 workspaces for an account before upgrading:
```bash
python tools/backup_amg_workspaces.py -p 123456789012_AdministratorAccess --only-version 9.4
```

**check_eks_vpc_connectivity.py** — analyze connectivity across all accounts or for a single account:
```bash
python tools/check_eks_vpc_connectivity.py
python tools/check_eks_vpc_connectivity.py -a 123456789012
```

**generate_okf_bundle.py** — build OKF documentation bundle and interactive visualization:
```bash
python tools/generate_okf_bundle.py -a 123456789012 -o output/okf/account-123456789012
python tools/generate_okf_bundle.py --all --service-wise -o output/okf/all-services
```

**generate_service_cost_breakdown.py** — generate per-service tabular cost markdown reports:
```bash
python tools/generate_service_cost_breakdown.py                         # automatically scan ALL accounts in output/
python tools/generate_service_cost_breakdown.py -a 123456789012        # by account ID (-a / -id / --id)
python tools/generate_service_cost_breakdown.py -p 123456789012_Admin  # by profile name
python tools/generate_service_cost_breakdown.py --path output/123456789012/cost/  # by directory
python tools/generate_service_cost_breakdown.py -i output/123456789012/cost/cost-inventory-YYYYMMDD-HHMMSS.json
# Outputs saved to: output/cost-breakdown/<account_id>/service-cost-breakdown-<account_id>-<timestamp>.md
```

**get_eks_unique_deployments.py** — list unique deployments from a workloads inventory:
```bash
python tools/get_eks_unique_deployments.py -i output/123456789012/k8s-workloads/k8s-workloads-inventory-20260101-000000.json
```

**get_eks_unique_namespaces.py** — list unique namespaces from a workloads inventory:
```bash
python tools/get_eks_unique_namespaces.py -i output/123456789012/k8s-workloads/k8s-workloads-inventory-20260101-000000.json
```

**get_eks_workloads_xls.py** — build an Excel report from a workloads inventory:
```bash
python tools/get_eks_workloads_xls.py --input output/123456789012/k8s-workloads/k8s-workloads-inventory-20260101-000000.json
```

**prune_inventory_files.py** — preview which older inventory files would be deleted:
```bash
python tools/prune_inventory_files.py -a 123456789012 --dry-run
```

**Tests** — run the offline self-checks in `tests/`:
```bash
pytest tests/
python tests/test_backup_amg_workspaces.py
```

## Notes

- Tools accept `-p/--profile` (raw AWS profile) or `-a/--account` (resolved via
  `conf/accounts.yaml`); read-only tools that only parse `output/` need neither.
- `backup_amg_workspaces.py` mints a short-lived Grafana service-account token,
  exports over the HTTP API, then deletes it — no credentials are persisted. Data
  source secrets (`secureJsonData`) are never returned by Grafana, so record those
  separately if you plan to restore.

