# suchi-chintan

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python: 3.9+](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![AWS SDK: boto3](https://img.shields.io/badge/AWS%20SDK-boto3-orange.svg)](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
[![CI](https://github.com/sagarnikam123/suchi-chintan/actions/workflows/ci.yml/badge.svg)](https://github.com/sagarnikam123/suchi-chintan/actions/workflows/ci.yml)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)

**suchi-chintan** is an automated cloud governance and discovery tool designed to catalog AWS resources across multiple accounts and regions, analyze utilization patterns, detect financial waste, and guide remediation.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Features](#features)
- [Quick Start](#quick-start)
  - [Run All Scanners](#run-all-scanners)
- [Services Covered](#services-covered)
- [Tools & Post-Processing](#tools--post-processing)
  - [Resource Audit](#resource-audit)
  - [Service Cost Breakdown](#service-cost-breakdown)
  - [EKS Workload Analysis](#eks-workload-analysis)
  - [OKF Bundle Generation](#okf-bundle-generation)
- [Output Structure](#output-structure)
- [Configuration & Credentials](#configuration--credentials)
  - [conf/accounts.yaml](#confaccountsyaml)
  - [AWS Credentials & Permissions](#aws-credentials--permissions)
- [Architecture](#architecture)
- [Adding a New Scanner](#adding-a-new-scanner)
- [Documentation Index](#documentation-index)
- [AWS Cost & Safety Disclaimer](#aws-cost--safety-disclaimer)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

---

## How It Works

The framework operates in three core phases:

- **Suchi - The Inventory**: Scans and compiles a comprehensive, crash-safe catalog of active AWS services and configurations across accounts and regions.
- **Chintan - The Reflection**: Evaluates gathered inventories against utilization, security, drift, and pricing metrics to surface idle compute, unattached storage, orphaned networking resources, and misconfigurations.
- **Kruti - The Action**: Generates actionable audit reports, service cost breakdowns, and structured bundles to eliminate infrastructure sprawl.

---

## Features

- **70+ AWS Service Scanners**: Comprehensive coverage across Compute, Storage, Networking, Database, Security, Analytics, AI/ML, and Observability.
- **Multi-Account & Multi-Region**: Automated multi-account scanning via `conf/accounts.yaml` or ad-hoc scanning via `--profile`.
- **Crash-Safe Incremental Writes**: Data is flushed to disk after each region and query — no data is lost on unexpected interruptions.
- **Concurrent Region Scanning**: Uses `ThreadPoolExecutor` for high-throughput multi-region collection.
- **Standardized CLI**: Consistent flags (`--account`, `--profile`, `--region`, `--output-dir`) across all scanner scripts.
- **Rich Post-Processing**: Includes offline auditing (60+ checks), cost breakdown visualizations, EKS connectivity mapping, and OKF bundle generation.
- **Zero In-Memory Sprawl**: Streaming JSON dumps with account-isolated folder hierarchies.

---

## Quick Start

### Prerequisites
- Python 3.9 or higher
- Valid AWS credentials configured in `~/.aws/credentials` or `~/.aws/config`

```bash
# 1. Clone the repository
git clone https://github.com/sagarnikam123/suchi-chintan.git
cd suchi-chintan

# 2. Set up virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Configure accounts
cp conf/accounts.yaml.example conf/accounts.yaml
# Edit conf/accounts.yaml with your account IDs and profile names

# 4. Run an individual scanner
# Single service using default AWS CLI profile
python inventory/get_ec2_inventory.py

# Single account (matching name in conf/accounts.yaml)
python inventory/get_ec2_inventory.py -a "Production"

# Single profile and specific region
python inventory/get_ec2_inventory.py -p my_aws_profile -r us-east-1
```

### Run All Scanners

`run_inventory.sh` runs all scanners for an account concurrently (batching N at a time). A failure in any single scanner logs a warning and does not interrupt the remaining scan.

```bash
# Configure environment overrides
cp conf/.env.example conf/.env

# Run all scanners (uses AWS CLI [default] profile if conf/.env is unset)
./run_inventory.sh

# Or override parameters inline
AWS_PROFILE=123456789012_AdministratorAccess PARALLEL=4 ./run_inventory.sh
```

> For full execution options, runtime filters (`ONLY`, `SKIP`), and arguments, see [docs/running-all-scanners.md](docs/running-all-scanners.md).

---

## Services Covered

| Category | Supported Services & Scanners |
|---|---|
| **Compute** | EC2, EBS, ECS, EKS, Lambda, EMR, App Runner, WorkSpaces |
| **Storage** | S3, EFS, FSx, Glacier, AWS Backup |
| **Networking** | VPC, ELB (ALB/NLB), NAT Gateway, Transit Gateway, VPC Endpoints, Direct Connect, Global Accelerator, Route 53, CloudFront |
| **Database** | RDS, DynamoDB, ElastiCache, DocumentDB, Redshift, Timestream |
| **Security & Identity** | IAM, KMS, Secrets Manager, WAF, GuardDuty, Security Hub, Inspector, ACM, Security Lake |
| **Analytics** | Athena, Glue, Kinesis (+ Firehose), MSK, QuickSight, SageMaker |
| **Application Integration** | API Gateway, SQS, SNS, SES, Step Functions, EventBridge, Amplify |
| **AI / Machine Learning** | Bedrock (Models, Agents, Knowledge Bases, Guardrails), Bedrock AgentCore |
| **Management & Governance** | CloudWatch, CloudTrail, AWS Config, Systems Manager (SSM), CodeBuild, AWS Health |
| **Observability** | CloudWatch (Logs, Alarms, Dashboards), X-Ray, AMP (Managed Prometheus), AMG (Managed Grafana), OpenSearch, Synthetics, RUM, Internet Monitor, Application Signals (*see [docs/aws-observability-services.md](docs/aws-observability-services.md)*) |
| **Cost Management** | Cost Explorer (MTD, YTD, monthly by service, region, usage type, and purchase option) |
| **Migration & Orchestration** | DMS, MWAA (Managed Apache Airflow) |

---

## Tools & Post-Processing

The `tools/` directory provides offline post-processing scripts that analyze the JSON data in `output/` without issuing additional AWS API calls (unless `--live-pricing` is selected).

| Script | Description |
|---|---|
| `audit_aws_resources.py` | Comprehensive multi-category audit (Security, Cost, Reliability, Drift) |
| `generate_service_cost_breakdown.py` | Generates service-by-service markdown tables and cost charts |
| `check_eks_vpc_connectivity.py` | Maps EKS clusters to VPCs, TGWs, and peering routes |
| `get_eks_unique_deployments.py` | Lists unique Kubernetes deployments/services from scanned workloads |
| `get_eks_unique_namespaces.py` | Extracts Kubernetes namespace mappings with filter rules |
| `get_eks_workloads_xls.py` | Exports EKS workload topology to an Excel sheet |
| `generate_okf_bundle.py` | Packages scanned inventory into OKF-compliant documentation bundles |
| `prune_inventory_files.py` | Retains latest N scan outputs per service folder, pruning older runs |

### Resource Audit

Run 60+ automated audit checks across security, financial waste, reliability, and configuration drift:

```bash
# Full audit for an account
python tools/audit_aws_resources.py -a 111111111111

# Audit specific category (security | cost | reliability | drift)
python tools/audit_aws_resources.py -a 111111111111 --category cost

# Use live AWS Pricing API for exact per-region cost calculations
python tools/audit_aws_resources.py -a 111111111111 --live-pricing -p my_aws_profile

# Output results to JSON and Markdown reports
python tools/audit_aws_resources.py -a 111111111111 --json
```

### Service Cost Breakdown

Generate detailed markdown tables and month-over-month comparisons from Cost Explorer output:

```bash
python tools/generate_service_cost_breakdown.py -a 111111111111
```

### EKS Workload Analysis

Inspect Kubernetes workloads and VPC topology (*see [docs/eks-kubectl-guide.md](docs/eks-kubectl-guide.md)*):

```bash
# Check cross-cluster VPC connectivity
python tools/check_eks_vpc_connectivity.py -a 111111111111

# Export cluster workloads to Excel
python tools/get_eks_workloads_xls.py output/111111111111/eks-workloads/*.json
```

### OKF Bundle Generation

Bundle architecture, inventory, and audit artifacts into Open Knowledge Framework structures:

```bash
python tools/generate_okf_bundle.py --account-id 111111111111
```
*See [docs/generating-okf-bundles.md](docs/generating-okf-bundles.md) for bundling specifications.*

---

## Output Structure

Inventory output is stored strictly within `output/<account_id>/` and is gitignored by default:

```text
output/
├── <account_id>/
│   ├── ec2/
│   │   └── ec2-inventory-<account_id>-<timestamp>.json
│   ├── rds/
│   │   └── rds-inventory-<account_id>-<timestamp>.json
│   ├── s3/
│   │   └── s3-inventory-<account_id>-<timestamp>.json
│   └── ...
├── audit/
│   ├── audit-report-<account_id>.json
│   ├── audit-report-<account_id>.md
│   └── audit-report-<account_id>.csv
└── cost-breakdown/
    └── <account_id>-cost-breakdown.md
```

All inventory files write incrementally per region: if execution is stopped midway, previously completed regions remain saved.

---

## Configuration & Credentials

### conf/accounts.yaml

Define target accounts for multi-account execution:

```yaml
accounts:
  - name: "Production"
    account_id: "111111111111"
    profile: "111111111111_AdministratorAccess"
    alias: "prod"

  - name: "Development"
    account_id: "222222222222"
    profile: "222222222222_AdministratorAccess"
    alias: "dev"
    enabled: false  # Skip account during bulk runs
```

A complete template is available at `conf/accounts.yaml.example`.

### AWS Credentials & Permissions

- Standard AWS profiles configured via AWS SSO (`aws configure sso`) or credentials file (`aws configure --profile <name>`) are supported.
- **Recommended Permissions**: The AWS managed `ReadOnlyAccess` policy provides sufficient permissions for all inventory scripts.
- **Cost Explorer Requirements**: To scan cost and billing data via `get_cost_inventory.py`, the calling IAM identity requires `ce:GetCostAndUsage`.

---

## Architecture

```text
suchi-chintan/
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── SECURITY.md
├── requirements.txt
├── .gitignore
├── run_inventory.sh            # Parallel batch orchestrator
├── conf/
│   ├── accounts.yaml           # Account configuration (gitignored)
│   ├── accounts.yaml.example   # Account config template
│   ├── .env                    # Runner environment settings (gitignored)
│   └── .env.example            # Runner environment template
├── common/
│   ├── __init__.py             # Package exports
│   └── common.py               # Shared CLI args, session resolution, thread pools
├── inventory/                  # 70+ AWS service scanner scripts
│   ├── get_ec2_inventory.py
│   ├── get_s3_inventory.py
│   ├── get_cost_inventory.py
│   └── ...
├── tools/                      # Audit, post-processing & report generators
│   ├── audit_aws_resources.py
│   ├── generate_service_cost_breakdown.py
│   ├── check_eks_vpc_connectivity.py
│   └── ...
├── tests/                      # Offline unit tests
│   ├── test_backup_amg_workspaces.py
│   └── test_common.py
├── docs/                       # Detailed guides & references
│   ├── aws-observability-services.md
│   ├── eks-kubectl-guide.md
│   ├── generating-okf-bundles.md
│   └── running-all-scanners.md
└── output/                     # Generated scan and audit outputs (gitignored)
```

---

## Adding a New Scanner

To add coverage for an AWS service, implement `inventory/get_<service>_inventory.py`:

```python
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common import (
    add_common_args,
    resolve_accounts,
    IncrementalWriter,
    make_output_filename,
    scan_regions_parallel,
    is_region_unsupported_error,
)

def scan_region(session, region):
    client = session.client("service_name", region_name=region)
    # Collect resources...
    return region_data, {"resources": len(region_data)}

# Leverage scan_regions_parallel to run across all regions concurrently
```

---

## Documentation Index

- [Running All Scanners Guide](docs/running-all-scanners.md): Complete reference for batch scanning, logging, and concurrency control.
- [AWS Observability Services Mapping](docs/aws-observability-services.md): Mapping of CloudWatch, X-Ray, Grafana, OpenSearch, and Prometheus components.
- [Generating OKF Bundles](docs/generating-okf-bundles.md): Instructions for building Open Knowledge Framework documentation bundles.
- [EKS & Kubectl Guide](docs/eks-kubectl-guide.md): Prerequisites and instructions for Kubernetes workload scanning.
- [Tools README](tools/README.md): Usage guide for audit, analysis, and report generation tools.

---

## AWS Cost & Safety Disclaimer

- **Cost Explorer API**: AWS charges **$0.01 per request** for `ce:GetCostAndUsage` API calls. Running `get_cost_inventory.py` will incur small API query costs on your AWS bill.
- **Read-Only Operation**: Scanner scripts do NOT modify, delete, reboot, or mutate any AWS resources.
- **API Throttling**: When running with high concurrency (`PARALLEL > 4`), monitor for AWS API rate limits and throttling responses.

---

## Contributing

Contributions are welcome! Please read our [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style guidelines, and contribution workflows.

---

## Security

Please refer to [SECURITY.md](SECURITY.md) for vulnerability reporting procedures and security best practices.

---

## License

This project is licensed under the terms of the [MIT License](LICENSE).
