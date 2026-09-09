# AWS Observability Services

Reference list of AWS services relevant to observability — metrics, logs, traces,
alerting, and the managed open-source stack.

The **Inventory script** column names the scanner in `inventory/` that collects
that service. Run any of them without profile flags to use the AWS CLI `[default]`
profile, or use `-p <profile>` for a specific profile and `-a <account>` for
accounts.yaml selection.

Observability = the three pillars (**metrics**, **logs**, **traces**) plus the
signals built on them (**alerts**, **dashboards**, **events**).

---

## Core observability

| Service | What it does | Inventory script |
|---|---|---|
| **Amazon CloudWatch** | Log groups, alarms, dashboards (+ Logs Insights, Container/Lambda Insights) | `get_cloudwatch_inventory.py` |
| **AWS X-Ray** | Distributed tracing, service maps, latency analysis | `get_xray_inventory.py` |
| **Amazon Managed Service for Prometheus (AMP)** | Managed Prometheus for metrics ingestion/query (PromQL) | `get_amp_inventory.py` |
| **Amazon Managed Grafana (AMG)** | Managed Grafana dashboards over AMP/CloudWatch/X-Ray | `get_amg_inventory.py` |
| **Amazon OpenSearch Service** | Log search/analytics, OpenSearch Dashboards (Kibana) | `get_opensearch_inventory.py` |

## Audit, events & change tracking

| Service | What it does | Inventory script |
|---|---|---|
| **AWS CloudTrail** | API-call audit log — who did what, when | `get_cloudtrail_inventory.py` |
| **Amazon EventBridge / CloudWatch Events** | Event bus + rules routing operational events | `get_eventbridge_inventory.py` |
| **AWS Config** | Resource configuration history + compliance rules | `get_config_inventory.py` |

## Security observability

| Service | What it does | Inventory script |
|---|---|---|
| **Amazon GuardDuty** | Threat detection from VPC/DNS/CloudTrail signals | `get_guardduty_inventory.py` |
| **AWS Security Hub** | Aggregated security findings + posture scoring | `get_security_hub_inventory.py` |
| **Amazon Inspector** | Continuous vulnerability scanning (EC2/ECR/Lambda) | `get_inspector_inventory.py` |
| **Amazon Security Lake** | Central OCSF security-data lake (logs/findings) | `get_security_lake_inventory.py` |

## Delivery / notification (observability plumbing)

| Service | What it does | Inventory script |
|---|---|---|
| **Amazon SNS** | Alarm/notification fan-out (email, SMS, HTTP, Lambda) | `get_sns_inventory.py` |
| **Amazon Kinesis Data Firehose** | Stream logs/metrics to S3/OpenSearch/3rd-party | `get_kinesis_inventory.py` (incl. Firehose) |

---

## Front-end / APM / network monitoring

| Service | What it does | Inventory script |
|---|---|---|
| **CloudWatch Synthetics (Canaries)** | Scripted uptime/endpoint monitoring | `get_cloudwatch_synthetics_inventory.py` |
| **CloudWatch RUM** | Real User Monitoring for web app front-ends | `get_cloudwatch_rum_inventory.py` |
| **CloudWatch Internet Monitor** | Internet-path performance/availability | `get_cloudwatch_internet_monitor_inventory.py` |
| **CloudWatch Application Signals** | APM (SLOs, service map) over ADOT/X-Ray | `get_cloudwatch_application_signals_inventory.py` |

## Account-event feed (not a resource inventory)

| Service | What it does | Inventory script |
|---|---|---|
| **AWS Health** | Open/upcoming service events affecting the account (maintenance, retirements, degradations) | `get_health_inventory.py` |

`get_health_inventory.py` collects an event feed, not a per-resource inventory — it
captures the last 90 days plus upcoming events. Requires **Business/Enterprise
Support**; on Basic/Developer it records `access: false` instead of erroring.

## Not covered by a scanner (by design)

Deliberately skipped — deprecated, or no control-plane API to inventory.

| Service | What it does | Why skipped |
|---|---|---|
| **CloudWatch Evidently** | Feature flags + A/B experiments | Being deprecated by AWS (end of support 2025) — building a scanner for a dead service is waste |
| **AWS Distro for OpenTelemetry (ADOT)** | OTel collector distro | It's an agent you run on EC2/EKS/Lambda — no AWS API lists "your ADOT deployments", so there is nothing to scan. Workload coverage comes from the EKS/Lambda scanners. |
| **AWS Managed Grafana – SAML/data sources** | Auth + data-source wiring detail | Partially covered by `get_amg_permissions.py` |

---

## Notes

- **CloudWatch is the hub.** Alarms trigger SNS; Logs feed Logs Insights; Container/Lambda
  Insights and Application Signals are all CloudWatch features, not separate services.
- **Managed OSS stack = AMP + AMG + OpenSearch.** These replace self-hosted
  Prometheus/Grafana/ELK.
- **"CloudWatch Events"** on a bill is the legacy name for **EventBridge** — same service.

## Coverage summary

- **19** observability services have inventory scanners.
- **Not covered (by design):** Evidently (deprecated) and ADOT (agent, no control-plane API).
