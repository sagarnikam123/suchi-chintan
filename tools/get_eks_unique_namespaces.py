#!/usr/bin/env python3
"""
Unique Namespaces Extractor
Reads a k8s-workloads inventory JSON and lists unique namespace names
across all clusters and regions.

Excludes infrastructure namespaces by default. Supports custom exclude patterns.

Usage:
    python get_eks_unique_namespaces.py
    python get_eks_unique_namespaces.py -i /path/to/k8s-workloads-inventory.json
    python get_eks_unique_namespaces.py --include-infra
    python get_eks_unique_namespaces.py --exclude-prefix staging test dev
    python get_eks_unique_namespaces.py --exclude-prefix staging test --exclude-pattern "^env\\d+"
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

# Default input
DEFAULT_INPUT = str(
    Path(__file__).parent.parent
    / "output/<account_id>/k8s-workloads/k8s-workloads-inventory-YYYYMMDD-HHMMSS.json"
)

# Infrastructure/platform namespaces to skip
INFRA_NAMESPACES = {
    "castai-agent", "cert-manager", "cloudability", "default", "external-dns",
    "ingress-nginx", "karpenter", "keda", "kube-system", "logging", "monitoring",
    "prometheus", "amazon-cloudwatch", "datadog", "nginx", "observability",
    "tempo", "skywalking", "skywalking-swck-system", "skywalking-test",
    "harness-delegate-ng", "envoy-gateway-system", "kafka-lag-exporter",
    "mimir-test", "alert-test", "robusta", "signalai", "signalai-v2-test",
    "ot-operators", "opensearch", "kafka", "kubecost", "warpstream",
    "spark-operator", "test", "test-analysis", "test-basic", "test-deep",
    "v2-debug", "v2-json-test",
    # Infra/maintenance/monitoring/logging additions
    "aiops", "airflow", "castai-live", "mimir", "monitoring-testing",
    "opentelemetry-operator-system", "cluster-autoscaler", "jenkins",
    "non-prod-jenkins", "rancher", "fleet-default", "fleet-local",
    "cattle-fleet-clusters-system", "cattle-fleet-local-system",
    "cattle-fleet-system", "cattle-global-data", "cattle-global-nt",
    "cattle-impersonation-system", "cattle-system", "local",
    "app-dtspilot", "app-dtspilot-system", "spark-watcher",
}


def extract_unique_namespaces(data, include_infra=False, exclude_prefixes=None, exclude_pattern=None):
    """Extract unique namespace names from workloads inventory JSON."""
    unique = set()
    exclude_re = re.compile(exclude_pattern) if exclude_pattern else None

    for region, clusters in data.get("regions", {}).items():
        for cluster, cluster_data in clusters.items():
            if not isinstance(cluster_data, dict) or "namespaces" not in cluster_data:
                continue
            for ns in cluster_data["namespaces"]:
                if not include_infra and ns in INFRA_NAMESPACES:
                    continue
                if exclude_prefixes and any(ns.startswith(p) for p in exclude_prefixes):
                    continue
                if exclude_re and exclude_re.match(ns):
                    continue
                unique.add(ns)

    return sorted(unique)


def main():
    parser = argparse.ArgumentParser(description="Extract unique namespace names from k8s workloads inventory")
    parser.add_argument("-i", "--input", default=DEFAULT_INPUT,
                        help="Path to k8s-workloads-inventory JSON file")
    parser.add_argument("--include-infra", action="store_true",
                        help="Include infrastructure/platform namespaces")
    parser.add_argument("--exclude-prefix", nargs="*", default=[],
                        help="Namespace prefixes to exclude (e.g. staging test dev)")
    parser.add_argument("--exclude-pattern", default=None,
                        help="Regex pattern to exclude namespaces (matched from start)")
    parser.add_argument("-o", "--output", default=None,
                        help="Output file path (default: output dir with timestamp)")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    with open(args.input) as f:
        data = json.load(f)

    unique_namespaces = extract_unique_namespaces(
        data,
        include_infra=args.include_infra,
        exclude_prefixes=args.exclude_prefix,
        exclude_pattern=args.exclude_pattern,
    )

    # Output path
    if args.output:
        output_path = args.output
    else:
        output_dir = str(Path(__file__).parent.parent / "output")
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        output_path = os.path.join(output_dir, f"unique-namespaces-{timestamp}.json")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    result = {
        "generated": datetime.now().isoformat(),
        "source": args.input,
        "include_infra": args.include_infra,
        "exclude_prefixes": args.exclude_prefix,
        "exclude_pattern": args.exclude_pattern,
        "total_unique_namespaces": len(unique_namespaces),
        "namespaces": unique_namespaces,
    }

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"Unique namespaces: {len(unique_namespaces)}")
    print(f"Output: {output_path}")

    print("\n--- Namespaces ---")
    for ns in unique_namespaces:
        print(f"  {ns}")


if __name__ == "__main__":
    main()
