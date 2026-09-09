#!/usr/bin/env python3
"""
Unique Deployments Extractor
Reads a k8s-workloads inventory JSON and lists unique deployment/service names
across all clusters and namespaces.

Excludes infrastructure namespaces and tenant-specific prefixes.

Usage:
    python get_eks_unique_deployments.py
    python get_eks_unique_deployments.py -i /path/to/k8s-workloads-inventory.json
    python get_eks_unique_deployments.py --include-infra   # don't skip infra namespaces
    python get_eks_unique_deployments.py --normalize       # strip tenant IDs to get base service names
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

# Default input — latest known workloads inventory
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
}

# Namespace prefixes to skip (tenant-specific). Customize for your environment.
SKIP_PREFIXES = ()

# Deployment name prefixes that are per-tenant instances (same service, one per tenant).
# Customize these for your environment.
TENANT_DEPLOY_PREFIXES = (
    # Example: "myapp-", "worker-", "ingestion-",
)

# ponytail: regex to strip tenant ID suffixes like -a1t1acuk, -a2t4azsx, -dts4okv7, -epocdmo1, -poc3krt8, -demo, -prod07
# Matches: dash + (tenant-id pattern OR environment suffix) at end of string
TENANT_SUFFIX_RE = re.compile(r"-(demo|dev|qa|uat|staging|prod\d*)$")


def normalize_deployment_name(name):
    """Strip tenant-specific suffixes to get the base service name."""
    # Keep stripping until stable
    return TENANT_SUFFIX_RE.sub("", name)


def extract_unique_deployments(data, include_infra=False, normalize=False):
    """Extract unique deployment names from workloads inventory JSON."""
    unique = set()

    for region, clusters in data.get("regions", {}).items():
        for cluster, cluster_data in clusters.items():
            if not isinstance(cluster_data, dict) or "namespaces" not in cluster_data:
                continue
            for ns, ns_data in cluster_data["namespaces"].items():
                if not include_infra:
                    if ns in INFRA_NAMESPACES:
                        continue
                    if ns.startswith(SKIP_PREFIXES):
                        continue
                for dep in ns_data.get("deployments", []):
                    name = dep["name"]
                    if normalize:
                        name = normalize_deployment_name(name)
                    # Skip per-tenant deployment variants
                    if any(name.startswith(p) for p in TENANT_DEPLOY_PREFIXES):
                        continue
                    unique.add(name)

    return sorted(unique)


def main():
    parser = argparse.ArgumentParser(description="Extract unique deployment names from k8s workloads inventory")
    parser.add_argument("-i", "--input", default=DEFAULT_INPUT,
                        help="Path to k8s-workloads-inventory JSON file")
    parser.add_argument("--include-infra", action="store_true",
                        help="Include infrastructure/platform namespaces")
    parser.add_argument("--normalize", action="store_true",
                        help="Strip tenant ID suffixes to get base service names")
    parser.add_argument("-o", "--output", default=None,
                        help="Output file path (default: output dir with timestamp)")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    with open(args.input) as f:
        data = json.load(f)

    unique_deployments = extract_unique_deployments(data, include_infra=args.include_infra, normalize=args.normalize)

    # Output path
    if args.output:
        output_path = args.output
    else:
        output_dir = str(Path(__file__).parent.parent / "output")
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        output_path = os.path.join(output_dir, f"unique-deployments-{timestamp}.json")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    result = {
        "generated": datetime.now().isoformat(),
        "source": args.input,
        "include_infra": args.include_infra,
        "normalized": args.normalize,
        "total_unique_deployments": len(unique_deployments),
        "deployments": unique_deployments,
    }

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"Unique deployments: {len(unique_deployments)}")
    print(f"Output: {output_path}")

    # Also print to stdout for quick inspection
    print("\n--- Deployments ---")
    for name in unique_deployments:
        print(f"  {name}")


if __name__ == "__main__":
    main()
