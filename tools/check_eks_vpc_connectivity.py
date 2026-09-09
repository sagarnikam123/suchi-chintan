#!/usr/bin/env python3
"""
EKS ↔ VPC Connectivity Analyzer

Reads the latest EKS and VPC inventory JSONs and produces:
  1. A mapping of each EKS cluster → its VPC
  2. A connectivity matrix: which clusters can reach each other via
     - Same VPC (trivial connectivity)
     - VPC Peering
     - Transit Gateway (shared TGW attachment)

By default it aggregates the latest EKS and VPC inventory from every account
directory under output/, so cross-account peering/TGW paths are analyzed. Pass
--eks-file / --vpc-file to restrict the analysis to a single inventory file.

Usage:
    python tools/check_eks_vpc_connectivity.py
    python tools/check_eks_vpc_connectivity.py --eks-file output/123456789012/eks/eks-inventory-123456789012-20260101-000000.json
    python tools/check_eks_vpc_connectivity.py --json   # Output as JSON instead of table
"""

import sys
import json
import argparse
from pathlib import Path
from collections import defaultdict

TOOLS_DIR = Path(__file__).parent.parent
OUTPUT_DIR = TOOLS_DIR / "output"


def latest_per_account(pattern, account_filter=None):
    """Return the newest inventory file per account directory under output/.

    output/<account_id>/<service>/<service>-inventory-<acct>-<ts>.json — pick the
    most recent file within each account dir so every account is represented
    (a single global 'newest' would silently drop all other accounts).
    """
    by_account = {}
    for match in OUTPUT_DIR.glob(pattern):
        account_dir = match.parent.parent.name
        if account_filter and account_filter != account_dir:
            continue
        current = by_account.get(account_dir)
        if current is None or match.stat().st_mtime > current.stat().st_mtime:
            by_account[account_dir] = match
    return [str(p) for p in by_account.values()]


def load_eks_inventory(path):
    """Load EKS inventory and extract cluster→VPC mapping.
    Returns: list of dicts with keys: cluster, account_id, account_name, region, vpc_id
    """
    with open(path) as f:
        data = json.load(f)

    clusters = []

    # Detect format: combined (has "accounts" key) vs per-account (has "regions" directly)
    if "accounts" in data:
        accounts_iter = data["accounts"].items()
    else:
        # Per-account file: wrap it as a single-account dict
        account_id = data.get("name", "unknown")
        accounts_iter = [(account_id, data)]

    for account_id, account_data in accounts_iter:
        account_name = account_data.get("name", account_id)
        for region, region_clusters in account_data.get("regions", {}).items():
            # region_clusters can be a list of cluster dicts or a dict with status/clusters
            if isinstance(region_clusters, dict):
                region_clusters = region_clusters.get("clusters", [])
            for c in region_clusters:
                if isinstance(c, str):
                    # Old format: just cluster name string, no VPC info
                    clusters.append({
                        "cluster": c, "account_id": account_id,
                        "account_name": account_name, "region": region,
                        "vpc_id": "",
                    })
                elif isinstance(c, dict):
                    vpc_id = c.get("vpc_id", "")
                    # --details mode nests it under vpc_config
                    if not vpc_id and "vpc_config" in c:
                        vpc_id = c["vpc_config"].get("vpc_id", "")
                    clusters.append({
                        "cluster": c.get("name", "unknown"),
                        "account_id": account_id,
                        "account_name": account_name,
                        "region": region,
                        "vpc_id": vpc_id,
                    })
    return clusters


def load_vpc_inventory(path):
    """Load VPC inventory and extract peering + TGW connectivity.
    Returns:
        peerings: list of (vpc_a, vpc_b) tuples (bidirectional)
        tgw_vpc_map: dict of tgw_id → set of vpc_ids attached
    """
    with open(path) as f:
        data = json.load(f)

    peerings = []
    tgw_vpc_map = defaultdict(set)  # tgw_id → {vpc_ids}

    # Detect format: combined (has "accounts" key) vs per-account (has "regions" directly)
    if "accounts" in data:
        accounts_iter = data["accounts"].items()
    else:
        account_id = data.get("name", "unknown")
        accounts_iter = [(account_id, data)]

    for account_id, account_data in accounts_iter:
        for region, region_data in account_data.get("regions", {}).items():
            # Peering connections
            for pc in region_data.get("peering", []):
                req_vpc = pc.get("requester_vpc", "")
                acc_vpc = pc.get("accepter_vpc", "")
                if req_vpc and acc_vpc:
                    peerings.append((req_vpc, acc_vpc))

            # Transit Gateway VPC attachments
            for att in region_data.get("tgw_attachments", []):
                tgw_id = att.get("tgw_id", "")
                vpc_id = att.get("vpc_id", "")
                if tgw_id and vpc_id:
                    tgw_vpc_map[tgw_id].add(vpc_id)

    return peerings, dict(tgw_vpc_map)


def build_connectivity(clusters, peerings, tgw_vpc_map):
    """Build connectivity matrix between EKS clusters.
    Returns list of connectivity edges:
        {"cluster_a": ..., "cluster_b": ..., "connection_type": ..., "via": ...}
    """
    # Build VPC → clusters index
    vpc_to_clusters = defaultdict(list)
    for c in clusters:
        if c["vpc_id"]:
            vpc_to_clusters[c["vpc_id"]].append(c)

    # Build VPC adjacency from peering (bidirectional)
    peered_vpcs = defaultdict(set)
    for vpc_a, vpc_b in peerings:
        peered_vpcs[vpc_a].add(vpc_b)
        peered_vpcs[vpc_b].add(vpc_a)

    # Build VPC adjacency from TGW (all VPCs on same TGW can reach each other)
    tgw_connected_vpcs = defaultdict(set)  # vpc → set of other vpcs via TGW
    for tgw_id, vpcs in tgw_vpc_map.items():
        vpc_list = list(vpcs)
        for i, vpc_a in enumerate(vpc_list):
            for vpc_b in vpc_list[i + 1:]:
                tgw_connected_vpcs[vpc_a].add((vpc_b, tgw_id))
                tgw_connected_vpcs[vpc_b].add((vpc_a, tgw_id))

    edges = []
    seen = set()

    # Same VPC
    for vpc_id, cls in vpc_to_clusters.items():
        for i, a in enumerate(cls):
            for b in cls[i + 1:]:
                key = tuple(sorted([a["cluster"], b["cluster"]]))
                if key not in seen:
                    seen.add(key)
                    edges.append({
                        "cluster_a": f"{a['cluster']} ({a['account_name']}/{a['region']})",
                        "cluster_b": f"{b['cluster']} ({b['account_name']}/{b['region']})",
                        "connection_type": "same_vpc",
                        "via": vpc_id,
                    })

    # VPC Peering
    for vpc_a, peer_set in peered_vpcs.items():
        clusters_a = vpc_to_clusters.get(vpc_a, [])
        for vpc_b in peer_set:
            clusters_b = vpc_to_clusters.get(vpc_b, [])
            for a in clusters_a:
                for b in clusters_b:
                    key = tuple(sorted([a["cluster"], b["cluster"]]))
                    if key not in seen:
                        seen.add(key)
                        edges.append({
                            "cluster_a": f"{a['cluster']} ({a['account_name']}/{a['region']})",
                            "cluster_b": f"{b['cluster']} ({b['account_name']}/{b['region']})",
                            "connection_type": "vpc_peering",
                            "via": f"{vpc_a} ↔ {vpc_b}",
                        })

    # Transit Gateway
    for vpc_a, tgw_peers in tgw_connected_vpcs.items():
        clusters_a = vpc_to_clusters.get(vpc_a, [])
        for vpc_b, tgw_id in tgw_peers:
            clusters_b = vpc_to_clusters.get(vpc_b, [])
            for a in clusters_a:
                for b in clusters_b:
                    key = tuple(sorted([a["cluster"], b["cluster"]]))
                    if key not in seen:
                        seen.add(key)
                        edges.append({
                            "cluster_a": f"{a['cluster']} ({a['account_name']}/{a['region']})",
                            "cluster_b": f"{b['cluster']} ({b['account_name']}/{b['region']})",
                            "connection_type": "transit_gateway",
                            "via": tgw_id,
                        })

    return edges


def print_cluster_vpc_table(clusters):
    """Print EKS cluster → VPC mapping as a table."""
    print("\n" + "=" * 90)
    print("EKS CLUSTER → VPC MAPPING")
    print("=" * 90)
    print(f"{'Cluster':<35} {'Account':<20} {'Region':<15} {'VPC ID':<25}")
    print("-" * 90)
    for c in sorted(clusters, key=lambda x: (x["account_name"], x["region"], x["cluster"])):
        vpc = c["vpc_id"] or "(not captured — re-run EKS scanner)"
        print(f"{c['cluster']:<35} {c['account_name']:<20} {c['region']:<15} {vpc:<25}")


def print_connectivity_table(edges):
    """Print connectivity matrix as a table."""
    print("\n" + "=" * 120)
    print("EKS CLUSTER CONNECTIVITY (direct network paths)")
    print("=" * 120)

    if not edges:
        print("  No connectivity found between EKS clusters.")
        print("  Possible reasons:")
        print("    - Clusters are isolated in separate VPCs with no peering/TGW")
        print("    - VPC inventory hasn't been run yet (run get_vpc_inventory.py first)")
        print("    - EKS inventory lacks vpc_id (re-run get_eks_inventory.py)")
        return

    # Group by connection type
    by_type = defaultdict(list)
    for e in edges:
        by_type[e["connection_type"]].append(e)

    for conn_type, group in sorted(by_type.items()):
        label = {"same_vpc": "🟢 Same VPC", "vpc_peering": "🔵 VPC Peering", "transit_gateway": "🟠 Transit Gateway"}
        print(f"\n  {label.get(conn_type, conn_type)} ({len(group)} paths)")
        print(f"  {'Cluster A':<45} {'Cluster B':<45} {'Via'}")
        print("  " + "-" * 115)
        for e in group:
            print(f"  {e['cluster_a']:<45} {e['cluster_b']:<45} {e['via']}")


def print_isolated_clusters(clusters, edges):
    """Print clusters with no connectivity to any other cluster."""
    connected = set()
    for e in edges:
        # Extract raw cluster name from formatted string
        connected.add(e["cluster_a"].split(" (")[0])
        connected.add(e["cluster_b"].split(" (")[0])

    isolated = [c for c in clusters if c["cluster"] not in connected]
    if isolated:
        print(f"\n{'=' * 90}")
        print(f"🔴 ISOLATED CLUSTERS (no direct network path to other EKS clusters)")
        print("=" * 90)
        for c in sorted(isolated, key=lambda x: (x["account_name"], x["cluster"])):
            vpc = c["vpc_id"] or "unknown"
            print(f"  {c['cluster']:<35} {c['account_name']:<20} {c['region']:<15} vpc={vpc}")


def main():
    parser = argparse.ArgumentParser(description='EKS ↔ VPC Connectivity Analyzer')
    parser.add_argument('--account', '-a', default=None, help='Filter by AWS account ID (default: all accounts)')
    parser.add_argument('--eks-file', default=None, help='Path to EKS inventory JSON (default: latest in output/<account>/eks/)')
    parser.add_argument('--vpc-file', default=None, help='Path to VPC inventory JSON (default: latest in output/<account>/vpc/)')
    parser.add_argument('--json', action='store_true', help='Output as JSON instead of table')
    args = parser.parse_args()

    # Find inventory files: a single file if overridden, else the latest per account.
    eks_inventory_files = [args.eks_file] if args.eks_file else latest_per_account("*/eks/eks-*.json", account_filter=args.account)
    vpc_inventory_files = [args.vpc_file] if args.vpc_file else latest_per_account("*/vpc/vpc-*.json", account_filter=args.account)

    if not eks_inventory_files:
        print("ERROR: No EKS inventory found. Run: python inventory/get_eks_inventory.py")
        sys.exit(1)

    clusters = []
    for eks_file in eks_inventory_files:
        print(f"EKS inventory: {eks_file}")
        clusters.extend(load_eks_inventory(eks_file))
    print(f"  Found {len(clusters)} EKS clusters across {len(eks_inventory_files)} account file(s)")

    # Check if any clusters lack vpc_id
    missing_vpc = [c for c in clusters if not c["vpc_id"]]
    if missing_vpc:
        print(f"  ⚠️  {len(missing_vpc)} clusters missing vpc_id — re-run: python inventory/get_eks_inventory.py")

    peerings, tgw_vpc_map = [], {}
    if vpc_inventory_files:
        for vpc_file in vpc_inventory_files:
            print(f"VPC inventory: {vpc_file}")
            file_peerings, file_tgw_map = load_vpc_inventory(vpc_file)
            peerings.extend(file_peerings)
            # Merge TGW→VPC sets across accounts so a shared TGW links all of them.
            for tgw_id, vpc_ids in file_tgw_map.items():
                tgw_vpc_map.setdefault(tgw_id, set()).update(vpc_ids)
        print(f"  Found {len(peerings)} peering connections, {len(tgw_vpc_map)} transit gateways with VPC attachments")
    else:
        print("VPC inventory: NOT FOUND — run: python inventory/get_vpc_inventory.py")
        print("  (Connectivity analysis will only show same-VPC clusters)")

    # Build connectivity
    edges = build_connectivity(clusters, peerings, tgw_vpc_map)

    if args.json:
        output = {
            "clusters": clusters,
            "connectivity": edges,
            "summary": {
                "total_clusters": len(clusters),
                "clusters_missing_vpc": len(missing_vpc),
                "same_vpc_paths": sum(1 for e in edges if e["connection_type"] == "same_vpc"),
                "peering_paths": sum(1 for e in edges if e["connection_type"] == "vpc_peering"),
                "tgw_paths": sum(1 for e in edges if e["connection_type"] == "transit_gateway"),
                "isolated_clusters": len(clusters) - len({e["cluster_a"].split(" (")[0] for e in edges} | {e["cluster_b"].split(" (")[0] for e in edges}),
            }
        }
        print(json.dumps(output, indent=2, default=str))
    else:
        print_cluster_vpc_table(clusters)
        print_connectivity_table(edges)
        print_isolated_clusters(clusters, edges)

        # Summary
        print(f"\n{'=' * 90}")
        print("📊 SUMMARY")
        print("=" * 90)
        print(f"  Total EKS clusters: {len(clusters)}")
        print(f"  Same-VPC paths: {sum(1 for e in edges if e['connection_type'] == 'same_vpc')}")
        print(f"  VPC Peering paths: {sum(1 for e in edges if e['connection_type'] == 'vpc_peering')}")
        print(f"  Transit Gateway paths: {sum(1 for e in edges if e['connection_type'] == 'transit_gateway')}")
        connected_names = {e["cluster_a"].split(" (")[0] for e in edges} | {e["cluster_b"].split(" (")[0] for e in edges}
        isolated_count = len(clusters) - len(connected_names)
        print(f"  Isolated clusters: {isolated_count}")


if __name__ == "__main__":
    main()
