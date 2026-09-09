#!/usr/bin/env python3
"""
Kubernetes Workloads Inventory Scanner
Connects to EKS clusters and inventories namespaces + workloads inside them.

Depth levels:
  default:     namespaces → services
  --workloads: + deployments, statefulsets, daemonsets, cronjobs, jobs, ingresses, HPAs
  --all:       + configmaps, secrets (names only), PVCs, service accounts, network policies

Requires: pip install kubernetes boto3 pyyaml

Usage:
    python get_k8s_workloads_inventory.py -p <profile> -r us-east-1
    python get_k8s_workloads_inventory.py -a "MyAccount" -r us-east-1 --workloads
    python get_k8s_workloads_inventory.py -p <profile> -r us-east-1 --all
    python get_k8s_workloads_inventory.py -p <profile> -r us-east-1 --cluster my-cluster
    python get_k8s_workloads_inventory.py -p <profile> -r us-east-1 --namespace kube-system
"""

import sys
import os
import subprocess
import tempfile
import time
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, str(Path(__file__).parent.parent))

from common import (
    logger, BOTO_CONFIG, get_accounts, get_regions, create_session,
    get_output_dir, get_timestamp, get_disabled_regions, add_common_args,
    create_session_with_identity, is_region_unsupported_error,
    IncrementalWriter, make_output_filename,
    run_with_timer,
)

SERVICE = "k8s-workloads"

# Namespaces to skip by default (system noise)
SKIP_NAMESPACES = {"kube-node-lease", "kube-public"}


def get_kubeconfig_for_cluster(cluster_name, region, profile):
    """Generate a temporary kubeconfig for the cluster using aws eks update-kubeconfig."""
    kubeconfig_path = tempfile.mktemp(suffix=".yaml", prefix=f"kubeconfig-{cluster_name}-")
    env = os.environ.copy()
    env["AWS_PROFILE"] = profile

    cmd = [
        "aws", "eks", "update-kubeconfig",
        "--name", cluster_name,
        "--region", region,
        "--kubeconfig", kubeconfig_path,
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=30)
    if result.returncode != 0:
        logger.warning(f"    Failed to get kubeconfig for {cluster_name}: {result.stderr.strip()}")
        return None

    return kubeconfig_path


def get_k8s_client(kubeconfig_path):
    """Create a kubernetes client from a kubeconfig file with 5s connect timeout."""
    from kubernetes import client, config
    import urllib3
    config.load_kube_config(config_file=kubeconfig_path)
    configuration = client.Configuration.get_default_copy()
    # Disable retries — fail fast on unreachable private clusters
    configuration.retries = 0
    api_client = client.ApiClient(configuration)
    # Patch urllib3 pool to enforce 5s connect, 15s read timeout
    api_client.rest_client.pool_manager.connection_pool_kw['timeout'] = urllib3.util.Timeout(connect=5, read=15)
    return (
        client.CoreV1Api(api_client),
        client.AppsV1Api(api_client),
        client.BatchV1Api(api_client),
        client.AutoscalingV1Api(api_client),
        client.NetworkingV1Api(api_client),
    )


def scan_namespace_services(core_v1, namespace):
    """Get services in a namespace."""
    services = []
    try:
        svc_list = core_v1.list_namespaced_service(namespace)
        for svc in svc_list.items:
            services.append({
                "name": svc.metadata.name,
                "type": svc.spec.type,
                "cluster_ip": svc.spec.cluster_ip,
                "ports": [
                    {"port": p.port, "target_port": str(p.target_port), "protocol": p.protocol}
                    for p in (svc.spec.ports or [])
                ],
            })
    except Exception as e:
        logger.debug(f"      Error listing services in {namespace}: {e}")
    return services


def scan_namespace(core_v1, apps_v1, batch_v1, autoscaling_v1, networking_v1, namespace, resource_types):
    """Scan a namespace for the specified resource types only."""
    result = {}

    if "service" in resource_types:
        result["services"] = scan_namespace_services(core_v1, namespace)

    if "deployment" in resource_types:
        try:
            deps = apps_v1.list_namespaced_deployment(namespace)
            result["deployments"] = [
                {
                    "name": d.metadata.name,
                    "replicas": d.spec.replicas,
                    "ready_replicas": d.status.ready_replicas or 0,
                    "image": d.spec.template.spec.containers[0].image if d.spec.template.spec.containers else "",
                }
                for d in deps.items
            ]
        except Exception as e:
            result["deployments_error"] = str(e)

    if "statefulset" in resource_types:
        try:
            sts = apps_v1.list_namespaced_stateful_set(namespace)
            result["statefulsets"] = [
                {
                    "name": s.metadata.name,
                    "replicas": s.spec.replicas,
                    "ready_replicas": s.status.ready_replicas or 0,
                    "image": s.spec.template.spec.containers[0].image if s.spec.template.spec.containers else "",
                }
                for s in sts.items
            ]
        except Exception as e:
            result["statefulsets_error"] = str(e)

    if "daemonset" in resource_types:
        try:
            ds = apps_v1.list_namespaced_daemon_set(namespace)
            result["daemonsets"] = [
                {
                    "name": d.metadata.name,
                    "desired": d.status.desired_number_scheduled,
                    "ready": d.status.number_ready,
                    "image": d.spec.template.spec.containers[0].image if d.spec.template.spec.containers else "",
                }
                for d in ds.items
            ]
        except Exception as e:
            result["daemonsets_error"] = str(e)

    if "cronjob" in resource_types:
        try:
            cj = batch_v1.list_namespaced_cron_job(namespace)
            result["cronjobs"] = [
                {
                    "name": c.metadata.name,
                    "schedule": c.spec.schedule,
                    "suspend": c.spec.suspend,
                    "last_schedule": str(c.status.last_schedule_time) if c.status.last_schedule_time else None,
                }
                for c in cj.items
            ]
        except Exception as e:
            result["cronjobs_error"] = str(e)

    if "job" in resource_types:
        try:
            jobs = batch_v1.list_namespaced_job(namespace)
            result["jobs"] = [
                {
                    "name": j.metadata.name,
                    "completions": j.spec.completions,
                    "succeeded": j.status.succeeded or 0,
                    "failed": j.status.failed or 0,
                }
                for j in jobs.items
            ]
        except Exception as e:
            result["jobs_error"] = str(e)

    if "ingress" in resource_types:
        try:
            ing = networking_v1.list_namespaced_ingress(namespace)
            result["ingresses"] = [
                {
                    "name": i.metadata.name,
                    "hosts": [rule.host for rule in (i.spec.rules or []) if rule.host],
                    "class": i.spec.ingress_class_name,
                }
                for i in ing.items
            ]
        except Exception as e:
            result["ingresses_error"] = str(e)

    if "hpa" in resource_types:
        try:
            hpas = autoscaling_v1.list_namespaced_horizontal_pod_autoscaler(namespace)
            result["hpas"] = [
                {
                    "name": h.metadata.name,
                    "target": h.spec.scale_target_ref.name,
                    "min_replicas": h.spec.min_replicas,
                    "max_replicas": h.spec.max_replicas,
                    "current_replicas": h.status.current_replicas,
                }
                for h in hpas.items
            ]
        except Exception as e:
            result["hpas_error"] = str(e)

    if "configmap" in resource_types:
        try:
            cms = core_v1.list_namespaced_config_map(namespace)
            result["configmaps"] = [{"name": cm.metadata.name} for cm in cms.items]
        except Exception as e:
            result["configmaps_error"] = str(e)

    if "secret" in resource_types:
        try:
            secrets = core_v1.list_namespaced_secret(namespace)
            result["secrets"] = [
                {"name": s.metadata.name, "type": s.type}
                for s in secrets.items
            ]
        except Exception as e:
            result["secrets_error"] = str(e)

    if "pvc" in resource_types:
        try:
            pvcs = core_v1.list_namespaced_persistent_volume_claim(namespace)
            result["pvcs"] = [
                {
                    "name": p.metadata.name,
                    "status": p.status.phase,
                    "storage_class": p.spec.storage_class_name,
                    "capacity": p.status.capacity.get("storage", "") if p.status.capacity else "",
                }
                for p in pvcs.items
            ]
        except Exception as e:
            result["pvcs_error"] = str(e)

    if "serviceaccount" in resource_types:
        try:
            sas = core_v1.list_namespaced_service_account(namespace)
            result["service_accounts"] = [{"name": sa.metadata.name} for sa in sas.items]
        except Exception as e:
            result["service_accounts_error"] = str(e)

    if "networkpolicy" in resource_types:
        try:
            netpols = networking_v1.list_namespaced_network_policy(namespace)
            result["network_policies"] = [
                {
                    "name": np.metadata.name,
                    "pod_selector": np.spec.pod_selector.match_labels if np.spec.pod_selector and np.spec.pod_selector.match_labels else {},
                    "policy_types": np.spec.policy_types or [],
                }
                for np in netpols.items
            ]
        except Exception as e:
            result["network_policies_error"] = str(e)

    return result


def scan_cluster(cluster_name, region, profile, resource_types, filter_namespace=None, connect_timeout=5):
    """Scan a single EKS cluster for specified resource types.
    resource_types: list of type names e.g. ["deployment", "service"]
    connect_timeout: seconds to wait for initial API server connectivity (default: 5)
    """
    kubeconfig = get_kubeconfig_for_cluster(cluster_name, region, profile)
    if not kubeconfig:
        return {"status": "kubeconfig_failed"}

    try:
        core_v1, apps_v1, batch_v1, autoscaling_v1, networking_v1 = get_k8s_client(kubeconfig)

        # Quick connectivity check — fail fast on unreachable clusters
        try:
            core_v1.list_namespace(_request_timeout=connect_timeout)
        except Exception as e:
            logger.warning(f"    {cluster_name}: unreachable (timeout {connect_timeout}s) — {type(e).__name__}: {e}")
            return {"status": "unreachable", "error": str(e)}

        # List namespaces (already succeeded above, fetch fresh)
        ns_list = core_v1.list_namespace(_request_timeout=15)
        namespaces = [ns.metadata.name for ns in ns_list.items if ns.metadata.name not in SKIP_NAMESPACES]

        if filter_namespace:
            namespaces = [ns for ns in namespaces if ns == filter_namespace]
            if not namespaces:
                logger.warning(f"    Namespace '{filter_namespace}' not found in {cluster_name}")
                return {"status": "namespace_not_found"}

        cluster_data = {"status": "ok", "namespaces": {}}

        for ns in namespaces:
            ns_data = scan_namespace(core_v1, apps_v1, batch_v1, autoscaling_v1, networking_v1, ns, resource_types)

            cluster_data["namespaces"][ns] = ns_data

            # Count for logging
            counts = {k: len(v) for k, v in ns_data.items() if isinstance(v, list)}
            total = sum(counts.values())
            if total > 0:
                logger.info(f"      {ns}: {total} objects ({', '.join(f'{k}={v}' for k, v in counts.items() if v > 0)})")

        cluster_data["total_namespaces"] = len(namespaces)
        return cluster_data

    except Exception as e:
        logger.warning(f"    Error scanning cluster {cluster_name}: {e}")
        return {"status": "error", "error": str(e)}
    finally:
        # Cleanup temp kubeconfig
        try:
            os.unlink(kubeconfig)
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser(description='Kubernetes Workloads Inventory Scanner')
    add_common_args(parser)
    parser.add_argument('--workloads', '-w', nargs='*', default=None,
                        help='Resource types to scan. No args = all workload types. '
                             'Choices: deployment, statefulset, daemonset, cronjob, job, service, ingress, hpa, '
                             'configmap, secret, pvc, serviceaccount, networkpolicy. '
                             'Examples: -w deployment daemonset | -w (all)')
    parser.add_argument('--cluster', '-c', default=None,
                        help='Scan only this cluster name (within the account/region)')
    parser.add_argument('--namespace', '-n', default=None,
                        help='Scan only this namespace')
    args = parser.parse_args()

    # Determine which resource types to scan
    ALL_TYPES = ["deployment", "statefulset", "daemonset", "cronjob", "job", "service", "ingress", "hpa",
                 "configmap", "secret", "pvc", "serviceaccount", "networkpolicy"]

    if args.workloads is None:
        # No --workloads flag at all → deployments only
        resource_types = ["deployment"]
    elif len(args.workloads) == 0:
        # --workloads with no args → all types
        resource_types = ALL_TYPES
    else:
        # --workloads deployment daemonset → specific types
        resource_types = args.workloads
        # Always include service for context
        invalid = [r for r in resource_types if r not in ALL_TYPES]
        if invalid:
            parser.error(f"Unknown resource type(s): {', '.join(invalid)}. Choose from: {', '.join(ALL_TYPES)}")

    depth_label = "deployments" if resource_types == ["deployment"] else ", ".join(resource_types)

    accounts = get_accounts(args.account)
    if args.profile:
        session, account_id, arn = create_session_with_identity(args.profile)
        if not session:
            sys.exit(1)
        accounts = [{"name": account_id, "account_id": account_id, "profile": args.profile, "_session": session}]

    regions = [args.region] if args.region else get_regions('eks')
    timestamp = get_timestamp()

    logger.info(f"Scanning {len(accounts)} account(s) across {len(regions)} region(s)")
    logger.info(f"Resources: {depth_label}")
    logger.info("=" * 60)
    start_time = time.time()

    combined_data = {
        "generated": timestamp,
        "resource_types": resource_types,
        "note": "Kubernetes workloads per EKS cluster per namespace.",
        "accounts": {},
        "summary": {
            "total_clusters_scanned": 0,
            "total_namespaces": 0,
        }
    }

    for account in accounts:
        name = account['name']
        account_id = account['account_id']
        profile = account['profile']

        if account.get('enabled') is False:
            logger.info(f"⏭️  {name} ({account_id}) — skipped (no credentials)")
            continue

        logger.info(f"🔍 {name} ({account_id})")

        # Reuse session from --profile if already authenticated
        session = account.get("_session") or create_session(profile)
        if not session:
            combined_data["accounts"][account_id] = {
                "name": name, "status": "auth_failed", "regions": {}
            }
            continue

        account_output = get_output_dir(account_id, SERVICE)
        account_writer = IncrementalWriter(account_output, make_output_filename(SERVICE, account_id, timestamp))
        account_writer.update({"name": name, "profile_used": profile, "status": "ok", "regions": {}})

        disabled = get_disabled_regions(session)
        acct_clusters = 0
        acct_namespaces = 0

        for region in regions:
            if region in disabled:
                continue

            # List EKS clusters in this region
            try:
                eks_client = session.client('eks', region_name=region, config=BOTO_CONFIG)
                response = eks_client.list_clusters()
                clusters = response.get('clusters', [])
            except Exception as e:
                if is_region_unsupported_error(e):
                    continue
                logger.warning(f"  {region}: EKS list error — {e}")
                continue

            if not clusters:
                continue

            if args.cluster:
                clusters = [c for c in clusters if c == args.cluster]
                if not clusters:
                    continue

            logger.info(f"  {region}: {len(clusters)} cluster(s)")
            region_data = {}

            # Scan clusters in parallel (max 4 workers)
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = {
                    executor.submit(
                        scan_cluster, cluster_name, region, profile,
                        resource_types=resource_types,
                        filter_namespace=args.namespace,
                    ): cluster_name
                    for cluster_name in clusters
                }
                for future in as_completed(futures):
                    cluster_name = futures[future]
                    logger.info(f"    📦 {cluster_name}")
                    try:
                        cluster_data = future.result()
                    except Exception as exc:
                        logger.warning(f"    {cluster_name}: worker error — {exc}")
                        cluster_data = {"status": "error", "error": str(exc)}

                    region_data[cluster_name] = cluster_data
                    acct_clusters += 1
                    acct_namespaces += cluster_data.get("total_namespaces", 0)

                    # Flush after each cluster — crash-safe
                    account_writer.set_nested("regions", region, value=region_data)

            # (region complete)

        combined_data["accounts"][account_id] = account_writer.get_data()

        summary = combined_data["summary"]
        summary["total_clusters_scanned"] += acct_clusters
        summary["total_namespaces"] += acct_namespaces

        logger.info(f"  📄 Flushed: {account_id} ({acct_clusters} clusters, {acct_namespaces} namespaces)")

    # Final summary
    logger.info("" + "=" * 60)
    logger.info("📊 SUMMARY")
    logger.info("=" * 60)
    final = combined_data["summary"]
    elapsed = time.time() - start_time
    if elapsed < 60:
        elapsed_str = f"{elapsed:.1f}s"
    elif elapsed < 3600:
        elapsed_str = f"{elapsed / 60:.1f}min"
    elif elapsed < 86400:
        h, m = divmod(int(elapsed), 3600)
        elapsed_str = f"{h}hr{m // 60}min"
    else:
        d, rem = divmod(int(elapsed), 86400)
        elapsed_str = f"{d}d{rem // 3600}hr"
    logger.info(f"  Clusters scanned: {final['total_clusters_scanned']}")
    logger.info(f"  Namespaces found: {final['total_namespaces']}")
    logger.info(f"  Time elapsed: {elapsed_str}")


if __name__ == "__main__":
    run_with_timer(main)
