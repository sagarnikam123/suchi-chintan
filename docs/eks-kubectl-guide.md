# EKS Cluster Access — kubectl Guide

How to connect to EKS clusters discovered by `get_eks_inventory.py`.

## Prerequisites

| Tool | Install |
|------|---------|
| `aws` CLI v2 | `brew install awscli` |
| `kubectl` | `brew install kubectl` |
| AWS profile configured | `~/.aws/credentials` or SSO |

---

## Add a Cluster to kubeconfig

```bash
aws eks update-kubeconfig \
  --name <CLUSTER_NAME> \
  --region <REGION> \
  --profile <AWS_PROFILE> \
  --alias <FRIENDLY_ALIAS>
```

### Examples

```bash
# Cluster in us-east-1
aws eks update-kubeconfig \
  --name my-app-cluster \
  --region us-east-1 \
  --profile 111111111111_AdministratorAccess \
  --alias app-prod

# Cluster in eu-west-1
aws eks update-kubeconfig \
  --name my-eu-cluster \
  --region eu-west-1 \
  --profile 111111111111_AdministratorAccess \
  --alias app-eu
```

The `--alias` flag gives a short name so you don't type the full ARN context name.

---

## View Clusters in kubeconfig

```bash
# List all contexts (clusters you've added)
kubectl config get-contexts

# Show current context
kubectl config current-context

# Show full kubeconfig
kubectl config view --minify
```

---

## Switch Between Clusters

```bash
# Switch to a cluster
kubectl config use-context app-prod

# Or specify inline without switching
kubectl get pods --context app-prod -n monitoring
```

---

## Basic kubectl Commands

```bash
# Verify connection
kubectl cluster-info

# List namespaces
kubectl get ns

# List pods in a namespace
kubectl get pods -n monitoring

# View nodes
kubectl get nodes -o wide

# Search pods across namespaces
kubectl get pods --all-namespaces | grep -i my-service
```

---

## Remove a Cluster from kubeconfig

```bash
# Delete a context
kubectl config delete-context app-prod

# Delete the cluster entry
kubectl config delete-cluster arn:aws:eks:us-east-1:111111111111:cluster/my-app-cluster

# Delete the user entry
kubectl config delete-user arn:aws:eks:us-east-1:111111111111:cluster/my-app-cluster
```

### Quick cleanup — remove all clusters by prefix

```bash
# List contexts matching a prefix
kubectl config get-contexts -o name | grep my-prefix-

# Remove them all
kubectl config get-contexts -o name | grep my-prefix- | xargs -I {} kubectl config delete-context {}
```

---

## Using with Inventory Output

After running `get_eks_inventory.py`, check the output JSON for cluster names and regions:

```bash
# Find cluster names from inventory
cat output/<account_id>/eks/eks-inventory-*.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for region, clusters in data.get('regions', {}).items():
    for c in clusters:
        print(f\"{c['name']}  ({region})\")"
```

Then add each cluster:

```bash
aws eks update-kubeconfig \
  --name <name_from_output> \
  --region <region_from_output> \
  --profile <your_profile>
```

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `error: You must be logged in` | Run `aws sso login --profile <your_profile>` |
| `Unauthorized` | IAM role may lack EKS access — check `aws-auth` ConfigMap |
| `No cluster found` | Verify cluster name + region match exactly (case-sensitive) |
| `Unable to connect to the server` | Check VPN/network — cluster may be in private subnets |
| Stale token | Delete `~/.kube/cache/` and re-run `update-kubeconfig` |
