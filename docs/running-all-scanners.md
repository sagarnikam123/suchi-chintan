# Running All Scanners

Every scanner in `inventory/` shares the same core CLI (via `add_common_args`),
so one runner can drive all of them for a single account.

## Common arguments (all 73 scripts)

| Arg | Short | Meaning |
|-----|-------|---------|
| `--profile` | `-p` | AWS profile to use directly (bypasses `accounts.yaml`). Omit it to use the AWS CLI `[default]` profile; account ID is auto-detected via STS. |
| `--account` | `-a` | Filter to an account (ID / name / profile) from `accounts.yaml`; this preserves accounts.yaml mode when no profile is supplied. |
| `--region` | `-r` | Limit to one region. Omit = all regions the service supports. |
| `--output-dir` | `-o` | Custom output directory (default `output/<account_id>/<service>`). |

## Script-specific arguments (optional, 4 scripts only)

These take extra **optional** flags — they still run fine with just `-p`:

| Script | Extra arg | Purpose |
|--------|-----------|---------|
| `get_ec2_inventory.py` | `--tag KEY=VALUE` | Filter EC2 by tag |
| `get_eks_inventory.py` | `--details` | Include detailed cluster info |
| `get_eks_workloads_inventory.py` | `--workloads`, `--cluster`, `--namespace` | Filter K8s workloads |
| `get_amg_permissions.py` | `--workspace` | Target one Grafana workspace |

Because the extras are optional, the runner drives every script with just
`-p <profile>` (and optional `-r <region>`); standalone scripts also use the
AWS CLI `[default]` profile when `-p` and `-a` are omitted.

## The runner: `run_inventory.sh`

Runs all scanners N at a time. A failing scanner is warned to the console but
**never stops the run** — the rest continue.

```bash
cp conf/.env.example conf/.env    # edit AWS_PROFILE, PARALLEL, etc.
./run_inventory.sh                  # uses the AWS CLI [default] profile if omitted
```

`AWS_PROFILE` is optional. When omitted or empty, the runner uses the AWS CLI
`[default]` profile.

Inline override (no conf/.env needed):

```bash
AWS_PROFILE=123456789012_AdministratorAccess PARALLEL=4 ./run_inventory.sh
```

### `conf/.env` settings

| Var | Default | Meaning |
|-----|---------|---------|
| `AWS_PROFILE` | `default` | Optional profile to scan; empty or omitted uses the AWS CLI `[default]` profile |
| `AWS_REGION` | all | Limit to one region |
| `PARALLEL` | `2` | Scanners to run concurrently |
| `ONLY` | all | Comma-separated scripts to run (e.g. `get_ec2_inventory.py,get_s3_inventory.py`) |
| `SKIP` | none | Comma-separated scripts to skip |

### Behavior

- Runs `PARALLEL` scripts at a time (via `xargs -P`).
- Each script's stdout/stderr goes to `output/_run_logs/<script>.log`.
- On failure: prints `⚠️ <script> FAILED (exit N)` + the last 3 log lines, then moves on.
- Ends with a summary: how many passed, which failed.

### Notes

- Single-account by design — one `AWS_PROFILE` per run. To scan another account,
  change the profile and run again.
- Keep `PARALLEL` modest (2–4). Too high risks API throttling across the shared
  account, and some scanners are already internally parallel across regions.
- Logs are under `output/_run_logs/` (gitignored with the rest of `output/`).
