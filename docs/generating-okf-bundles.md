# Generating OKF Bundles from AWS Inventory

`tools/generate_okf_bundle.py` converts the scanner's existing inventory, cost, and audit-report JSON into an [Open Knowledge Format (OKF)](https://github.com/GoogleCloudPlatform/knowledge-catalog/tree/main/okf) v0.2 markdown bundle. It does **not** call AWS or re-run `audit_aws_resources.py`.

Each generated service concept contains:

- resource count and regional distribution from the latest inventory JSON;
- month-to-date unblended cost from the latest cost inventory JSON, when its AWS cost key is known;
- estimated waste and quick-win remediation actions from the existing audit report, including drift findings where the audit associates them with the service.

Services with no matched cost or audit data are still written and explicitly state that no match was found.

## Prerequisites

1. Run the inventory scanner and audit first. The generator reads:
   - `output/<account-id>/<service>/*.json`
   - `output/<account-id>/cost/cost-inventory-*.json`
   - `output/audit/audit-report-<account-id>.json`
2. Clone the OKF reference implementation beside this repository at `../knowledge-catalog/okf`, or pass its source path with `--okf-src`.
3. Its virtual environment is used automatically when `../knowledge-catalog/okf/.venv/bin/python` exists. Otherwise the generator uses the current Python interpreter.

## Generate a Bundle

Run commands from the repository root:

```bash
# One account; account-wise layout is the default.
python3 tools/generate_okf_bundle.py \
  -a 111111111111 \
  -o output/okf/account-111111111111

# Select one account by its inventory `name` field.
python3 tools/generate_okf_bundle.py \
  --name my-account-name \
  -o output/okf/by-name

# Select one account by the prefix of inventory `profile_used`.
python3 tools/generate_okf_bundle.py \
  -p 111111111111_AdministratorAccess \
  -o output/okf/by-profile

# First three sorted account ids (useful for a small validation/sample bundle).
python3 tools/generate_okf_bundle.py \
  --all --max-accounts 3 \
  -o output/okf/first-three-accounts

# All inventory account directories, grouped by AWS service.
python3 tools/generate_okf_bundle.py \
  --all --service-wise \
  -o output/okf/all-services
```

Choose exactly one account selector:

| Argument | Meaning |
| :--- | :--- |
| `-a`, `--account <id>` | A single 12-digit account directory under `output/` |
| `--name <name>` | A single exact match for inventory JSON `name` |
| `-p`, `--profile <prefix>` | A single profile prefix match against inventory JSON `profile_used` |
| `--all` | Every `output/<12-digit-account-id>/` directory |
| `--max-accounts <N>` | With `--all`, only the first `N` sorted account IDs (useful for sample bundles) |

Other arguments:

| Argument | Meaning |
| :--- | :--- |
| `-o`, `--output-dir <path>` | Required OKF bundle destination |
| `--account-wise` | Group concepts by account (default) |
| `--service-wise` | Group concepts by service across accounts |
| `--input-dir <path>` | Override `output/` as the inventory input root |
| `--no-visualize` | Write markdown only; do not create `viz.html` |
| `--okf-src <path>` | Override the default `../knowledge-catalog/okf/src` source location |
| `--okf-python <path>` | Interpreter used for the OKF visualizer |
| `--check-links <bundle-dir>` | Assert that every generated relative markdown link resolves |
| `--self-check` | Run the built-in assert-based generator checks without writing a bundle |

## Bundle Layouts

### Account-wise (default)

```text
output/okf/account-111111111111/
├── index.md
├── viz.html
└── accounts/
    └── 111111111111/
        ├── index.md          # navigation / progressive-disclosure listing
        ├── _account.md       # typed AWS Account graph node and audit summary
        ├── ec2.md            # resource summary, cost, and findings
        ├── rds.md
        └── ...
```

### Service-wise

```text
output/okf/all-services/
├── index.md
├── viz.html
└── services/
    └── ec2/
        ├── index.md          # navigation / progressive-disclosure listing
        ├── _rollup.md        # typed cross-account AWS Service graph node
        ├── 111111111111.md   # per-account EC2 detail
        ├── 222222222222.md
        └── ...
```

`index.md` is intentionally only a directory listing: the OKF visualizer reserves and skips every file named `index.md`. `_account.md` and `_rollup.md` are therefore separate typed concepts so their links appear as graph nodes and edges.

## Generate the Visualization

Visualization runs automatically unless `--no-visualize` is given. The generator executes:

```bash
PYTHONPATH=<okf-src> <okf-python> -m reference_agent visualize \
  --bundle <output-dir> \
  --out <output-dir>/viz.html
```

To run it yourself after a `--no-visualize` generation:

```bash
PYTHONPATH=../knowledge-catalog/okf/src \
  ../knowledge-catalog/okf/.venv/bin/python -m reference_agent visualize \
  --bundle output/okf/account-111111111111 \
  --out output/okf/account-111111111111/viz.html \
  --name "AWS Inventory"
```

Open the result locally on macOS:

```bash
open output/okf/account-111111111111/viz.html
```

The bundled visualizer colors `AWS Account` nodes orange and `AWS Service` nodes blue. Select a node to inspect its frontmatter, resource summary, cost, and findings.

## Validate a Bundle

```bash
python3 tools/generate_okf_bundle.py --self-check
python3 tools/generate_okf_bundle.py --check-links output/okf/account-111111111111
```

The first command validates generator logic and a real EC2 concept when the existing sample output is available. The second verifies that every relative `.md` link in a generated bundle resolves to a file.
