# Contributing to suchi-chintan

Thank you for your interest in contributing to **suchi-chintan**!

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/sagarnikam123/suchi-chintan.git
   cd suchi-chintan
   ```
2. Create and activate a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Adding a New Service Scanner

All scanners reside in the `inventory/` directory and adhere to the standard pattern:

1. **Naming**: Script name should follow `get_<service_name>_inventory.py`.
2. **Imports**: Import utilities from `common`:
   ```python
   from common import (
       setup_logging,
       add_common_args,
       resolve_accounts,
       IncrementalWriter,
       make_output_filename,
       scan_regions_parallel,
       is_region_unsupported_error,
   )
   ```
3. **Region Scan**: Define `scan_region(session, region)` that returns `(data, counts)`.
4. **Execution**: Use `scan_regions_parallel(...)` to handle concurrent region queries and incremental disk flushes automatically.
5. **Output**: Use `make_output_filename("<service_name>", account_id, timestamp)` for standard path generation.

## Code Style & Guidelines

- Maintain Python 3.9+ compatibility.
- Ensure no sensitive information, hardcoded credentials, or private account IDs are committed.
- Keep region error handling graceful (using `is_region_unsupported_error()` for services not enabled in specific regions).
- Follow PEP 8 guidelines.

## Pull Request Guidelines

1. Create a descriptive branch: `git checkout -b feat/new-service-scanner`.
2. Ensure new scanner scripts run cleanly without throwing unhandled exceptions on unsupported regions.
3. Commit with concise conventional commit messages (e.g., `feat(inventory): add app runner scanner`).
4. Submit a Pull Request with a summary of changes and test results.
