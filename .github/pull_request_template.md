## Description

Briefly describe the purpose of this pull request and what changes were made.

## Type of Change

- [ ] New service scanner (`inventory/get_<service>_inventory.py`)
- [ ] New tool or enhancement (`tools/`)
- [ ] Bug fix
- [ ] Documentation update
- [ ] CI/CD or repository maintenance

## Checklist

- [ ] My code follows the repository's style and conventions.
- [ ] I have run local tests (`pytest`) and verified that existing tests pass.
- [ ] If adding a new scanner:
  - [ ] Tested with `--account`, `--profile`, and `--region` flags.
  - [ ] Uses `scan_regions_parallel()` and `IncrementalWriter`.
  - [ ] Gracefully handles unsupported regions via `is_region_unsupported_error()`.
- [ ] No sensitive credentials, private AWS account IDs, or tokens are included in code, docs, or commit history.
- [ ] Updated relevant documentation in `README.md` or `docs/` if applicable.
