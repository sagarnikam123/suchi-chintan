# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability within **suchi-chintan**, please do NOT open a public issue.

Instead, please report security concerns privately by contacting the maintainers or via GitHub Private Vulnerability Reporting on the repository.

Please include:
- Description of the vulnerability and potential impact.
- Steps or a minimal script to reproduce the issue.
- Any suggested remediations or mitigations.

We will acknowledge receipt within 48 hours and coordinate remediation before public disclosure.

## Security Best Practices for Users

- **Credentials**: Never commit `conf/accounts.yaml` or `conf/.env`. Verify that `.gitignore` is intact before pushing.
- **Permissions**: Grant the minimum required IAM permissions. For standard resource scanning, AWS managed `ReadOnlyAccess` policy is recommended.
- **Cost Awareness**: Use caution when running scanners with high parallel counts or frequent Cost Explorer queries (`ce:GetCostAndUsage`) to avoid AWS API charges or throttling.
