# examples

[`workflow.yml`](workflow.yml) — a scheduled workflow that assumes a read-only role,
audits security groups across two regions, and uploads SARIF to code scanning.

Locally, with credentials in your environment:

```bash
# human-readable
aws-sg-audit --regions us-east-1,eu-west-1 --format table

# machine-readable
aws-sg-audit --regions us-east-1 --format json

# SARIF for GitHub code scanning
aws-sg-audit --regions us-east-1 --format sarif > sg-audit.sarif
```

Treat extra ports as intentionally public, or skip audited groups by tag:

```bash
aws-sg-audit --regions us-east-1 --public-ports 80,443,8080 --ignore-tag sg-audit-ignore
```
