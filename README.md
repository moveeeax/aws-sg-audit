# aws-sg-audit

[![ci](https://github.com/moveeeax/aws-sg-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-sg-audit/actions/workflows/ci.yml)
[![go](https://img.shields.io/badge/go-1.26%2B-00ADD8)](https://go.dev)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

> Find the security groups that leave the door open.

`aws-sg-audit` scans AWS security groups across regions and flags the ones that
expose **sensitive ports to the whole internet** (`0.0.0.0/0` or `::/0`) — SSH,
RDP, database and cache ports, and the like. It notes whether each group is
actually attached, scores severity, and emits table, JSON, or SARIF.

```console
$ aws-sg-audit --regions us-east-1,eu-west-1 --format table
SEVERITY  REGION     SECURITY GROUP   PORT      SERVICE  CIDR       ATTACHED
critical  us-east-1  web (sg-0a1b)    22/tcp    SSH      0.0.0.0/0  true
high      eu-west-1  db  (sg-0c2d)    3306/tcp  MySQL    ::/0       false

2 finding(s).
```

## What it flags

- **World-open sensitive ports** — a curated set (22, 3389, 3306, 5432, 6379,
  27017, 23, 445, 1433, 2379, …) reachable from `0.0.0.0/0` or `::/0`.
- **All-traffic rules** — a `-1` / full-range ingress from the world is reported
  as a single `critical` "ALL PORTS" finding.
- It does **not** flag intended public ports (`80`/`443` by default, configurable
  with `--public-ports`), so there are no false positives on your web tier.

Each finding records whether the SG is **attached** to a live ENI; an attached
world-open port is scored one level higher than the same rule on an unused group.

## Install

```bash
go install github.com/moveeeax/aws-sg-audit@latest
```

Single static binary. It uses the standard AWS credential chain (env,
`~/.aws/credentials`, SSO, `--profile`) and needs only `ec2:Describe*`.

## Usage

```
aws-sg-audit --regions <r1,r2,...> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--regions` | — | Comma-separated regions to scan (required) |
| `-f`, `--format` | `table` | `table`, `json`, or `sarif` |
| `--public-ports` | `80,443` | Ports treated as intentionally public |
| `--ignore-tag` | `sg-audit-ignore` | Skip SGs carrying this tag key |
| `--fail-on` | `medium` | Min severity for a non-zero exit (`medium`/`high`/`critical`/`none`) |
| `--profile` | — | AWS shared-config profile |

Exit code is `0` when nothing at/above `--fail-on` is found, `1` otherwise — a
drop-in CI gate.

## GitHub Action

Upload findings to **code scanning** as SARIF:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: aws-actions/configure-aws-credentials@v6
    with:
      role-to-assume: arn:aws:iam::123456789012:role/sg-audit-readonly
      aws-region: us-east-1
  - uses: moveeeax/aws-sg-audit@v0
    with:
      regions: us-east-1,eu-west-1
      fail-on: high
```

See [`examples/`](examples/) for a full scheduled workflow.

## How it works

Per region it calls `DescribeSecurityGroups`, and `DescribeNetworkInterfaces`
once to build the set of SG ids that are actually attached. Each ingress rule is
checked for a world-open CIDR; the port range is expanded against the sensitive-port
table, and the intended-public allowlist is subtracted. The AWS surface sits behind
a `Scanner` interface, so the rule engine and all three output formats are
unit-tested without touching AWS.

## Development

```bash
make build   # go build -o aws-sg-audit .
make test    # go test -race ./...
make lint    # gofmt -l . && go vet ./...
```

## License

MIT — see [LICENSE](LICENSE).
