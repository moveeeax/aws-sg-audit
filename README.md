# aws-sg-audit

> Find the security groups that leave the door open.

**Status:** 🚧 In development

## Overview

Flag overly permissive AWS security groups (0.0.0.0/0 on sensitive ports).

## Features

- Scans all SGs across regions
- Rules for sensitive ports (22, 3389, 3306, 5432, 6379, ...)
- Distinguishes attached vs unused SGs
- Severity scoring + JSON/SARIF output
- Ignore-list via tags

## Stack

Go + aws-sdk-go-v2 (EC2).

## Usage

```bash
aws-sg-audit --regions us-east-1,eu-west-1 --format table
```

## License

MIT
