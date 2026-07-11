# Open AWS Scanner

Find unused AWS resources costing you money. No admin panel, no Keycloak, no multi-tenant complexity — just point it at your AWS account and find waste.

---

## Table of Contents

- [Install](#install)
- [How To: Run Your First Scan](#how-to-run-your-first-scan)
- [How To: Set Up AWS Credentials](#how-to-set-up-aws-credentials)
- [How To: Scan Multiple Regions](#how-to-scan-multiple-regions)
- [How To: Run as a Server](#how-to-run-as-a-server)
- [How To: Use the API](#how-to-use-the-api)
- [How To: Run with Docker](#how-to-run-with-docker)
- [How To: Use Stage Mode (No AWS Needed)](#how-to-use-stage-mode-no-aws-needed)
- [How To: Track Savings](#how-to-track-savings)
- [How To: Use Postgres Instead of SQLite](#how-to-use-postgres-instead-of-sqlite)
- [How To: Set Up the IAM Role](#how-to-set-up-the-iam-role)
- [How To: Verify Package Signatures](#how-to-verify-package-signatures)
- [CLI Reference](#cli-reference)
- [API Reference](#api-reference)
- [What It Scans](#what-it-scans)
- [Configuration Reference](#configuration-reference)
- [Relationship to CostOps Platform](#relationship-to-costops-platform)
- [License](#license)

---

## Install

```bash
pip install open-aws-scanner
```

Or from source:

```bash
git clone https://github.com/yourusername/open-aws-scanner.git
cd open-aws-scanner
pip install .
```

For development (editable install):

```bash
pip install -e .
```

---

## How To: Run Your First Scan

**Step 1** — Create a config file:

```bash
open-aws-scanner init
```

This creates `config.env` in your current directory.

**Step 2** — Edit `config.env` with your AWS setup (see [credentials section](#how-to-set-up-aws-credentials) below).

**Step 3** — Run a scan:

```bash
open-aws-scanner scan
```

Output looks like:

```
================================================================================
 Open AWS Scanner — 10 issues found | $472.90/mo potential savings
================================================================================

  EC2_Instance (2 found, $227.50/mo)
    • test-server-bob: CPU avg 2.1% over last 7 days  $85.00/mo  [us-east-1]
    • legacy-worker-node: CPU avg 1.3% over last 7 days  $142.50/mo  [us-east-1]

  EBS_Volume (2 found, $76.80/mo)
    • backup-vol-old: Volume is not attached to any instance  $64.00/mo  [us-east-1]
    • dev-data-volume: Volume is not attached to any instance  $12.80/mo  [us-east-1]

────────────────────────────────────────────────────────────────────────────────
  Total potential savings: $472.90/month
```

**Step 4** — Get JSON output (for piping to other tools):

```bash
open-aws-scanner scan --output json > findings.json
```

---

## How To: Set Up AWS Credentials

The scanner needs read-only AWS access. Pick one of these methods:

### Option A: Use your existing AWS profile (simplest)

Leave `AWS_ROLE_ARN` blank in `config.env`. The scanner uses whatever credentials are available:

- `~/.aws/credentials` (AWS CLI profile)
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` environment variables
- EC2 instance profile or ECS task role

```env
AWS_ROLE_ARN=
AWS_REGIONS=us-east-1
```

### Option B: Assume an IAM role (cross-account)

Set up a read-only role in the target account (see [IAM setup](#how-to-set-up-the-iam-role)), then:

```env
AWS_ROLE_ARN=arn:aws:iam::123456789012:role/OpenScannerRole
AWS_EXTERNAL_ID=my-scanner
AWS_REGIONS=us-east-1
```

### Option C: Explicit credentials

```env
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=wJal...
AWS_REGIONS=us-east-1
```

Not recommended for production — use roles or profiles instead.

### Verify credentials work

```bash
# Quick check that your credentials are valid
aws sts get-caller-identity
```

---

## How To: Scan Multiple Regions

Comma-separate regions in `config.env`:

```env
AWS_REGIONS=us-east-1,us-west-2,eu-west-1,ap-southeast-1
```

Or override from CLI:

```bash
open-aws-scanner scan --regions us-east-1,eu-west-1
```

Each region is scanned independently. Findings are tagged with their region.

---

## How To: Run as a Server

Start the API server with automatic scheduled scans:

```bash
open-aws-scanner serve
```

This gives you:

- Automatic scans every N hours (default: 6, configurable via `SCAN_INTERVAL_HOURS`)
- REST API for querying findings
- JSON index page at `/` with status summary
- Swagger docs at `/docs`

Custom host/port:

```bash
open-aws-scanner serve --host 127.0.0.1 --port 9000
```

Keep it running in the background:

```bash
nohup open-aws-scanner serve > scanner.log 2>&1 &
```

Or with systemd (Linux):

```ini
# /etc/systemd/system/open-aws-scanner.service
[Unit]
Description=Open AWS Scanner
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/scanner
ExecStart=/usr/local/bin/open-aws-scanner serve
Restart=always
Environment=AWS_REGIONS=us-east-1

[Install]
WantedBy=multi-user.target
```

---

## How To: Use the API

Once the server is running:

### Trigger a scan

```bash
curl -X POST http://localhost:8000/scan
```

### Get all findings

```bash
curl http://localhost:8000/findings
```

### Filter findings

```bash
# Only open findings
curl "http://localhost:8000/findings?status=open"

# Only EC2 findings
curl "http://localhost:8000/findings?resource_type=EC2_Instance"

# Combine filters
curl "http://localhost:8000/findings?status=open&resource_type=EBS_Volume"
```

### Mark a finding as fixed

```bash
curl -X PUT "http://localhost:8000/findings/42/status?status=fixed"
```

Valid statuses: `open`, `fixed`, `dismissed`, `in_progress`

### Get savings summary

```bash
curl http://localhost:8000/summary
```

Response:

```json
{
  "total_findings": 10,
  "total_potential_savings": 472.90,
  "open": { "count": 7, "savings": 380.50 },
  "fixed": { "count": 2, "savings_realized": 67.65 },
  "dismissed": { "count": 0, "savings": 0 },
  "in_progress": { "count": 1, "savings": 24.75 }
}
```

### Get scan history

```bash
curl http://localhost:8000/scans
```

---

## How To: Run with Docker

### Build and run

```bash
docker build -t open-aws-scanner .
docker run -p 8000:8000 --env-file config.env open-aws-scanner
```

### With AWS credentials from host

```bash
docker run -p 8000:8000 \
  -e AWS_REGIONS=us-east-1 \
  -e STAGE_MODE=true \
  -v ~/.aws:/root/.aws:ro \
  open-aws-scanner
```

### Persist the database

```bash
docker run -p 8000:8000 \
  --env-file config.env \
  -v $(pwd)/data:/app/scanner.db \
  open-aws-scanner
```

---

## How To: Use Stage Mode (No AWS Needed)

Stage mode uses mock data — no real AWS credentials required. Perfect for:

- Testing the API
- Developing integrations
- Demoing the tool

Set in `config.env`:

```env
STAGE_MODE=true
```

Or as an environment variable:

```bash
STAGE_MODE=true open-aws-scanner scan
STAGE_MODE=true open-aws-scanner serve
```

---

## How To: Track Savings

The scanner tracks finding status over time. A typical workflow:

1. Run a scan → findings are `open`
2. Fix a resource (e.g., delete the unused EBS volume in AWS console)
3. Mark it fixed:

```bash
curl -X PUT "http://localhost:8000/findings/42/status?status=fixed"
```

4. Check realized savings:

```bash
curl http://localhost:8000/summary
# → "fixed": { "count": 3, "savings_realized": 145.25 }
```

Statuses:

| Status | Meaning |
|--------|---------|
| `open` | Identified waste, not yet addressed |
| `in_progress` | Being worked on |
| `fixed` | Resource cleaned up — savings realized |
| `dismissed` | Intentionally kept (not waste) |

---

## How To: Use Postgres Instead of SQLite

By default the scanner uses SQLite (zero config, file-based). For production or team use, switch to Postgres:

**Step 1** — Install the postgres extra:

```bash
pip install open-aws-scanner[postgres]
```

**Step 2** — Set `DATABASE_URL` in `config.env`:

```env
DATABASE_URL=postgresql://user:pass@localhost:5432/scanner
```

**Step 3** — Create the database:

```bash
createdb scanner
```

The tables are created automatically on first run.

---

## How To: Set Up the IAM Role

If scanning a different AWS account, create a read-only role:

**Step 1** — In the target account, create a role with this trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::YOUR_SCANNER_ACCOUNT:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "my-scanner"
        }
      }
    }
  ]
}
```

**Step 2** — Attach this permissions policy to the role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "OpenScannerReadOnly",
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters",
        "lambda:ListFunctions",
        "lambda:ListProvisionedConcurrencyConfigs",
        "s3:ListAllMyBuckets",
        "s3:ListBucket",
        "sqs:ListQueues",
        "sns:ListTopics",
        "elasticloadbalancing:DescribeLoadBalancers",
        "dynamodb:ListTables",
        "elasticache:DescribeCacheClusters",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:StartQuery",
        "logs:GetQueryResults",
        "secretsmanager:ListSecrets",
        "ecs:ListClusters",
        "ecs:ListServices",
        "autoscaling:DescribeAutoScalingGroups",
        "autoscaling:DescribeAutoScalingInstances",
        "organizations:ListAccounts",
        "organizations:DescribeOrganization",
        "organizations:DescribeAccount",
        "cloudwatch:GetMetricData",
        "cloudwatch:GetMetricStatistics",
        "cloudwatch:ListMetrics",
        "cloudtrail:LookupEvents",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors",
        "ce:GetCostAndUsage",
        "ce:GetCostAndUsageWithResources",
        "ce:GetCostForecast",
        "ce:GetUsageForecast",
        "ce:GetDimensionValues",
        "ce:GetTags",
        "ce:GetCostCategories",
        "ce:GetCostAndUsageComparisons",
        "ce:GetCostComparisonDrivers",
        "ce:GetSavingsPlansCoverage",
        "ce:GetSavingsPlansUtilization",
        "ce:GetSavingsPlansUtilizationDetails",
        "ce:GetSavingsPlansPurchaseRecommendation",
        "ce:GetReservationCoverage",
        "ce:GetReservationUtilization",
        "ce:GetReservationPurchaseRecommendation",
        "ce:GetRightsizingRecommendation",
        "ce:GetAnomalies",
        "ce:GetAnomalyMonitors",
        "ce:ListCostAllocationTags",
        "ce:ListCostAllocationTagBackfillHistory",
        "ce:DescribeCostCategoryDefinition",
        "ce:ListCostCategoryDefinitions",
        "budgets:ViewBudget",
        "cost-optimization-hub:GetRecommendation",
        "cost-optimization-hub:ListRecommendations",
        "cost-optimization-hub:ListRecommendationSummaries",
        "compute-optimizer:DescribeRecommendationExportJobs",
        "compute-optimizer:GetEnrollmentStatus",
        "compute-optimizer:GetEnrollmentStatusesForOrganization",
        "compute-optimizer:GetRecommendationSummaries",
        "compute-optimizer:GetEC2InstanceRecommendations",
        "compute-optimizer:GetEC2RecommendationProjectedMetrics",
        "compute-optimizer:GetAutoScalingGroupRecommendations",
        "compute-optimizer:GetEBSVolumeRecommendations",
        "compute-optimizer:GetLambdaFunctionRecommendations",
        "compute-optimizer:GetRecommendationPreferences",
        "compute-optimizer:GetEffectiveRecommendationPreferences",
        "compute-optimizer:GetECSServiceRecommendations",
        "compute-optimizer:GetECSServiceRecommendationProjectedMetrics",
        "compute-optimizer:GetLicenseRecommendations",
        "compute-optimizer:GetRDSDatabaseRecommendations",
        "compute-optimizer:GetRDSDatabaseRecommendationProjectedMetrics",
        "compute-optimizer:GetIdleRecommendations",
        "pricing:DescribeServices",
        "pricing:GetAttributeValues",
        "pricing:GetProducts",
        "freetier:GetFreeTierUsage",
        "bcm-pricing-calculator:GetPreferences",
        "bcm-pricing-calculator:GetWorkloadEstimate",
        "bcm-pricing-calculator:ListWorkloadEstimateUsage",
        "bcm-pricing-calculator:ListWorkloadEstimates"
      ],
      "Resource": "*"
    }
  ]
}
```

**Step 3** — Configure `config.env`:

```env
AWS_ROLE_ARN=arn:aws:iam::123456789012:role/OpenScannerRole
AWS_EXTERNAL_ID=my-scanner
```

**Step 4** — Make sure the machine running the scanner has `sts:AssumeRole` permission for that role ARN.

---

## How To: Verify Package Signatures

All releases are signed with [Sigstore](https://www.sigstore.dev/).

### Verify a release

```bash
pip install sigstore

sigstore verify identity open_aws_scanner-0.1.0.tar.gz \
    --cert-identity "luge-sud-0q@icloud.com" \
    --cert-oidc-issuer "https://appleid.apple.com"
```

### Verify git commits

```bash
git log --show-signature
```

---

## CLI Reference

```
open-aws-scanner init
    Create a config.env template in the current directory.

open-aws-scanner scan [OPTIONS]
    Run a one-shot scan and print results.

    --regions REGIONS       Comma-separated AWS regions (overrides config)
    --role-arn ARN          AWS role ARN to assume (overrides config)
    --output {json,table}   Output format (default: table)
    --config PATH           Path to config.env (default: ./config.env)

open-aws-scanner serve [OPTIONS]
    Start the API server with scheduled scans.

    --host HOST             Host to bind (default: 0.0.0.0)
    --port PORT             Port to bind (default: 8000)
    --config PATH           Path to config.env (default: ./config.env)
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Status summary + endpoint list (JSON) |
| GET | `/health` | Health check |
| POST | `/scan` | Trigger a scan now |
| GET | `/findings` | List all findings |
| GET | `/findings?status=open` | Filter by status |
| GET | `/findings?resource_type=EC2_Instance` | Filter by resource type |
| PUT | `/findings/{id}/status?status=fixed` | Update finding status |
| GET | `/summary` | Savings summary by status |
| GET | `/scans` | Scan run history |
| GET | `/docs` | Swagger UI (interactive) |
| GET | `/redoc` | ReDoc (readable docs) |

---

## What It Scans

| Resource | Detection | Est. Savings |
|----------|-----------|-------------|
| EBS Volumes | Unattached | $0.08/GB/mo |
| Elastic IPs | Unassociated | $3.65/mo |
| EBS Snapshots | Orphaned (source volume deleted, 30+ days) | $0.05/GB/mo |
| ENIs | Detached | $0 |
| Security Groups | Not attached to any ENI | $0 |
| EC2 Instances | CPU avg < 5% over 7 days | — |
| RDS Instances | < 1 avg connection over 7 days | — |
| Lambda Functions | Zero invocations in 30 days | $0 |
| S3 Buckets | Empty (zero objects) | $0 |
| SQS Queues | Zero messages sent in 14 days | $0 |
| SNS Topics | Zero publishes in 14 days | $0 |
| Load Balancers | Zero requests in 7 days | $16.20/mo |
| NAT Gateways | Zero bytes processed in 7 days | $32.40/mo |
| DynamoDB Tables | Zero read capacity in 14 days | — |
| ElastiCache | < 1 avg connection in 7 days | — |
| CloudWatch Logs | No ingestion in 30 days | $0.03/GB |
| Secrets Manager | Not accessed in 90 days | $0.40/mo |

---

## Configuration Reference

All settings go in `config.env` (or as environment variables):

| Variable | Description | Default |
|----------|-------------|---------|
| `AWS_ROLE_ARN` | IAM role to assume (blank = use local creds) | *(empty)* |
| `AWS_EXTERNAL_ID` | External ID for role assumption | *(empty)* |
| `AWS_REGIONS` | Comma-separated regions to scan | `us-east-1` |
| `AWS_ACCESS_KEY_ID` | Explicit access key (optional) | *(from env/profile)* |
| `AWS_SECRET_ACCESS_KEY` | Explicit secret key (optional) | *(from env/profile)* |
| `SCAN_INTERVAL_HOURS` | Hours between scheduled scans (server mode) | `6` |
| `STAGE_MODE` | Use mock data (no real AWS calls) | `false` |
| `DATABASE_URL` | Database connection string | `sqlite:///./scanner.db` |
| `HOST` | Server bind host | `0.0.0.0` |
| `PORT` | Server bind port | `8000` |

---

## Relationship to CostOps Platform

This is the open-source core of the [CostOps AWS Scanner](../costops-AWS-scanner/) platform. The full platform adds:

- Multi-tenant support with per-tenant IAM role assumption
- Keycloak SSO with JWT zero-trust auth on every endpoint
- Admin API for tenant/user/billing management
- React dashboard with drag-and-drop tiles
- AWS Cost Explorer integration (rightsizing, RI/Savings Plans utilization)
- Email reports, activity logging, billing model
- 55+ resource scanners (this package has the core 17)

The full scanner imports scanning functions from this package — one codebase, shared logic.

---

## License

MIT
