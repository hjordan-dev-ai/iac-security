# IaC Security Scanner Bake-Off

A reproducible comparison harness for picking a Terraform IaC security scanner
to replace Stacklet's `c7n-left`. Five scanners run against the same pair of
manufactured-vulnerability Terraform stacks (one AWS, one Azure) and emit
GitLab SAST–compatible JSON reports. An aggregator merges those into a
comparison dataset and a self-contained HTML dashboard.

## Why this project exists

Our current toolchain pins an old Trivy that crashes on blank variables and
unknown `tfvars` files, and rule maintenance has become a tax. We need a
defensible, evidence-based decision on which scanner(s) to adopt going forward.
This repo gives the Director of CICD four answers:

1. Which tool catches the most planted issues with the fewest blind spots?
2. Which tool produces the richest report data?
3. Which tool handles `tfvars` / partial config gracefully (the c7n-left pain point)?
4. Which tool's JSON is easiest to render in our internal UI?

## The six scanners

| Tool | License | GitLab SAST | Notes |
|---|---|---|---|
| **Checkov** (Bridgecrew) | Apache 2.0 | Native (`-o gitlab_sast`) | Largest community, Python custom rules |
| **KICS** (Checkmarx) | Apache 2.0 | Native (`--report-formats glsast`) | 2,400+ Rego rules |
| **Trivy** (Aqua) | Apache 2.0 | SARIF → converted | Direct comparison vs. broken bundled version |
| **Snyk IaC** | Freemium | SARIF → converted | Requires `SNYK_TOKEN` repo secret |
| **Semgrep IaC** | LGPL 2.1 | Native (`--gitlab-sast`) | Strongest custom-rule story |
| **c7n-left** (Cloud Custodian) | Apache 2.0 | JSON → converted | The incumbent. No built-in rules — uses custom YAML policies in `policies/` |

> See [`SECURITY.md`](SECURITY.md) for supply-chain pin rationale — Trivy and
> KICS GitHub Actions were reportedly compromised in March 2026 and we run
> those scanners via binary/container instead of the marketplace actions.

## Repo layout

```
.github/workflows/        bakeoff.yml — 6 parallel scanner jobs + aggregator
terraform/aws/            Realistic AWS stack with 20 planted issues
terraform/azure/          Realistic Azure stack with 21 planted issues
policies/                 c7n-left YAML policies (starter set for the bake-off)
tools/normalize/          SARIF/c7n → GitLab SAST converters (stdlib only)
tools/aggregate/          Merge reports → comparison.json + comparison.html
tools/ground_truth/       Score per-tool recall against EXPECTED_FINDINGS.md
```

Each cloud has an `EXPECTED_FINDINGS.md` ground-truth table listing every
planted issue with its expected check IDs. The ground-truth comparator uses
that table to compute per-tool recall.

## Running the bake-off

### In CI (GitHub Actions)

Push a branch and `bakeoff.yml` runs all five scanners as parallel matrix
jobs (one job per scanner × cloud). After every scanner finishes, the
`aggregate` job (declared via `needs:`) merges all artifacts and produces
the `bake-off-results` bundle containing:

- `comparison.json` — structured per-tool comparison dataset
- `comparison.html` — self-contained dashboard (open in browser, no server)
- `summary.md` — markdown summary (also posted to the workflow step summary)
- `precision_recall.json` — per-tool recall against ground truth
- `reports/` — every raw and normalized scanner output

You can also dispatch `aggregate-reports.yml` manually after re-running any
individual scan.

### Locally

```bash
# Install Terraform 1.5+ and any of the scanners you want to test, then:
cd terraform/aws
terraform init -backend=false
terraform validate    # should pass — issues are misconfigs, not syntax errors

# Run any scanner directly, e.g. Checkov:
checkov -d . -o gitlab_sast,json --output-file-path /tmp/checkov-out

# Convert SARIF output (Trivy/Snyk) to GitLab SAST:
python tools/normalize/sarif_to_gitlab_sast.py \
  /tmp/trivy.sarif \
  /tmp/gl-sast-report-trivy-aws.json \
  --scanner-id trivy --scanner-name Trivy --vendor "Aqua Security"

# Aggregate (point at a directory of gl-sast-report-*.json files):
python tools/aggregate/aggregate.py --input /tmp/reports --output /tmp/out
python tools/aggregate/render_html.py \
  --input /tmp/out/comparison.json \
  --output /tmp/out/comparison.html
open /tmp/out/comparison.html
```

## The tfvars repro

Each `variables.tf` declares variables (`environment`, `allowed_ssh_cidrs` /
`allowed_management_cidrs`) with **no default** that are also **not provided**
in `terraform.tfvars`. This is the exact condition that crashes the bundled
Trivy in our current c7n-left toolchain. The bake-off grades each scanner on
how it handles this:

- **Crash** — worst (current state with old Trivy bundled by c7n-left)
- **Skip silently** — acceptable but loses coverage
- **Warn and continue** — what we want from the replacement

## Decision matrix (filled in after first full run)

| Tool | Recall | Tfvars | GitLab SAST | Custom rules | Verdict |
|---|---|---|---|---|---|
| Checkov | _tbd_ | _tbd_ | Native | Python | _tbd_ |
| KICS | _tbd_ | _tbd_ | Native | Rego | _tbd_ |
| Trivy | _tbd_ | _tbd_ | Converted | Rego | _tbd_ |
| Snyk IaC | _tbd_ | _tbd_ | Converted | Proprietary | _tbd_ |
| Semgrep | _tbd_ | _tbd_ | Native | YAML | _tbd_ |
| c7n-left | _tbd_ | _tbd_ | Converted | YAML (Cloud Custodian DSL) | _tbd_ |

## Known reporting quirks

- **Checkov severity is always `Unknown`** in the GitLab SAST output. Open-source
  Checkov leaves the severity field blank — severities live in the paid
  Bridgecrew/Prisma policy catalog. This is upstream behavior, not a converter
  bug. The dashboard still shows totals; severity buckets just collapse into
  the Unknown column for Checkov.
- **Recall is matched by file + resource line range**, not by rule ID. Different
  scanners use wildly different rule-ID conventions (`CKV_AWS_24` vs `AWS-0107`
  vs `terraform.aws.security.aws-ec2-...`). The matcher parses the actual `.tf`
  files for resource line ranges and credits a tool if it flagged anything in
  the right block.
- **Tool overlap matrix uses `(file_basename, line)`** — also rule-ID-agnostic
  for the same reason. The diagonal shows each tool's unique source-location
  count (which is lower than total findings since most tools fire multiple
  rules at the same resource).

## What's intentionally out of scope

- Running scanners against real internal Terraform — this is a synthetic bake-off
- Procurement / contract negotiation
- Migrating production GitLab CI pipelines (separate effort once a winner is picked)
- Custom rule authoring — we're benchmarking out-of-the-box rule libraries
