# Automated Cloud Security Auditor (GCP)

![CI](https://github.com/YOUR-USERNAME/cloud-security-auditor/actions/workflows/security.yml/badge.svg)

A two-layer cloud security tool for Google Cloud Platform:

1. **Shift-left:** Terraform is scanned with **Checkov** (built-in and custom policies) before anything is deployed.
2. **Runtime:** A **Python auditor** calls GCP APIs, finds misconfigurations in live resources, writes a report, and can safely remediate the low-risk ones.

**Skills demonstrated:** Python, Google Cloud APIs, Terraform, policy-as-code, CI/CD gating, least privilege, and automated remediation.

---

## Why this exists

Most cloud breaches come from misconfiguration, not exploits: a public bucket, SSH open to the internet, an over-privileged service account. These issues enter through new code and through manual console changes. Scanning only code misses the second source, and auditing only live resources finds problems after they are already exposed. This project covers both.

## Results

I deployed an intentionally insecure stack to an isolated sandbox project, audited it, remediated it, and audited again.

| Severity | Before | After | Change |
|---|---|---|---|
| CRITICAL | 1 | 0 | -1 |
| HIGH | 8 | 5 | -3 |
| MEDIUM | 2 | 1 | -1 |
| LOW | 1 | 0 | -1 |
| **Total** | **12** | **6** | **-6** |

One run of automated remediation resolved 6 of 12 findings, including the only CRITICAL one (a publicly readable bucket). The remaining 6 are IAM role findings and a low-risk ICMP rule that are **left for human review by design** (see [Design decisions](#design-decisions)).

Full reports: [`evidence/audit_before.md`](evidence/audit_before.md) and [`evidence/audit_after.md`](evidence/audit_after.md).
Checkov output: [`evidence/checkov_insecure.txt`](evidence/checkov_insecure.txt) and [`evidence/checkov_secure.txt`](evidence/checkov_secure.txt).

<!-- Add screenshots here: Checkov failing on insecure, Checkov passing on secure, CI run, report.md -->

## Architecture

```
Developer -> git push -> GitHub Actions
                           |-- terraform fmt / validate
                           |-- checkov (must pass on terraform/secure)
                           '-- pytest

Terraform -> deploys test resources to an isolated sandbox GCP project

Python auditor -> Cloud Storage API + Resource Manager API + Compute API
               -> findings (JSON + Markdown report)
               -> optional remediation (dry-run by default)
```

## What it checks

| ID | Severity | Check | Auto-remediation |
|---|---|---|---|
| GCS-001 | CRITICAL | Bucket grants access to `allUsers` or `allAuthenticatedUsers` | Yes: removes public members |
| GCS-002 | MEDIUM | Public access prevention not enforced | Yes: enforces it |
| GCS-003 | LOW | Uniform bucket-level access disabled | Yes: enables it |
| IAM-001 | CRITICAL | Public principal in project IAM policy | No |
| IAM-002 | HIGH | Primitive role (`owner`, `editor`) granted | No |
| IAM-003 | HIGH | Service account holds a primitive role | No |
| FW-001 | HIGH / CRITICAL | Ingress from `0.0.0.0/0` exposing SSH (22), RDP (3389), or all ports | Yes: disables the rule |
| FW-002 | MEDIUM | Ingress from `0.0.0.0/0` on non-sensitive ports | No |

Firewall logic handles port ranges (for example `20-30` covers SSH), `all` protocol rules, disabled rules, and egress/deny rules.

## Repository layout

```
cloud-security-auditor/
|-- terraform/
|   |-- insecure/        # intentionally vulnerable stack (demo)
|   '-- secure/          # hardened version; must pass Checkov
|-- checkov_policies/
|   '-- no_open_ingress.yaml   # custom policy CKV2_CUSTOM_1
|-- auditor/
|   |-- models.py              # Finding dataclass
|   |-- storage_checks.py
|   |-- iam_checks.py
|   |-- firewall_checks.py
|   |-- remediate.py
|   |-- report.py
|   '-- main.py                # CLI
|-- tests/
|-- evidence/                  # before/after reports and Checkov output
|-- .github/workflows/security.yml
'-- requirements.txt
```

## Quick start

**Requirements:** Python 3.10+, Terraform 1.5+, `gcloud`, and a **dedicated sandbox GCP project** (never point this at production). Google Cloud Shell has everything except the Python packages.

```bash
git clone https://github.com/YOUR-USERNAME/cloud-security-auditor.git
cd cloud-security-auditor
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export PROJECT_ID="your-sandbox-project-id"
gcloud config set project $PROJECT_ID
gcloud services enable storage.googleapis.com compute.googleapis.com \
  cloudresourcemanager.googleapis.com iam.googleapis.com
```

### 1. Scan Terraform before deploying

```bash
# Expected to FAIL (this is the demo of what gets caught)
checkov -d terraform/insecure --framework terraform --external-checks-dir checkov_policies

# Expected to PASS
checkov -d terraform/secure --framework terraform --external-checks-dir checkov_policies
```

### 2. Audit live resources (read-only)

```bash
python -m auditor.main --project $PROJECT_ID
cat report.md
```

The exit code is non-zero when findings at or above `--fail-on` (default `HIGH`) exist, so the tool can gate a pipeline.

### 3. Remediate

```bash
# Dry-run is the default: logs what it would change, changes nothing
python -m auditor.main --project $PROJECT_ID

# Apply fixes, with a y/N prompt per change
python -m auditor.main --project $PROJECT_ID --remediate

# Non-interactive (for automation, use with care)
python -m auditor.main --project $PROJECT_ID --remediate --yes
```

### CLI options

| Flag | Description |
|---|---|
| `--project` | GCP project ID to audit (required) |
| `--checks` | Subset of `storage iam firewall` (default: all) |
| `--remediate` | Apply fixes instead of dry-run |
| `--yes` | Skip confirmation prompts |
| `--fail-on` | Lowest severity that causes a non-zero exit (default `HIGH`) |

### 4. Demo end to end

```bash
cd terraform/insecure
terraform init
terraform apply -var="project_id=$PROJECT_ID"
cd ../..

python -m auditor.main --project $PROJECT_ID               # before
python -m auditor.main --project $PROJECT_ID --remediate   # fix
python -m auditor.main --project $PROJECT_ID               # after

cd terraform/insecure && terraform destroy -var="project_id=$PROJECT_ID"
```

## Design decisions

- **Two layers, not one.** Checkov catches mistakes in new code. The auditor catches console changes, drift, and pre-existing resources. For example, the audit flagged the default network's `default-allow-ssh` and `default-allow-rdp` rules, which exist in no Terraform file and so were invisible to Checkov.
- **Dry-run by default.** Nothing changes without the explicit `--remediate` flag, plus a confirmation prompt per change, and every action is logged.
- **IAM is never auto-remediated.** Removing a role can silently break workloads, so the tool reports and recommends but leaves the decision to a human. The same applies to the low-risk ICMP finding.
- **Disable, don't delete.** Open firewall rules are disabled, which is reversible, rather than deleted.
- **Ordered fixes.** Public IAM bindings are removed before public access prevention is enforced, and duplicate per-bucket fixes are skipped.
- **Least privilege for the tool itself.** The sandbox uses separate read-only (`auditorReadOnly`) and write (`auditorRemediator`) custom roles, so the auditing identity cannot change anything. No service account keys are created or committed.
- **Testable logic.** Firewall evaluation (`evaluate_rule`) is separated from API calls, so it is covered by unit tests that need no cloud access.
- **Documented exceptions.** The secure stack's log bucket suppresses `CKV_GCP_62` with a written reason (a log destination does not log to itself) rather than forcing every check green.
- **Narrow custom policy.** `CKV2_CUSTOM_1` fails any firewall rule that allows `0.0.0.0/0`, regardless of port, mirroring the runtime auditor's logic in the pre-deploy stage.

## Important: remediation fixes the cloud, not the code

Automated remediation changes live resources only. The Terraform files still describe the old, insecure state, so running `terraform apply` afterwards would **re-introduce the problem**, and `terraform plan` will show drift. In a real workflow, a remediation must be followed by a pull request that fixes the Terraform. That is exactly what the `terraform/secure` stack represents.

## CI/CD

`.github/workflows/security.yml` runs on every pull request and push to `main`:

1. `terraform fmt -check`, `init`, and `validate` on the secure stack
2. Checkov on `terraform/secure` (**must pass**, blocks the merge)
3. Checkov on `terraform/insecure` with `--soft-fail` (documents the expected failures)
4. `pytest`

Recommended: enable branch protection on `main` and require this workflow to pass.

## Limitations

- Covers three resource categories (Cloud Storage, project IAM, VPC firewall rules) in a single project. It does not yet check folder or organization IAM policies, per-bucket IAM conditions, VMs, or databases.
- IAM checks flag every `owner` and `editor` binding, including legitimate ones, such as the project owner. There is no allow-list yet.
- Firewall checks only consider `0.0.0.0/0`, not `::/0` or very large CIDR ranges.
- Reports are local files; findings are not yet pushed to a central system.
- Pinned to Checkov 3.3.30 for the evidence in this repo. Rule IDs and results can change between versions.

## Roadmap

- [ ] Run the auditor on a schedule (Cloud Run Job + Cloud Scheduler) with keyless auth (Workload Identity Federation)
- [ ] Separate "tooling" and "target" projects for cross-project auditing
- [ ] Map each finding to CIS Google Cloud Foundations Benchmark controls
- [ ] Export findings to Security Command Center or BigQuery
- [ ] Slack/email alerts for CRITICAL findings
- [ ] Allow-list file for approved exceptions
- [ ] Checks for VMs with external IPs and default service accounts, CMEK on buckets, and `::/0` ranges
- [ ] Generate a suggested Terraform patch per finding

## Cleanup

```bash
cd terraform/insecure && terraform destroy -var="project_id=$PROJECT_ID"
gcloud projects delete $PROJECT_ID   # optional: removes the whole sandbox
```

## Safety notice

This project deliberately deploys vulnerable resources. Use an isolated sandbox project with a budget alert, and never run `--remediate` against a project that holds real workloads.

## License

MIT (add a `LICENSE` file)
