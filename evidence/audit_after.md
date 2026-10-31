# Cloud Security Audit: sec-auditor-sandbox-1XXXX
_Generated 2026-10-31T02:54:20+00:00_

| Severity | Count |
|---|---|
| CRITICAL | 0 |
| HIGH | 5 |
| MEDIUM | 1 |
| LOW | 0 |

## Findings

### [HIGH] IAM-002: sec-auditor-sandbox-1xxxx
- **Type:** project.iam
- **Issue:** Primitive role roles/editor granted to serviceAccount:844293679862-compute@developer.gserviceaccount.com
- **Fix:** Replace with a predefined or custom role with only the needed permissions.

### [HIGH] IAM-003: sec-auditor-sandbox-1xxxx
- **Type:** project.iam
- **Issue:** Service account serviceAccount:844293679862-compute@developer.gserviceaccount.com has roles/editor
- **Fix:** Service accounts should use narrowly scoped roles.

### [HIGH] IAM-002: sec-auditor-sandbox-1xxxx
- **Type:** project.iam
- **Issue:** Primitive role roles/editor granted to serviceAccount:audit-demo-sa@sec-auditor-sandbox-1xxxx.iam.gserviceaccount.com
- **Fix:** Replace with a predefined or custom role with only the needed permissions.

### [HIGH] IAM-003: sec-auditor-sandbox-1xxxx
- **Type:** project.iam
- **Issue:** Service account serviceAccount:audit-demo-sa@sec-auditor-sandbox-1xxxx.iam.gserviceaccount.com has roles/editor
- **Fix:** Service accounts should use narrowly scoped roles.

### [HIGH] IAM-002: sec-auditor-sandbox-1xxxx
- **Type:** project.iam
- **Issue:** Primitive role roles/owner granted to user:you@example.com
- **Fix:** Replace with a predefined or custom role with only the needed permissions.

### [MEDIUM] FW-002: default-allow-icmp
- **Type:** compute.firewall
- **Issue:** Ingress allowed from 0.0.0.0/0 on non-sensitive ports.
- **Fix:** Restrict source ranges where possible.
