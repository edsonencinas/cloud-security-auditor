# Cloud Security Audit: sec-auditor-sandbox-1xxxx
_Generated 2026-10-31T02:12:33+00:00_

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
- **Issue:** Primitive role roles/owner granted to user:you@example.com
- **Fix:** Replace with a predefined or custom role with only the needed permissions.

### [HIGH] FW-001: default-allow-rdp
- **Type:** compute.firewall
- **Issue:** Ingress from 0.0.0.0/0 exposes: 3389
- **Fix:** Restrict source ranges to trusted CIDRs or use IAP TCP forwarding.

### [HIGH] FW-001: default-allow-ssh
- **Type:** compute.firewall
- **Issue:** Ingress from 0.0.0.0/0 exposes: 22
- **Fix:** Restrict source ranges to trusted CIDRs or use IAP TCP forwarding.

### [MEDIUM] FW-002: default-allow-icmp
- **Type:** compute.firewall
- **Issue:** Ingress allowed from 0.0.0.0/0 on non-sensitive ports.
- **Fix:** Restrict source ranges where possible.
