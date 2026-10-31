# Cloud Security Audit: sec-auditor-sandbox-1xxxx
_Generated 2026-10-31T02:47:56+00:00_

| Severity | Count |
|---|---|
| CRITICAL | 1 |
| HIGH | 8 |
| MEDIUM | 2 |
| LOW | 1 |

## Findings

### [CRITICAL] GCS-001: audit-demo-public-372414a3
- **Type:** storage.bucket
- **Issue:** Bucket grants roles/storage.objectViewer to ['allUsers']
- **Fix:** Remove public principals and enforce public access prevention.

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

### [HIGH] FW-001: allow-ssh-anywhere
- **Type:** compute.firewall
- **Issue:** Ingress from 0.0.0.0/0 exposes: 22, 3389
- **Fix:** Restrict source ranges to trusted CIDRs or use IAP TCP forwarding.

### [HIGH] FW-001: default-allow-rdp
- **Type:** compute.firewall
- **Issue:** Ingress from 0.0.0.0/0 exposes: 3389
- **Fix:** Restrict source ranges to trusted CIDRs or use IAP TCP forwarding.

### [HIGH] FW-001: default-allow-ssh
- **Type:** compute.firewall
- **Issue:** Ingress from 0.0.0.0/0 exposes: 22
- **Fix:** Restrict source ranges to trusted CIDRs or use IAP TCP forwarding.

### [MEDIUM] GCS-002: audit-demo-public-372414a3
- **Type:** storage.bucket
- **Issue:** Public access prevention is not enforced.
- **Fix:** Set public_access_prevention = enforced.

### [MEDIUM] FW-002: default-allow-icmp
- **Type:** compute.firewall
- **Issue:** Ingress allowed from 0.0.0.0/0 on non-sensitive ports.
- **Fix:** Restrict source ranges where possible.

### [LOW] GCS-003: audit-demo-public-372414a3
- **Type:** storage.bucket
- **Issue:** Uniform bucket-level access is disabled (legacy ACLs possible).
- **Fix:** Enable uniform bucket-level access.
