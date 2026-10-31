from google.cloud import storage
from .models import Finding

PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


def audit_buckets(project_id: str) -> list[Finding]:
    client = storage.Client(project=project_id)
    findings = []

    for bucket in client.list_buckets():
        policy = bucket.get_iam_policy(requested_policy_version=3)

        # 1. Public IAM bindings
        for binding in policy.bindings:
            exposed = PUBLIC_MEMBERS.intersection(binding["members"])
            if exposed:
                findings.append(Finding(
                    check_id="GCS-001",
                    severity="CRITICAL",
                    resource_type="storage.bucket",
                    resource=bucket.name,
                    description=f"Bucket grants {binding['role']} to {sorted(exposed)}",
                    recommendation="Remove public principals and enforce public access prevention.",
                    remediable=True,
                    details={"role": binding["role"], "members": sorted(exposed)},
                ))

        # 2. Public access prevention
        if bucket.iam_configuration.public_access_prevention != "enforced":
            findings.append(Finding(
                check_id="GCS-002",
                severity="MEDIUM",
                resource_type="storage.bucket",
                resource=bucket.name,
                description="Public access prevention is not enforced.",
                recommendation="Set public_access_prevention = enforced.",
                remediable=True,
            ))

        # 3. Uniform bucket-level access
        if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
            findings.append(Finding(
                check_id="GCS-003",
                severity="LOW",
                resource_type="storage.bucket",
                resource=bucket.name,
                description="Uniform bucket-level access is disabled (legacy ACLs possible).",
                recommendation="Enable uniform bucket-level access.",
                remediable=True,
            ))
    return findings
