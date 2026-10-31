from googleapiclient import discovery
from .models import Finding

PRIMITIVE_ROLES = {"roles/owner": "HIGH", "roles/editor": "HIGH"}
PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


def audit_project_iam(project_id: str) -> list[Finding]:
    crm = discovery.build("cloudresourcemanager", "v1", cache_discovery=False)
    policy = crm.projects().getIamPolicy(
        resource=project_id,
        body={"options": {"requestedPolicyVersion": 3}},
    ).execute()

    findings = []
    for binding in policy.get("bindings", []):
        role = binding["role"]
        for member in binding["members"]:
            if member in PUBLIC_MEMBERS:
                findings.append(Finding(
                    check_id="IAM-001", severity="CRITICAL",
                    resource_type="project.iam", resource=project_id,
                    description=f"{role} granted to public principal {member}",
                    recommendation="Remove public principals from project IAM.",
                    details={"role": role, "member": member},
                ))
            elif role in PRIMITIVE_ROLES:
                findings.append(Finding(
                    check_id="IAM-002", severity=PRIMITIVE_ROLES[role],
                    resource_type="project.iam", resource=project_id,
                    description=f"Primitive role {role} granted to {member}",
                    recommendation="Replace with a predefined or custom role with only the needed permissions.",
                    details={"role": role, "member": member},
                ))
            if role in PRIMITIVE_ROLES and member.startswith("serviceAccount:"):
                findings.append(Finding(
                    check_id="IAM-003", severity="HIGH",
                    resource_type="project.iam", resource=project_id,
                    description=f"Service account {member} has {role}",
                    recommendation="Service accounts should use narrowly scoped roles.",
                    details={"role": role, "member": member},
                ))
    return findings
