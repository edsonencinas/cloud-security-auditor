from googleapiclient import discovery
from .models import Finding

SENSITIVE_PORTS = {"22": "SSH", "3389": "RDP"}


def _ports_exposed(allowed_rules: list[dict]) -> list[str]:
    """Return a list of risky ports/protocols exposed by the allowed blocks."""
    exposed = []
    for rule in allowed_rules:
        proto = rule.get("IPProtocol", "")
        ports = rule.get("ports")
        if proto == "all" or (proto in ("tcp", "udp") and not ports):
            exposed.append("ALL")
            continue
        for p in ports or []:
            if "-" in p:
                lo, hi = (int(x) for x in p.split("-"))
                for sensitive in SENSITIVE_PORTS:
                    if lo <= int(sensitive) <= hi:
                        exposed.append(sensitive)
            elif p in SENSITIVE_PORTS:
                exposed.append(p)
    return sorted(set(exposed))


def evaluate_rule(rule: dict, project_id: str) -> list[Finding]:
    if rule.get("disabled") or rule.get("direction") != "INGRESS":
        return []
    if "0.0.0.0/0" not in rule.get("sourceRanges", []):
        return []
    if not rule.get("allowed"):
        return []  # deny rules are fine

    exposed = _ports_exposed(rule["allowed"])
    if not exposed:
        return [Finding(
            check_id="FW-002", severity="MEDIUM",
            resource_type="compute.firewall", resource=rule["name"],
            description="Ingress allowed from 0.0.0.0/0 on non-sensitive ports.",
            recommendation="Restrict source ranges where possible.",
            remediable=False,
            details={"project": project_id},
        )]
    severity = "CRITICAL" if "ALL" in exposed else "HIGH"
    return [Finding(
        check_id="FW-001", severity=severity,
        resource_type="compute.firewall", resource=rule["name"],
        description=f"Ingress from 0.0.0.0/0 exposes: {', '.join(exposed)}",
        recommendation="Restrict source ranges to trusted CIDRs or use IAP TCP forwarding.",
        remediable=True,
        details={"project": project_id, "exposed": exposed},
    )]


def audit_firewalls(project_id: str) -> list[Finding]:
    compute = discovery.build("compute", "v1", cache_discovery=False)
    findings = []
    request = compute.firewalls().list(project=project_id)
    while request is not None:
        response = request.execute()
        for rule in response.get("items", []):
            findings.extend(evaluate_rule(rule, project_id))
        request = compute.firewalls().list_next(request, response)
    return findings
