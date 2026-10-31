import json
from collections import Counter
from datetime import datetime, timezone

ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def write_reports(findings, project_id, json_path="report.json", md_path="report.md"):
    findings = sorted(findings, key=lambda f: ORDER.index(f.severity))
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    with open(json_path, "w") as fh:
        json.dump({"project": project_id, "generated": now,
                   "findings": [f.to_dict() for f in findings]}, fh, indent=2)

    counts = Counter(f.severity for f in findings)
    lines = [f"# Cloud Security Audit: {project_id}", f"_Generated {now}_", "",
             "| Severity | Count |", "|---|---|"]
    lines += [f"| {s} | {counts.get(s, 0)} |" for s in ORDER]
    lines += ["", "## Findings", ""]
    for f in findings:
        lines += [f"### [{f.severity}] {f.check_id}: {f.resource}",
                  f"- **Type:** {f.resource_type}",
                  f"- **Issue:** {f.description}",
                  f"- **Fix:** {f.recommendation}", ""]
    with open(md_path, "w") as fh:
        fh.write("\n".join(lines))
