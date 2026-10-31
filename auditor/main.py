import argparse
import sys

from .storage_checks import audit_buckets
from .iam_checks import audit_project_iam
from .firewall_checks import audit_firewalls
from .remediate import remediate
from .report import write_reports


def main():
    ap = argparse.ArgumentParser(description="Automated GCP Security Auditor")
    ap.add_argument("--project", required=True)
    ap.add_argument("--checks", nargs="+", default=["storage", "iam", "firewall"],
                    choices=["storage", "iam", "firewall"])
    ap.add_argument("--remediate", action="store_true",
                    help="Apply fixes (default is dry-run).")
    ap.add_argument("--yes", action="store_true",
                    help="Skip confirmation prompts when remediating.")
    ap.add_argument("--fail-on", default="HIGH",
                    choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    args = ap.parse_args()

    findings = []
    if "storage" in args.checks:
        findings += audit_buckets(args.project)
    if "iam" in args.checks:
        findings += audit_project_iam(args.project)
    if "firewall" in args.checks:
        findings += audit_firewalls(args.project)

    write_reports(findings, args.project)
    print(f"{len(findings)} findings written to report.json / report.md")

    if any(f.remediable for f in findings):
        remediate(findings, args.project, apply=args.remediate, assume_yes=args.yes)

    levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    threshold = levels.index(args.fail_on)
    if any(levels.index(f.severity) >= threshold for f in findings):
        sys.exit(1)  # non-zero exit lets CI/CD gate on results


if __name__ == "__main__":
    main()
