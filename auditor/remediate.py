import logging
from google.cloud import storage
from googleapiclient import discovery
from .storage_checks import PUBLIC_MEMBERS

log = logging.getLogger("remediation")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def _confirm(msg: str, assume_yes: bool) -> bool:
    return assume_yes or input(f"{msg} [y/N]: ").strip().lower() == "y"


def fix_bucket_public_iam(client, bucket_name, apply, assume_yes):
    bucket = client.bucket(bucket_name)
    policy = bucket.get_iam_policy(requested_policy_version=3)
    new_bindings = []
    for b in policy.bindings:
        members = set(b["members"]) - PUBLIC_MEMBERS
        if members:
            new_bindings.append({**b, "members": members})
    log.info("[%s] remove public members from IAM policy", bucket_name)
    if apply and _confirm(f"Remove public access from {bucket_name}?", assume_yes):
        policy.bindings = new_bindings
        bucket.set_iam_policy(policy)
        log.info("[%s] APPLIED", bucket_name)


def fix_bucket_settings(client, bucket_name, apply, assume_yes):
    bucket = client.get_bucket(bucket_name)
    log.info("[%s] enforce PAP + uniform bucket-level access", bucket_name)
    if apply and _confirm(f"Harden settings on {bucket_name}?", assume_yes):
        bucket.iam_configuration.public_access_prevention = "enforced"
        bucket.iam_configuration.uniform_bucket_level_access_enabled = True
        bucket.patch()
        log.info("[%s] APPLIED", bucket_name)


def fix_firewall(compute, project, rule_name, apply, assume_yes):
    # Safest automated action: disable the rule (reversible), do not delete it.
    log.info("[%s] disable firewall rule that is open to 0.0.0.0/0", rule_name)
    if apply and _confirm(f"Disable firewall rule {rule_name}?", assume_yes):
        compute.firewalls().patch(
            project=project, firewall=rule_name, body={"disabled": True}
        ).execute()
        log.info("[%s] APPLIED (disabled)", rule_name)


def remediate(findings, project_id, apply=False, assume_yes=False):
    client = storage.Client(project=project_id)
    compute = discovery.build("compute", "v1", cache_discovery=False)
    mode = "APPLY" if apply else "DRY-RUN"
    log.info("Remediation mode: %s", mode)

    # Fix public IAM first, then bucket settings, then firewalls
    order = {"GCS-001": 0, "GCS-002": 1, "GCS-003": 1, "FW-001": 2}
    todo = sorted((f for f in findings if f.remediable and f.check_id in order),
                  key=lambda f: order[f.check_id])
    done = set()
    for f in todo:
        key = (f.check_id in ("GCS-002", "GCS-003") and "settings" or f.check_id, f.resource)
        if key in done:
            continue
        done.add(key)
        if f.check_id == "GCS-001":
            fix_bucket_public_iam(client, f.resource, apply, assume_yes)
        elif f.check_id in ("GCS-002", "GCS-003"):
            fix_bucket_settings(client, f.resource, apply, assume_yes)
        elif f.check_id == "FW-001":
            fix_firewall(compute, project_id, f.resource, apply, assume_yes)
