from auditor.firewall_checks import evaluate_rule


def rule(**kw):
    base = {"name": "r", "direction": "INGRESS", "disabled": False,
            "sourceRanges": ["0.0.0.0/0"],
            "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]}
    base.update(kw)
    return base


def test_open_ssh_is_high():
    f = evaluate_rule(rule(), "p")
    assert f[0].check_id == "FW-001" and f[0].severity == "HIGH"


def test_all_ports_is_critical():
    f = evaluate_rule(rule(allowed=[{"IPProtocol": "all"}]), "p")
    assert f[0].severity == "CRITICAL"


def test_port_range_covering_ssh():
    f = evaluate_rule(rule(allowed=[{"IPProtocol": "tcp", "ports": ["20-30"]}]), "p")
    assert "22" in f[0].details["exposed"]


def test_restricted_source_ok():
    assert evaluate_rule(rule(sourceRanges=["10.0.0.0/8"]), "p") == []


def test_disabled_rule_ignored():
    assert evaluate_rule(rule(disabled=True), "p") == []
