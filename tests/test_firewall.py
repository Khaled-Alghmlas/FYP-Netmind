import device_control as dc

INPUT_RAW = """Chain INPUT (policy ACCEPT)
num  target     prot opt source               destination
1    DROP       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:2222
2    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22
"""
FORWARD_RAW = """Chain FORWARD (policy ACCEPT)
num  target     prot opt source               destination
1    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22
"""


def test_parse_tags_rules_with_chain():
    rules = dc._parse_iptables_rules(INPUT_RAW, "INPUT")
    assert [(r["chain"], r["port"], r["action"]) for r in rules] == [
        ("INPUT", 2222, "DROP"), ("INPUT", 22, "ACCEPT")]


def test_effective_rules_are_per_chain():
    rules = dc._parse_iptables_rules(INPUT_RAW, "INPUT") + dc._parse_iptables_rules(FORWARD_RAW, "FORWARD")
    eff = dc._effective_port_rules(rules)
    assert ("INPUT", 22, "tcp") in eff and ("FORWARD", 22, "tcp") in eff


class FakeContainer:
    """Tiny iptables emulator: keeps a rule list per chain."""

    def __init__(self):
        self.chains = {"INPUT": [], "FORWARD": []}
        self.persisted = False

    def exec_run(self, cmd):
        if cmd[0] == "sh":
            self.persisted = True
            return 0, b""
        assert cmd[0] == "iptables"
        op, chain = cmd[1], cmd[2]
        if op == "-L":
            lines = [f"Chain {chain} (policy ACCEPT)", "num  target     prot opt source               destination"]
            for i, (proto, port, action) in enumerate(self.chains[chain], 1):
                lines.append(f"{i}    {action}     {proto}  --  0.0.0.0/0            0.0.0.0/0            {proto} dpt:{port}")
            return 0, ("\n".join(lines) + "\n").encode()
        proto = cmd[cmd.index("-p") + 1]
        port = int(cmd[cmd.index("--dport") + 1])
        action = cmd[cmd.index("-j") + 1]
        rule = (proto, port, action)
        if op == "-C":
            return (0 if rule in self.chains[chain] else 1), b""
        if op == "-D":
            self.chains[chain].remove(rule)
            return 0, b""
        if op == "-I":
            self.chains[chain].insert(0, rule)
            return 0, b""
        raise AssertionError(cmd)


def patch(monkeypatch, c):
    fw = {"id": "fw-branch1", "type": "firewall", "container": "clab-x-fw-branch1", "owner": None}
    monkeypatch.setattr(dc, "_load_registry", lambda: [fw])
    monkeypatch.setattr(dc, "_client", type("C", (), {"containers": type("K", (), {"get": staticmethod(lambda n: c)})})())


def test_block_port_applies_to_input_and_forward(monkeypatch):
    c = FakeContainer()
    patch(monkeypatch, c)
    res = dc.block_port("fw-branch1", 22)
    assert res["chains"] == ["INPUT", "FORWARD"]
    assert c.chains["INPUT"] == [("tcp", 22, "DROP")]
    assert c.chains["FORWARD"] == [("tcp", 22, "DROP")]
    assert c.persisted


def test_block_then_allow_leaves_single_rule_and_is_idempotent(monkeypatch):
    c = FakeContainer()
    patch(monkeypatch, c)
    dc.block_port("fw-branch1", 22)
    dc.block_port("fw-branch1", 22)
    assert c.chains["FORWARD"] == [("tcp", 22, "DROP")]
    dc.allow_port("fw-branch1", 22)
    assert c.chains["FORWARD"] == [("tcp", 22, "ACCEPT")]
    assert c.chains["INPUT"] == [("tcp", 22, "ACCEPT")]


def test_list_and_audit_cover_forward_chain(monkeypatch):
    c = FakeContainer()
    c.chains["FORWARD"] = [("tcp", 23, "ACCEPT")]
    patch(monkeypatch, c)
    rules = dc.list_firewall_rules("fw-branch1")["rules"]
    assert any(r["chain"] == "FORWARD" and r["port"] == 23 for r in rules)
    audit = dc.audit_firewall("fw-branch1")
    assert not audit["clean"] and "FORWARD" in audit["findings"][0]
    ports = dc.get_open_ports("fw-branch1")["open_ports"]
    assert {"port": 23, "protocol": "tcp", "chain": "FORWARD", "source": "0.0.0.0/0"} in ports
