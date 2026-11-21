"""Issue #12: the services run on plain fakes - no Docker daemon, no docker/requests import, no API key."""
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from iptables import effective_port_rules, parse_rules
from models import Device
from services import CameraService, DeviceService, FirewallService

AGENT_DIR = Path(__file__).resolve().parent.parent / "agent"

REGISTRY = [
    {"id": "host-khalid", "type": "host", "owner": "khalid", "container": "c-host-khalid", "ip": "172.20.20.8"},
    {"id": "cam-khalid", "type": "camera", "owner": "khalid", "container": "c-cam-khalid", "ip": "172.20.20.10"},
    {"id": "host-khalil", "type": "host", "owner": "khalil", "container": "c-host-khalil", "ip": "172.20.20.9"},
    {"id": "fw-branch1", "type": "firewall", "owner": None, "container": "c-fw", "ip": "172.20.20.2"},
]


class Box:
    def __init__(self, status="running", rules=None, creds="admin", name="box"):
        self.status = status
        self.name = name
        self.rules = rules if rules is not None else {"INPUT": [], "FORWARD": []}
        self.creds = creds
        self.persisted = False
        self.stopped_with = None

    def start(self):
        self.status = "running"

    def stop(self, timeout=10):
        self.stopped_with = timeout
        self.status = "exited"

    def exec_run(self, cmd):
        if cmd[0] == "cat":
            return 0, self.creds.encode()
        if cmd[0] == "sh":
            if "iptables-save" in cmd[2]:
                self.persisted = True
            else:
                self.creds = cmd[2].split("'%s' ")[1].split(" >")[0].strip("'")
            return 0, b""
        assert cmd[0] == "iptables"
        op, chain = cmd[1], cmd[2]
        if op == "-L":
            lines = [f"Chain {chain} (policy ACCEPT)", "num  target     prot opt source               destination"]
            for i, (proto, port, action) in enumerate(self.rules[chain], 1):
                lines.append(f"{i}    {action}     {proto}  --  0.0.0.0/0            0.0.0.0/0            {proto} dpt:{port}")
            return 0, ("\n".join(lines) + "\n").encode()
        proto, port, action = cmd[cmd.index("-p") + 1], int(cmd[cmd.index("--dport") + 1]), cmd[cmd.index("-j") + 1]
        rule = (proto, port, action)
        if op == "-C":
            return (0 if rule in self.rules[chain] else 1), b""
        if op == "-D":
            self.rules[chain].remove(rule)
        elif op == "-I":
            self.rules[chain].insert(0, rule)
        return 0, b""


def client_for(boxes):
    def get(name):
        if name not in boxes:
            raise KeyError(name)
        return boxes[name]
    return lambda: NS(containers=NS(get=get, list=lambda all=False: list(boxes.values())))


def resolver(query):
    return [d for d in REGISTRY if d["id"] == query]


# --- DeviceService ---------------------------------------------------------------------------
def devices(boxes=None, **kwargs):
    boxes = boxes or {d["container"]: Box(name=d["container"]) for d in REGISTRY}
    return DeviceService(lambda: REGISTRY, client_for(boxes), **kwargs), boxes


def test_find_by_id_owner_and_typo():
    svc, _ = devices()
    assert [d.id for d in svc.find("host-khalid")] == ["host-khalid"]
    assert [d.id for d in svc.find("Khalid")] == ["host-khalid", "cam-khalid"]
    assert [d.id for d in svc.find("host-khaled")] == ["host-khalid"]
    assert svc.find("host-khal") == []                      # between khalid and khalil: never guess


def test_status_reports_not_found_for_a_missing_container():
    class Missing(Exception):
        pass

    def get(name):
        raise Missing(name)

    svc = DeviceService(lambda: REGISTRY, lambda: NS(containers=NS(get=get)), not_found=(Missing,))
    assert svc.status("host-khalid")[0].status == "not found"


def test_power_off_then_on_calls_the_hooks_and_the_reconnect():
    changes, reconnects = [], []
    svc, boxes = devices(on_change=lambda: changes.append(1), reconnect=lambda i: reconnects.append(i) or {"ok": True})
    off = svc.power_off("host-khalid")[0]
    assert off.new_status == "offline" and off.already_in_that_state is False
    assert boxes["c-host-khalid"].stopped_with == 2
    on = svc.power_on("host-khalid")[0]
    assert on.link == {"ok": True} and reconnects == ["host-khalid"] and len(changes) == 2
    again = svc.power_on("host-khalid")[0]                 # already running: nothing changes
    assert again.already_in_that_state is True and again.link is None and len(reconnects) == 1


def test_power_result_dumps_to_the_dict_the_tools_expect():
    svc, _ = devices()
    entry = svc.power_off("host-khalil")[0].model_dump(exclude_none=True)
    assert set(entry) == {"id", "already_in_that_state", "previous_status", "new_status"}   # no "link" key
    assert entry["id"] == "host-khalil" and entry["new_status"] == "offline"


def test_dashboard_rows_work_without_a_runtime_error_class():
    svc, _ = devices()
    rows = svc.dashboard_rows()
    assert len(rows) == 4 and all(r.status == "online" for r in rows)


def test_a_custom_resolver_decides_which_devices_an_action_touches():
    svc, boxes = devices(resolver=lambda q: [REGISTRY[2]])
    svc.power_off("anything")
    assert boxes["c-host-khalil"].status == "exited" and boxes["c-host-khalid"].status == "running"


# --- FirewallService -------------------------------------------------------------------------
def firewall(**kwargs):
    box = Box()
    return FirewallService(resolver, client_for({"c-fw": box}), **kwargs), box


def test_block_applies_to_input_and_forward_persists_and_drops_the_cached_audit():
    dropped = []
    svc, box = firewall(on_change=dropped.append)
    res = svc.block_port("fw-branch1", 22)
    assert res.chains == ["INPUT", "FORWARD"] and res.new_action == "blocked"
    assert box.rules["INPUT"] == [("tcp", 22, "DROP")] == box.rules["FORWARD"]
    assert box.persisted and dropped == ["fw-branch1"]


def test_audit_flags_a_sensitive_port_open_through_the_firewall():
    svc, box = firewall()
    box.rules["FORWARD"] = [("tcp", 23, "ACCEPT")]
    audit = svc.audit("fw-branch1")
    assert not audit.clean and "Telnet" in audit.findings[0] and "FORWARD" in audit.findings[0]
    assert svc.open_ports("fw-branch1").open_ports[0].port == 23


def test_a_non_firewall_is_refused():
    svc, _ = firewall()
    with pytest.raises(ValueError, match="not a known firewall"):
        FirewallService(lambda q: [REGISTRY[0]], client_for({})).list_rules("host-khalid")


def test_iptables_helpers_are_pure_and_typed():
    raw = ("Chain INPUT (policy ACCEPT)\nnum  target     prot opt source               destination\n"
           "1    DROP       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:2222\n"
           "2    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22\n")
    rules = parse_rules(raw, "INPUT")
    assert [(r.port, r.action) for r in rules] == [(2222, "DROP"), (22, "ACCEPT")]
    assert ("INPUT", 22, "tcp") in effective_port_rules(rules)


# --- CameraService ---------------------------------------------------------------------------
def camera(creds="admin", up=True, **kwargs):
    box = Box(creds=creds)
    urls = []
    return CameraService(resolver, client_for({"c-cam-khalid": box}), lambda u: urls.append(u) or up, **kwargs), box, urls


def test_camera_default_password_is_reported_then_changed():
    changed = []
    svc, box, _ = camera(on_change=changed.append)
    assert svc.check_credentials("cam-khalid").using_default_credentials is True
    assert svc.change_credentials("cam-khalid", "S3cret pass").credentials_changed is True
    assert box.creds == "S3cret pass" and changed == ["cam-khalid"]
    assert svc.check_credentials("cam-khalid").clean is True


def test_camera_stream_status_uses_the_injected_http_check():
    svc, _, urls = camera(up=False)
    st = svc.stream_status("cam-khalid")
    assert st.streaming is False and urls == ["http://172.20.20.10:8080/snapshot"]


def test_device_model_keeps_unknown_registry_fields():
    d = Device(**{**REGISTRY[0], "network_ip": "10.1.0.10", "extra_field": 1})
    assert d.model_dump()["extra_field"] == 1 and d.network_ip == "10.1.0.10"


# --- acceptance: no Docker, no requests, no API key --------------------------------------------
def test_services_import_without_docker_or_requests():
    code = (f"import sys; sys.path.insert(0, {str(AGENT_DIR)!r}); "
            "sys.modules['docker'] = None; sys.modules['requests'] = None; "   # None makes `import x` raise
            "import services, models, iptables; print('ok')")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-500:]
    assert r.stdout.strip() == "ok"
