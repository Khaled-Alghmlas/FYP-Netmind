"""Unit tests for lab_network: re-attaching a device after a power cycle, and ping_between.
Nothing here needs Docker or Containerlab - containers and the registry are faked."""
import types

import device_control as dc
import lab_network as ln

DEVICES = {
    "host-khalid": {"id": "host-khalid", "container": "c-khalid", "type": "host", "ip": "172.20.20.8", "network_ip": "10.1.0.10"},
    "cam-khalid": {"id": "cam-khalid", "container": "c-cam", "type": "camera", "ip": "172.20.20.10", "network_ip": "10.1.0.50"},
    "host-khalil": {"id": "host-khalil", "container": "c-khalil", "type": "host", "ip": "172.20.20.11", "network_ip": "10.1.0.11"},
    "fw-branch1": {"id": "fw-branch1", "container": "c-fw", "type": "firewall", "ip": "172.20.20.2", "network_ip": "10.1.0.1"},
}

TOPO = {
    "nodes": {
        "switch-branch1": {"kind": "bridge"},
        "fw-branch1": {"kind": "linux"},
        "host-khalil": {"kind": "linux", "exec": [
            "ip addr add 10.1.0.11/24 dev eth1",
            "ip route add 10.0.0.0/8 via 10.1.0.1 dev eth1",
        ]},
    },
    "links": [
        {"endpoints": ["fw-branch1:eth2", "switch-branch1:b1p1"]},
        {"endpoints": ["switch-branch1:b1p3", "host-khalil:eth1"]},
        {"endpoints": ["r1:eth1", "fw-branch1:eth1"]},
    ],
}


class FakeContainer:
    def __init__(self, status="running", output=b"", has_iface=True):
        self.status = status
        self.output = output
        self.has_iface = has_iface
        self.commands = []
        self.started = False

    def reload(self):
        pass

    def start(self):
        self.started = True
        self.status = "running"

    def exec_run(self, cmd, **kwargs):
        self.commands.append(cmd)
        if cmd[:3] == ["ip", "link", "show"]:
            return (0 if self.has_iface else 1), b""
        return 0, self.output


def fake_client(containers):
    return types.SimpleNamespace(containers=types.SimpleNamespace(get=lambda name: containers[name]))


def find(name):
    exact = [d for d in DEVICES.values() if d["id"] == name]
    return exact or [d for d in DEVICES.values() if d["id"].endswith("-" + name)]


def setup_ping(monkeypatch, container):
    monkeypatch.setattr(dc, "find_devices", find)
    monkeypatch.setattr(dc, "_client", fake_client({"c-khalid": container}))


def setup_reconnect(monkeypatch, container, run):
    monkeypatch.setattr(dc, "_load_registry", lambda: [dict(d) for d in DEVICES.values()])
    monkeypatch.setattr(dc, "_client", fake_client({"c-khalil": container}))
    monkeypatch.setattr(ln, "_load_topology", lambda: TOPO)
    monkeypatch.setattr(ln, "_as_root", lambda cmd: cmd)
    monkeypatch.setattr(ln.shutil, "which", lambda name: "/usr/bin/containerlab")
    monkeypatch.setattr(ln.subprocess, "run", run)


# --- helpers -----------------------------------------------------------------
def test_gateway_is_read_from_the_route_command():
    cmds = ["ip addr add 10.1.0.11/24 dev eth1", "ip route add 10.0.0.0/8 via 10.1.0.1 dev eth1"]
    assert ln._gateway(cmds) == "10.1.0.1"
    assert ln._gateway(["ip addr add 10.1.0.11/24 dev eth1"]) is None


def test_bridge_link_finds_interface_bridge_and_port_in_either_order():
    assert ln._bridge_link(TOPO, "host-khalil") == ("eth1", "switch-branch1", "b1p3")
    assert ln._bridge_link(TOPO, "fw-branch1") == ("eth2", "switch-branch1", "b1p1")


def test_bridge_link_is_none_without_a_bridge_link():
    assert ln._bridge_link(TOPO, "r1") is None


# --- ping_between ------------------------------------------------------------
def test_ping_uses_the_lab_address_not_the_management_address(monkeypatch):
    src = FakeContainer(output=b"3 packets transmitted, 3 packets received, 0% packet loss\n")
    setup_ping(monkeypatch, src)
    r = ln.ping_between("host-khalid", "host-khalil")
    assert r["reachable"] is True and r["received"] == 3 and r["to_ip"] == "10.1.0.11"
    assert "10.1.0.11" in src.commands[-1] and "172.20.20.11" not in src.commands[-1]


def test_ping_reports_unreachable(monkeypatch):
    src = FakeContainer(output=b"3 packets transmitted, 0 packets received, 100% packet loss\n")
    setup_ping(monkeypatch, src)
    r = ln.ping_between("host-khalid", "host-khalil")
    assert r["reachable"] is False and r["received"] == 0


def test_ping_asks_which_device_when_a_name_is_ambiguous(monkeypatch):
    setup_ping(monkeypatch, FakeContainer())
    r = ln.ping_between("khalid", "host-khalil")
    assert "error" in r and r["src_matches"] == ["host-khalid", "cam-khalid"]


def test_ping_refuses_a_powered_off_source(monkeypatch):
    setup_ping(monkeypatch, FakeContainer(status="exited"))
    assert "powered off" in ln.ping_between("host-khalid", "host-khalil")["error"]


def test_ping_count_is_clamped(monkeypatch):
    src = FakeContainer(output=b"5 packets transmitted, 5 packets received, 0% packet loss\n")
    setup_ping(monkeypatch, src)
    ln.ping_between("host-khalid", "host-khalil", count=99)
    cmd = src.commands[-1]
    assert cmd[cmd.index("-c") + 1] == "5"


# --- reconnect_device --------------------------------------------------------
def test_reconnect_recreates_the_link_replays_exec_and_verifies(monkeypatch):
    c = FakeContainer(has_iface=False)
    seen = {}

    def run(cmd, **kwargs):
        seen["cmd"] = cmd
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    setup_reconnect(monkeypatch, c, run)
    r = ln.reconnect_device("host-khalil")
    assert r["reconnected"] is True and r["verified"] is True and r["gateway"] == "10.1.0.1"
    assert "bridge:switch-branch1:b1p3" in seen["cmd"]
    assert ["sh", "-c", "ip addr add 10.1.0.11/24 dev eth1"] in c.commands


def test_reconnect_reports_a_failed_veth_create(monkeypatch):
    def run(cmd, **kwargs):
        return types.SimpleNamespace(returncode=1, stdout="", stderr="boom")

    setup_reconnect(monkeypatch, FakeContainer(has_iface=False), run)
    r = ln.reconnect_device("host-khalil")
    assert "veth create failed" in r["error"] and r["detail"] == "boom"


def test_reconnect_skips_firewalls_and_routers(monkeypatch):
    setup_reconnect(monkeypatch, FakeContainer(), lambda cmd, **kwargs: None)
    assert "skipped" in ln.reconnect_device("fw-branch1")


def test_reconnect_does_nothing_when_the_link_is_already_there(monkeypatch):
    def run(cmd, **kwargs):
        raise AssertionError("veth create must not run when the interface exists")

    setup_reconnect(monkeypatch, FakeContainer(has_iface=True), run)
    r = ln.reconnect_device("host-khalil")
    assert r["reconnected"] is False and "already present" in r["reason"]


# --- power_on integration ----------------------------------------------------
def test_power_on_reattaches_the_device_after_start(monkeypatch):
    c = FakeContainer(status="exited")
    calls = []
    monkeypatch.setattr(dc, "find_devices", lambda name: [dict(DEVICES["host-khalil"])])
    monkeypatch.setattr(dc, "_client", fake_client({"c-khalil": c}))
    monkeypatch.setattr(ln, "reconnect_device", lambda device_id: calls.append(device_id) or {"reconnected": True, "verified": True})
    r = dc.power_on("host-khalil")
    assert c.started and calls == ["host-khalil"]
    assert r[0]["link"]["verified"] is True


def test_power_on_does_not_reattach_a_device_that_is_already_running(monkeypatch):
    calls = []
    monkeypatch.setattr(dc, "find_devices", lambda name: [dict(DEVICES["host-khalil"])])
    monkeypatch.setattr(dc, "_client", fake_client({"c-khalil": FakeContainer(status="running")}))
    monkeypatch.setattr(ln, "reconnect_device", lambda device_id: calls.append(device_id))
    r = dc.power_on("host-khalil")
    assert calls == [] and "link" not in r[0] and r[0]["already_in_that_state"] is True


def test_a_failed_reattach_does_not_break_power_on(monkeypatch):
    def boom(device_id):
        raise RuntimeError("no docker")

    monkeypatch.setattr(dc, "find_devices", lambda name: [dict(DEVICES["host-khalil"])])
    monkeypatch.setattr(dc, "_client", fake_client({"c-khalil": FakeContainer(status="exited")}))
    monkeypatch.setattr(ln, "reconnect_device", boom)
    r = dc.power_on("host-khalil")
    assert r[0]["new_status"] == "online" and "RuntimeError" in r[0]["link"]["error"]
