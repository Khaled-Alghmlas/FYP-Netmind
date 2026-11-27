"""Issue #25: reversible fault-injection scenarios, the lab-network probe that detects them, and
the /api/faults endpoints. Docker is faked: every command a scenario runs is recorded."""
import json
from types import SimpleNamespace as NS

import pytest
from fastapi.testclient import TestClient

import device_control as dc
import faults
import health
import lab_network as ln
import web_server as ws

REGISTRY = [
    {"id": "r1", "type": "router", "container": "c-r1", "network_ip": None},
    {"id": "fw-branch1", "type": "firewall", "container": "c-fw1", "branch": "branch1", "network_ip": "10.1.0.1"},
    {"id": "host-khalid", "type": "host", "container": "c-khalid", "branch": "branch1", "network_ip": "10.1.0.10"},
    {"id": "cam-khalid", "type": "camera", "container": "c-cam", "branch": "branch1", "network_ip": "10.1.0.50",
     "ip": "172.20.20.11"},
    {"id": "fw-branch2", "type": "firewall", "container": "c-fw2", "branch": "branch2", "network_ip": "10.2.0.1"},
    {"id": "host-sara", "type": "host", "container": "c-sara", "branch": "branch2", "network_ip": "10.2.0.10"},
]
TOPOLOGY = {"nodes": {
    "r1": {"exec": ["sysctl -w net.ipv4.ip_forward=1", "ip addr add 10.10.1.1/30 dev eth1",
                    "ip route add 10.1.0.0/24 via 10.10.1.2 dev eth1", "ip addr add 10.10.2.1/30 dev eth2",
                    "ip route add 10.2.0.0/24 via 10.10.2.2 dev eth2"]},
    "fw-branch1": {"exec": ["sysctl -w net.ipv4.ip_forward=1", "ip addr add 10.10.1.2/30 dev eth1",
                            "ip addr add 10.1.0.1/24 dev eth2", "ip route add 10.0.0.0/8 via 10.10.1.1 dev eth1"]},
    "host-khalid": {"exec": ["ip addr add 10.1.0.10/24 dev eth1", "ip route add 10.0.0.0/8 via 10.1.0.1 dev eth1"]},
}}


class Box:
    """A fake container that records the shell commands run in it."""

    def __init__(self, name, status="running"):
        self.name, self.status, self.commands, self.fail_on, self.outputs = name, status, [], None, {}

    def reload(self):
        pass

    def exec_run(self, cmd):
        command = cmd[-1] if cmd[:2] == ["sh", "-c"] else " ".join(cmd)
        self.commands.append(command)
        if self.fail_on and self.fail_on in command:
            return 1, b"RTNETLINK answers: Operation not permitted"
        for key, out in self.outputs.items():
            if key in command:
                return 0, out
        return 0, b""


@pytest.fixture
def lab(monkeypatch, tmp_path):
    boxes = {d["container"]: Box(d["container"]) for d in REGISTRY}
    boxes["c-cam"].outputs["cat /etc/netmind-camera-creds"] = b"S3cret'pw"
    power = []
    monkeypatch.setattr(dc, "_load_registry", lambda: REGISTRY)
    monkeypatch.setattr(dc, "_client", NS(containers=NS(get=lambda name: boxes[name])))
    monkeypatch.setattr(dc, "power_off", lambda d: power.append(("off", d)) or [])
    monkeypatch.setattr(dc, "power_on", lambda d: power.append(("on", d)) or [])
    monkeypatch.setattr(ln, "_load_topology", lambda: TOPOLOGY)
    monkeypatch.setattr(faults, "STATE_PATH", tmp_path / "faults.json")
    faults._runs.clear()
    faults._loaded["done"] = False

    def by_id(device_id):
        return boxes[next(d["container"] for d in REGISTRY if d["id"] == device_id)]

    return NS(box=by_id, power=power, state=tmp_path / "faults.json")


TARGETS = {"host": "host-khalid", "camera": "cam-khalid", "firewall": "fw-branch1"}


def test_at_least_ten_scenarios_each_with_inject_and_revert():
    assert len(faults.SCENARIOS) >= 10
    for s in faults.SCENARIOS.values():
        assert callable(s.inject) and callable(s.revert) and s.target_type in TARGETS
        assert s.title_ar and faults.DESCRIPTION_AR[s.id]


@pytest.mark.parametrize("scenario_id", sorted(faults.SCENARIOS))
def test_every_scenario_injects_and_reverts(lab, scenario_id):
    target = TARGETS[faults.SCENARIOS[scenario_id].target_type]
    run = faults.inject(scenario_id, target)
    assert run["status"] == "active" and run["target"] == target and target in run["watch"]
    assert [r["id"] for r in faults.active()] == [run["id"]]
    done = faults.revert(run["id"])
    assert done["status"] == "reverted" and done["reverted_at"] >= done["injected_at"]
    assert faults.active() == []


def test_scenarios_list_the_devices_they_can_target(lab):
    listed = {s["id"]: s for s in faults.scenarios()}
    assert listed["branch-latency"]["targets"] == ["fw-branch1", "fw-branch2"]
    assert listed["host-down"]["targets"] == ["host-khalid", "host-sara"]
    assert listed["camera-stream-stop"]["targets"] == ["cam-khalid"]


def test_a_branch_link_fault_brings_the_routes_back_when_undone(lab):
    run = faults.inject("branch-link-down", "fw-branch1")
    assert lab.box("fw-branch1").commands[-1] == "ip link set eth1 down"
    assert sorted(run["watch"]) == ["cam-khalid", "fw-branch1", "host-khalid"]   # the whole branch
    faults.revert(run["id"])
    cmds = lab.box("fw-branch1").commands
    assert "ip link set eth1 up" in cmds and "ip route replace 10.0.0.0/8 via 10.10.1.1 dev eth1" in cmds


def test_latency_and_loss_use_tc_netem_and_are_removed(lab):
    faults.revert(faults.inject("branch-latency", "fw-branch1")["id"])
    faults.revert(faults.inject("branch-packet-loss", "fw-branch1")["id"])
    cmds = lab.box("fw-branch1").commands
    assert "tc qdisc replace dev eth1 root netem delay 300ms" in cmds
    assert "tc qdisc replace dev eth1 root netem loss 40%" in cmds
    assert cmds.count("tc qdisc del dev eth1 root") == 2


def test_missing_tc_is_explained(lab):
    lab.box("fw-branch1").fail_on = "tc qdisc"
    with pytest.raises(faults.FaultError, match="make up"):
        faults.inject("branch-latency", "fw-branch1")
    assert faults.runs() == []                        # nothing recorded for a fault that never happened


def test_route_removed_on_the_router_and_put_back(lab):
    faults.revert(faults.inject("route-removed", "fw-branch1")["id"])
    assert lab.box("r1").commands == ["ip route del 10.1.0.0/24", "ip route replace 10.1.0.0/24 via 10.10.1.2 dev eth1"]


def test_firewall_rules_are_added_and_fully_removed(lab):
    faults.revert(faults.inject("firewall-block-camera", "cam-khalid")["id"])
    faults.revert(faults.inject("firewall-block-branch", "fw-branch1")["id"])
    cmds = lab.box("fw-branch1").commands
    assert cmds[0] == "iptables -I FORWARD 1 -d 10.1.0.50 -p tcp --dport 8080 -j DROP"
    assert "while iptables -C FORWARD -d 10.1.0.50 -p tcp --dport 8080 -j DROP" in cmds[1]
    assert cmds[2] == "iptables -I FORWARD 1 -i eth1 -j DROP"
    assert "iptables -D FORWARD -i eth1 -j DROP" in cmds[3]


def test_camera_password_is_reset_and_restored(lab):
    cam = lab.box("cam-khalid")
    faults.revert(faults.inject("camera-default-password", "cam-khalid")["id"])
    assert "printf '%s' admin > /etc/netmind-camera-creds" in cam.commands
    assert cam.commands[-1] == "printf '%s' 'S3cret'\"'\"'pw' > /etc/netmind-camera-creds"   # quote kept


def test_a_camera_already_on_the_default_password_is_refused(lab):
    lab.box("cam-khalid").outputs["cat /etc/netmind-camera-creds"] = b"admin\n"
    with pytest.raises(faults.FaultError, match="already uses the default password"):
        faults.inject("camera-default-password", "cam-khalid")


def test_power_scenarios_use_the_normal_power_actions(lab):
    faults.revert(faults.inject("host-down", "host-sara")["id"])
    assert lab.power == [("off", "host-sara"), ("on", "host-sara")]


def test_a_wrong_gateway_is_replaced_and_restored(lab):
    faults.revert(faults.inject("host-wrong-gateway", "host-khalid")["id"])
    cmds = lab.box("host-khalid").commands
    assert cmds[0] == "ip route replace 10.0.0.0/8 via 10.1.0.254 dev eth1"
    assert "ip route replace 10.0.0.0/8 via 10.1.0.1 dev eth1" in cmds


def test_bad_requests_are_refused(lab):
    with pytest.raises(faults.FaultError, match="unknown scenario"):
        faults.inject("meteor-strike", "host-khalid")
    with pytest.raises(faults.FaultError, match="needs a firewall"):
        faults.inject("branch-latency", "host-khalid")
    with pytest.raises(faults.FaultError, match="unknown device"):
        faults.inject("host-down", "host-nobody")
    faults.inject("camera-stream-stop", "cam-khalid")
    with pytest.raises(faults.FaultError, match="already active"):
        faults.inject("camera-stream-stop", "cam-khalid")
    lab.box("host-sara").status = "exited"
    with pytest.raises(faults.FaultError, match="powered off"):
        faults.inject("host-link-down", "host-sara")


def test_a_failed_revert_stays_active_and_revert_all_carries_on(lab):
    a = faults.inject("camera-stream-stop", "cam-khalid")
    b = faults.inject("host-link-down", "host-khalid")
    lab.box("host-khalid").fail_on = "ip link set eth1 up"
    results = {r["id"]: r for r in faults.revert_all()}
    assert results[a["id"]]["status"] == "reverted"
    assert "failed" in results[b["id"]]["error"] and [r["id"] for r in faults.active()] == [b["id"]]
    lab.box("host-khalid").fail_on = None
    assert faults.revert(b["id"])["status"] == "reverted" and faults.revert(b["id"])["status"] == "reverted"
    with pytest.raises(faults.FaultError, match="no fault run"):
        faults.revert("nope")


def test_runs_survive_a_restart(lab):
    run = faults.inject("host-link-down", "host-khalid")
    assert json.loads(lab.state.read_text())[0]["id"] == run["id"]
    faults._runs.clear()
    faults._loaded["done"] = False                   # a restart
    assert [r["id"] for r in faults.active()] == [run["id"]]
    faults.revert(run["id"])                         # can still be undone


def test_evaluate_measures_detection_and_other_alerts():
    run = {"target": "fw-branch1", "watch": ["fw-branch1", "host-khalid"], "injected_at": 10_000, "reverted_at": 60_000}
    alerts = [
        {"id": "a1", "kind": "device_degraded", "device": "host-khalid", "ts": 18_500},
        {"id": "a2", "kind": "device_degraded", "device": "fw-branch1", "ts": 17_200},
        {"id": "a3", "kind": "device_recovered", "device": "fw-branch1", "ts": 59_000},   # not a detection
        {"id": "a4", "kind": "device_offline", "device": "host-sara", "ts": 30_000},      # someone else
        {"id": "a5", "kind": "device_offline", "device": "fw-branch1", "ts": 9_000},       # before the fault
        {"id": "a6", "kind": "device_offline", "device": "fw-branch1", "ts": 70_000},      # after it
    ]
    result = faults.evaluate(run, alerts)
    assert result == {"detected": True, "detection_seconds": 7.2, "alerts": ["a2", "a1"], "other_alerts": ["a4"]}
    assert faults.evaluate(run, [])["detected"] is False


# --- API -------------------------------------------------------------------------------------
@pytest.fixture
def api(lab, monkeypatch):
    monkeypatch.setattr(ws, "ALERTS_PATH", None)
    monkeypatch.setattr(dc, "_invalidate_dashboard_cache", lambda: None)
    ws.ALERT_LOG.clear()
    records = []
    monkeypatch.setattr(ws.AUDIT_LOG, "record", lambda *a: records.append(a))
    return NS(client=TestClient(ws.app), records=records)


def test_the_api_injects_measures_and_reverts(api, monkeypatch):
    run = api.client.post("/api/faults/inject", json={"scenario": "camera-stream-stop", "target": "cam-khalid"}).json()
    assert run["status"] == "active" and run["detected"] is False and "revert_data" not in run
    ws.ALERT_LOG.insert(0, {"id": "a9", "kind": "device_degraded", "device": "cam-khalid", "ts": run["injected_at"] + 8000})
    monkeypatch.setattr(faults, "_now_ms", lambda: run["injected_at"] + 20_000)   # 20 s later
    body = api.client.get("/api/faults").json()
    assert len(body["scenarios"]) == len(faults.SCENARIOS)
    [listed] = body["runs"]
    assert listed["detected"] is True and listed["detection_seconds"] == 8.0 and "revert_data" not in listed
    assert api.client.post(f"/api/faults/{run['id']}/revert").json()["status"] == "reverted"
    assert [r[1] for r in api.records] == ["inject_fault", "revert_fault"]


def test_the_api_explains_errors_and_reverts_everything(api, lab):
    bad = api.client.post("/api/faults/inject", json={"scenario": "branch-latency", "target": "host-khalid"})
    assert bad.status_code == 400 and "needs a firewall" in bad.json()["error"]
    assert api.client.post("/api/faults/nope/revert").status_code == 400
    api.client.post("/api/faults/inject", json={"scenario": "host-link-down", "target": "host-khalid"})
    api.client.post("/api/faults/inject", json={"scenario": "camera-stream-stop", "target": "cam-khalid"})
    lab.box("cam-khalid").fail_on = "/start_camera.sh"
    body = api.client.post("/api/faults/revert-all").json()
    assert len(body["reverted"]) == 1 and body["failed"][0]["error"].startswith("starting the stream failed")


def test_the_api_reports_a_lab_that_was_never_deployed(api, monkeypatch):
    def missing():
        raise FileNotFoundError("registry.json")

    monkeypatch.setattr(dc, "_load_registry", missing)
    body = api.client.get("/api/faults").json()
    assert body["scenarios"] == [] and "lab not available" in body["error"]


# --- the lab-network probe that detects these faults -----------------------------------------
PROBE_OUTPUT = b"""== nmp_10.1.0.1
3 packets transmitted, 3 packets received, 0% packet loss
round-trip min/avg/max = 300.2/301.0/302.1 ms
== nmp_10.1.0.10
3 packets transmitted, 1 packets received, 66% packet loss
round-trip min/avg/max = 0.1/0.1/0.1 ms
== nmp_10.1.0.50
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 0.071/0.088/0.103/0.01 ms
== nmp_10.2.0.10
3 packets transmitted, 0 packets received, 100% packet loss
== nmw_10.1.0.50
fail
"""


def test_the_probe_output_is_parsed_for_busybox_and_iputils():
    pings, streams = dc._parse_lab_probe(PROBE_OUTPUT.decode())
    assert pings["10.1.0.1"] == {"lab_reachable": True, "lab_loss": 0.0, "lab_rtt": 301.0}
    assert pings["10.1.0.10"]["lab_loss"] == 66.7
    assert pings["10.1.0.50"] == {"lab_reachable": True, "lab_loss": 0.0, "lab_rtt": 0.088}
    assert pings["10.2.0.10"] == {"lab_reachable": False, "lab_loss": 100.0}
    assert streams == {"10.1.0.50": False}


def test_sample_lab_adds_the_probe_from_the_router(monkeypatch):
    boxes = {d["container"]: Box(d["container"]) for d in REGISTRY}
    boxes["c-sara"].status = "exited"
    boxes["c-r1"].outputs["nmp_"] = PROBE_OUTPUT
    monkeypatch.setattr(dc, "_load_registry", lambda: REGISTRY)
    monkeypatch.setattr(dc, "_client", NS(containers=NS(list=lambda all=False: list(boxes.values()))))
    monkeypatch.setattr(dc, "_snapshot_ok", lambda url: True)
    monkeypatch.setattr(dc, "_ping_ok", lambda ip: True)
    samples = {d["id"]: s for d, s in dc.sample_lab()}
    [script] = boxes["c-r1"].commands
    assert "10.2.0.10" not in script                 # powered-off devices are not probed
    assert "http://$ip:8080/snapshot" in script and "10.1.0.50" in script
    assert "-W 1 -w 3" in script                      # an unreachable device costs at most ~3 s, not 10 s per ping
    assert samples["fw-branch1"]["lab_rtt"] == 301.0
    assert samples["cam-khalid"]["lab_stream"] is False and samples["cam-khalid"]["stream"] is True
    assert "lab_reachable" not in samples["r1"] and samples["host-sara"] == {"container": "exited"}
    boxes["c-r1"].status = "exited"                  # no router: nothing concluded from the probe
    assert all("lab_reachable" not in s for _d, s in dc.sample_lab())
    boxes["c-r1"].status = "running"
    boxes["c-r1"].outputs["nmp_"] = b"sh: ping: not found"
    assert all("lab_reachable" not in s for _d, s in dc.sample_lab())
    assert all("lab_reachable" not in s for _d, s in dc.sample_lab(lab_probe=False))


@pytest.mark.parametrize("sample, reason", [
    ({"lab_reachable": False}, "not reachable over the lab network"),
    ({"lab_reachable": True, "lab_loss": 66.7}, "67% packet loss on the lab network"),
    ({"lab_reachable": True, "lab_loss": 0.0, "lab_rtt": 301.0}, "high latency on the lab network (301 ms)"),
    ({"lab_reachable": True, "lab_loss": 0.0, "lab_rtt": 0.1, "lab_stream": False}, "camera stream blocked on the lab network"),
])
def test_lab_problems_make_a_device_degraded(sample, reason):
    assert health.classify("camera", {"container": "running", "stream": True, **sample}) == (health.DEGRADED, reason)


def test_a_healthy_lab_sample_is_up():
    assert health.classify("host", {"container": "running", "lab_reachable": True, "lab_loss": 0.0, "lab_rtt": 0.2})[0] == health.UP


def test_the_lab_probe_can_be_turned_off():
    from settings import Settings
    assert Settings.from_env({"NETMIND_COLLECT_LAB": "0"}).collector_lab_probe is False
    assert Settings.from_env({}).collector_lab_probe is True


def test_the_collector_keeps_its_rhythm_when_a_round_is_slow():
    import time
    from collector import Collector
    starts = []

    def slow():
        starts.append(time.monotonic())
        time.sleep(0.05)
        return []

    c = Collector(slow, lambda t: None, interval=0.1)
    c.start()
    try:
        deadline = time.time() + 3
        while len(starts) < 4 and time.time() < deadline:
            time.sleep(0.01)
    finally:
        c.stop()
    gaps = [b - a for a, b in zip(starts, starts[1:4])]
    assert all(0.08 <= g <= 0.2 for g in gaps)       # start to start, not 0.05 + 0.1
