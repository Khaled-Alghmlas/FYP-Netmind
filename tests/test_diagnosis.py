"""Issue #26: the root-cause playbooks, tested against every fault scenario of issue #25.

A small model of the lab stands in for Docker: links, addresses, routes, firewall rules, tc
impairments, camera services and CPU. The scenarios run their real commands against it (so a
scenario and the model can never drift apart), and then the playbooks must find the cause in
their evidence, and find nothing once the fault is undone."""
import re
from types import SimpleNamespace as NS

import pytest

import device_control as dc
import diagnosis
import faults
import lab_network as ln

REGISTRY = [
    {"id": "r1", "type": "router", "container": "c-r1", "ip": "172.20.20.13"},
    {"id": "fw-branch1", "type": "firewall", "container": "c-fw1", "branch": "branch1", "network_ip": "10.1.0.1", "ip": "172.20.20.10"},
    {"id": "fw-branch2", "type": "firewall", "container": "c-fw2", "branch": "branch2", "network_ip": "10.2.0.1", "ip": "172.20.20.4"},
    {"id": "host-khalid", "type": "host", "owner": "khalid", "container": "c-khalid", "branch": "branch1", "network_ip": "10.1.0.10", "ip": "172.20.20.12"},
    {"id": "host-khalil", "type": "host", "owner": "khalil", "container": "c-khalil", "branch": "branch1", "network_ip": "10.1.0.11", "ip": "172.20.20.8"},
    {"id": "cam-khalid", "type": "camera", "owner": "khalid", "container": "c-cam", "branch": "branch1", "network_ip": "10.1.0.50", "ip": "172.20.20.11"},
    {"id": "host-sara", "type": "host", "owner": "sara", "container": "c-sara", "branch": "branch2", "network_ip": "10.2.0.10", "ip": "172.20.20.2"},
]
BY_ID = {d["id"]: d for d in REGISTRY}
FW_OF = {"branch1": "fw-branch1", "branch2": "fw-branch2"}
WAN = {"fw-branch1": ("10.10.1.2", "10.10.1.1", "eth1"), "fw-branch2": ("10.10.2.2", "10.10.2.1", "eth2")}  # fw wan, r1 side, r1 iface


def _host_exec(ip, gw):
    return [f"ip addr add {ip}/24 dev eth1", f"ip route add 10.0.0.0/8 via {gw} dev eth1"]


TOPOLOGY = {"links": [{"endpoints": ["r1:eth1", "fw-branch1:eth1"]}, {"endpoints": ["r1:eth2", "fw-branch2:eth1"]},
                     {"endpoints": ["fw-branch1:eth2", "switch-branch1:b1p1"]}],
            "nodes": {"switch-branch1": {"kind": "bridge"},
    "r1": {"exec": ["sysctl -w net.ipv4.ip_forward=1",
                    "ip addr add 10.10.1.1/30 dev eth1", "ip route add 10.1.0.0/24 via 10.10.1.2 dev eth1",
                    "ip addr add 10.10.2.1/30 dev eth2", "ip route add 10.2.0.0/24 via 10.10.2.2 dev eth2"]},
    "fw-branch1": {"exec": ["sysctl -w net.ipv4.ip_forward=1", "ip addr add 10.10.1.2/30 dev eth1",
                            "ip addr add 10.1.0.1/24 dev eth2", "ip route add 10.0.0.0/8 via 10.10.1.1 dev eth1"]},
    "fw-branch2": {"exec": ["sysctl -w net.ipv4.ip_forward=1", "ip addr add 10.10.2.2/30 dev eth1",
                            "ip addr add 10.2.0.1/24 dev eth2", "ip route add 10.0.0.0/8 via 10.10.2.1 dev eth1"]},
    "host-khalid": {"exec": _host_exec("10.1.0.10", "10.1.0.1")},
    "host-khalil": {"exec": _host_exec("10.1.0.11", "10.1.0.1")},
    "cam-khalid": {"exec": _host_exec("10.1.0.50", "10.1.0.1")},
    "host-sara": {"exec": _host_exec("10.2.0.10", "10.2.0.1")},
}}
BASE_RULES = ["-A INPUT -i lo -j ACCEPT", "-A INPUT -p icmp -j ACCEPT",
              "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT", "-A INPUT -p tcp -m tcp --dport 23 -j DROP"]


def _design_routes(dev_id):
    return {net: via for net, via, _i in re.findall(r"ip route add (\S+) via (\S+) dev (\S+)", " ; ".join(TOPOLOGY["nodes"][dev_id]["exec"]))}


class Lab:
    """The network state, and how packets fare in it."""

    def __init__(self):
        self.power = {d["id"]: True for d in REGISTRY}
        self.links = {}
        for d in REGISTRY:
            for iface in (["eth1", "eth2"] if d["type"] in ("router", "firewall") else ["eth1"]):
                self.links[(d["id"], iface)] = "up"
        self.routes = {d["id"]: _design_routes(d["id"]) for d in REGISTRY}
        self.tc = {}
        self.rules = {fw: list(BASE_RULES) for fw in FW_OF.values()}
        self.stream = {"cam-khalid": True}
        self.creds = {"cam-khalid": "S3cret"}
        self.cpu = {d["id"]: 1.0 for d in REGISTRY}

    def by_ip(self, ip):
        return next((d for d in REGISTRY if d.get("network_ip") == ip), None)

    def fw_ok(self, fw, inbound_from_core):
        """Can traffic cross this firewall? -> (ok, loss, delay)."""
        if not self.power[fw] or self.links[(fw, "eth1")] != "up" or self.links[(fw, "eth2")] != "up":
            return False, 0, 0
        if self.routes[fw].get("10.0.0.0/8") != _design_routes(fw)["10.0.0.0/8"]:
            return False, 0, 0
        if any(r == "-A FORWARD -i eth1 -j DROP" for r in self.rules[fw]):
            return False, 0, 0
        spec = self.tc.get((fw, "eth1"), "")
        loss = 0.34 if "loss" in spec else 0
        delay = 300 if "delay" in spec else 0
        return True, loss, delay

    def leaf_ok(self, dev):
        if not self.power[dev] or self.links.get((dev, "eth1")) != "up":
            return False
        return self.routes[dev].get("10.0.0.0/8") == _design_routes(dev)["10.0.0.0/8"]

    def r1_reaches(self, fw):
        wan, _r1ip, iface = WAN[fw]
        net = BY_ID[fw]["network_ip"].rsplit(".", 1)[0] + ".0/24"
        return self.power["r1"] and self.links[("r1", iface)] == "up" and self.routes["r1"].get(net) == wan

    def reach(self, src, dst_ip, port=None):
        """-> (reached, loss_fraction, extra_delay_ms, hops_passed)."""
        a, b = BY_ID[src], self.by_ip(dst_ip)
        if b is None or not self.power[src] or not self.power[b["id"]]:
            return False, 1, 0, 0
        if a["type"] in ("host", "camera") and not self.leaf_ok(src):
            return False, 1, 0, 0
        loss, delay, hops = 0, 0, 0
        if a["type"] in ("host", "camera") and b["type"] in ("host", "camera") and a["branch"] == b["branch"]:
            ok = self.leaf_ok(b["id"])
            return ok, 0 if ok else 1, 0, 1
        fws = []
        if a["type"] in ("host", "camera"):
            fws.append(FW_OF[a["branch"]])
        if b["type"] in ("host", "camera"):
            fws.append(FW_OF[b["branch"]])
        elif b["type"] == "firewall":
            fws.append(b["id"])
        for fw in fws:
            if fw == b["id"]:   # the firewall itself answers: only its link to the core matters
                if not (self.power[fw] and self.links[(fw, "eth1")] == "up"):
                    return False, 1, delay, hops
            else:
                ok, fw_loss, dl = self.fw_ok(fw, True)
                if not ok:
                    return False, 1, delay, hops
                loss, delay = max(loss, fw_loss), delay + dl
            hops += 1
            if not self.r1_reaches(fw):
                return False, 1, delay, hops
            hops += 1
        if b["type"] in ("host", "camera") and not self.leaf_ok(b["id"]):
            return False, 1, delay, hops
        if port == 8080:
            for fw in fws:
                if any(f"-d {dst_ip}/32" in r and "--dport 8080 -j DROP" in r for r in self.rules[fw]):
                    return False, 1, delay, hops
            if not self.stream.get(b["id"]):
                return False, 1, delay, hops
        return True, loss, delay, hops + 1


class Box:
    def __init__(self, lab, dev):
        self.lab, self.dev, self.id = lab, dev, dev["id"]
        self.name = dev["container"]

    @property
    def status(self):
        return "running" if self.lab.power[self.id] else "exited"

    @property
    def attrs(self):
        return {"State": {"ExitCode": 137, "FinishedAt": "2026-11-27T18:19:00.1Z", "OOMKilled": False}}

    def reload(self):
        pass

    def stats(self, stream=False):
        pct = self.lab.cpu[self.id]
        return {"cpu_stats": {"cpu_usage": {"total_usage": pct}, "system_cpu_usage": 100, "online_cpus": 1},
                "precpu_stats": {"cpu_usage": {"total_usage": 0}, "system_cpu_usage": 0}}

    def exec_run(self, cmd):
        if cmd[:2] != ["sh", "-c"]:
            return self._traceroute(cmd)
        return self._sh(cmd[2])

    def _ping_text(self, ip, count=3):
        ok, loss, delay, _ = self.lab.reach(self.id, ip)
        got = 0 if not ok else count - round(loss * count)
        text = f"{count} packets transmitted, {got} packets received\n"
        if got:
            text += f"round-trip min/avg/max = {delay + 0.1}/{delay + 0.2}/{delay + 0.3} ms\n"
        return 0 if got else 1, text.encode()

    def _traceroute(self, cmd):
        ip = cmd[-1]
        ok, _l, delay, hops = self.lab.reach(self.id, ip)
        a, b = self.dev, self.lab.by_ip(ip)
        path = []
        if a["type"] in ("host", "camera"):
            path.append(BY_ID[FW_OF[a["branch"]]]["network_ip"])
            path.append(WAN[FW_OF[a["branch"]]][1])
        if b and b["type"] in ("host", "camera") and (a.get("branch") != b["branch"]):
            path.append(WAN[FW_OF[b["branch"]]][0])
        path.append(ip)
        shown = path if ok else path[:max(hops, 0)]
        lines = [f"{i + 1}  {h}  {delay + 0.5:.1f} ms" for i, h in enumerate(shown)]
        if not ok:
            lines.append(f"{len(shown) + 1}  *")
        return 0, ("traceroute to x\n" + "\n".join(lines)).encode()

    def _sh(self, c):
        lab, me = self.lab, self.id
        if not lab.power[me]:
            return 1, b"container not running"
        # ---- reads ----
        if c.startswith("for i in /sys/class/net/eth*"):
            # like Linux: a side switched off has its UP flag cleared; the far end keeps it but loses the carrier
            flags = {"up": "0x1003", "down": "0x1002", "nocarrier": "0x1003"}
            return 0, "\n".join(f"{i} {'down' if s == 'nocarrier' else s} {flags[s]}"
                                for (d, i), s in sorted(lab.links.items()) if d == me and s != "absent").encode()
        if c == "ip addr show":
            addrs = re.findall(r"ip addr add (\S+) dev (\S+)", " ; ".join(TOPOLOGY["nodes"][me]["exec"]))
            return 0, "\n".join(f"2: {i}    inet {cidr} scope global {i}" for cidr, i in addrs).encode()
        if c == "ip route":
            return 0, "\n".join(f"{net} via {via} dev eth1" for net, via in lab.routes[me].items()).encode()
        if c.startswith("tc qdisc show dev "):
            if BY_ID[me]["type"] != "firewall":
                return 127, b"sh: tc: not found"
            spec = lab.tc.get((me, c.split()[-1]))
            return 0, (f"qdisc netem 8001: root refcnt 2 limit 1000 {spec} seed 123" if spec else "qdisc noqueue 0: root").encode()
        if c == "iptables -S":
            return 0, ("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n" + "\n".join(lab.rules[me])).encode()
        if c.startswith("cat /etc/netmind-fw-rules"):
            return 0, ("*filter\n" + "\n".join(BASE_RULES) + "\nCOMMIT").encode()
        if c.startswith("cat /etc/netmind-camera-creds"):
            return 0, lab.creds[me].encode()
        m = re.match(r"ping -c (\d+) -W \d+ -q (\S+)", c)
        if m:
            return self._ping_text(m.group(2), int(m.group(1)))
        m = re.match(r"wget -q -T \d+ -O /dev/null http://(\S+):8080/snapshot", c)
        if m:
            return (0 if lab.reach(me, m.group(1), port=8080)[0] else 1), b""
        # ---- changes made by the fault scenarios ----
        m = re.match(r"ip link set (\S+) (up|down)", c)
        if m:
            iface, state = m.group(1), m.group(2)
            lab.links[(me, iface)] = state
            if me in WAN and iface == "eth1":      # the cable to r1: Linux behaviour on both ends
                lab.links[("r1", WAN[me][2])] = "up" if state == "up" else "nocarrier"
            if state == "down":                   # a link taken down loses its routes
                design = re.findall(r"ip route add (\S+) via \S+ dev (\S+)", " ; ".join(TOPOLOGY["nodes"][me]["exec"]))
                for net, dev in design:
                    if dev == iface:
                        lab.routes[me].pop(net, None)
            return 0, b""
        m = re.match(r"tc qdisc replace dev (\S+) root netem (.*)", c)
        if m:
            lab.tc[(me, m.group(1))] = m.group(2)
            return 0, b""
        if c.startswith("tc qdisc del dev "):
            lab.tc.pop((me, c.split()[4]), None)
            return 0, b""
        m = re.match(r"ip route del (\S+)", c)
        if m:
            lab.routes[me].pop(m.group(1), None)
            return 0, b""
        m = re.match(r"ip route replace (\S+) via (\S+) dev \S+", c)
        if m:
            lab.routes[me][m.group(1)] = m.group(2)
            return 0, b""
        m = re.match(r"iptables -I (\S+) 1 (.*)", c)
        if m:
            spec = m.group(2).replace("-p tcp --dport", "-p tcp -m tcp --dport")
            spec = re.sub(r"-d (\d+\.\d+\.\d+\.\d+) ", r"-d \1/32 ", spec)
            lab.rules[me].insert(0, f"-A {m.group(1)} {spec}")
            return 0, b""
        m = re.match(r"while iptables -C (\S+) (.*?) 2>/dev/null", c)
        if m:
            spec = m.group(2).replace("-p tcp --dport", "-p tcp -m tcp --dport")
            spec = re.sub(r"-d (\d+\.\d+\.\d+\.\d+) ", r"-d \1/32 ", spec)
            lab.rules[me] = [r for r in lab.rules[me] if r != f"-A {m.group(1)} {spec}"]
            return 0, b""
        if c == "/stop_camera.sh":
            lab.stream[me] = False
            return 0, b""
        if c == "/start_camera.sh":
            lab.stream[me] = True
            return 0, b""
        m = re.match(r"printf '%s' '?(.*?)'? > /etc/netmind-camera-creds", c)
        if m:
            lab.creds[me] = m.group(1)
            return 0, b""
        if c.startswith("timeout 600 yes"):
            lab.cpu[me] = 100.0
            return 0, b""
        if "netmind-stress.pid" in c:
            lab.cpu[me] = 1.0
            return 0, b""
        if c.startswith(("ip addr add", "sysctl")):
            return 0, b""
        raise AssertionError(f"the fake lab does not know the command: {c}")


@pytest.fixture
def lab(monkeypatch, tmp_path):
    state = Lab()
    boxes = {d["container"]: Box(state, d) for d in REGISTRY}
    monkeypatch.setattr(dc, "_load_registry", lambda: REGISTRY)
    monkeypatch.setattr(dc, "_client", NS(containers=NS(get=lambda name: boxes[name], list=lambda all=False: list(boxes.values()))))
    monkeypatch.setattr(dc, "find_devices", lambda n: [d for d in REGISTRY if n in (d["id"], d.get("owner"))])
    monkeypatch.setattr(dc, "power_off", lambda d: state.power.__setitem__(d, False) or [])
    monkeypatch.setattr(dc, "power_on", lambda d: state.power.__setitem__(d, True) or [])
    monkeypatch.setattr(dc, "_snapshot_ok", lambda url: next(
        (state.power[d["id"]] and state.stream.get(d["id"], False) for d in REGISTRY if d["ip"] in url), False))
    monkeypatch.setattr(dc, "get_security_findings", lambda: [
        (cam, "Camera is using the default password (admin)", "camera_finding")
        for cam, pw in state.creds.items() if pw == "admin"])
    monkeypatch.setattr(ln, "_load_topology", lambda: TOPOLOGY)
    monkeypatch.setattr(faults, "STATE_PATH", tmp_path / "faults.json")
    faults._runs.clear()
    faults._loaded["done"] = False
    diagnosis.set_sources(health=lambda: [], actions=lambda: [], alerts=lambda: [])
    return state


def problems(result):
    return " | ".join(result["problems"])


# scenario, target, how the assistant would investigate it, what the evidence must say
CASES = [
    ("host-down", "host-khalil", ("device", "host-khalil"), ["host-khalil is powered off", "stopped by a stop request"]),
    ("camera-down", "cam-khalid", ("device", "cam-khalid"), ["cam-khalid is powered off"]),
    ("camera-stream-stop", "cam-khalid", ("device", "cam-khalid"), ["video service is not running"]),
    ("host-link-down", "host-khalil", ("device", "host-khalil"), ["host-khalil's eth1 is switched off on host-khalil itself"]),
    ("branch-link-down", "fw-branch2", ("path", "host-khalid", "host-sara"),
     ["cannot reach host-sara", "fw-branch2's eth1 is switched off on fw-branch2 itself"]),
    ("branch-latency", "fw-branch2", ("path", "host-khalid", "host-sara"),
     ["slowly", "fw-branch2's eth1 has a netem impairment: delay 300ms"]),
    ("branch-packet-loss", "fw-branch2", ("path", "host-khalid", "host-sara"),
     ["packet loss", "fw-branch2's eth1 has a netem impairment: loss 40%"]),
    ("route-removed", "fw-branch2", ("path", "host-khalid", "host-sara"), ["r1 has no route to 10.2.0.0/24"]),
    ("firewall-block-branch", "fw-branch2", ("path", "host-khalid", "host-sara"),
     ["fw-branch2 drops forwarded traffic: -A FORWARD -i eth1 -j DROP"]),
    ("firewall-block-camera", "cam-khalid", ("path", "host-sara", "cam-khalid"),
     ["something on the path blocks port 8080", "fw-branch1 drops forwarded traffic: -A FORWARD -d 10.1.0.50/32"]),
    ("firewall-open-telnet", "fw-branch1", ("device", "fw-branch1"),
     ["not in its saved configuration", "--dport 23 -j ACCEPT"]),
    ("host-wrong-gateway", "host-khalil", ("device", "host-khalil"),
     ["sends 10.0.0.0/8 via 10.1.0.254, but the design says via 10.1.0.1"]),
    ("host-cpu-stress", "host-khalil", ("device", "host-khalil"), ["CPU at 100% (saturated)"]),
]


def investigate(how):
    return diagnosis.diagnose_device(how[1]) if how[0] == "device" else diagnosis.diagnose_connectivity(how[1], how[2])


def test_every_scenario_except_the_password_one_is_covered():
    covered = {c[0] for c in CASES} | {"camera-default-password"}   # a security finding, tested below
    assert covered == set(faults.SCENARIOS)


@pytest.mark.parametrize("scenario, target, how, evidence", CASES, ids=[c[0] for c in CASES])
def test_the_playbook_finds_the_cause_of_each_fault(lab, scenario, target, how, evidence):
    assert investigate(how)["problems"] == []                   # healthy lab: nothing to report
    run = faults.inject(scenario, target)
    found = problems(investigate(how))
    for text in evidence:
        assert text in found, f"{scenario}: expected '{text}' in: {found}"
    faults.revert(run["id"])
    assert investigate(how)["problems"] == [], f"{scenario}: still reported after the revert"


def test_a_default_camera_password_is_a_security_finding_not_an_outage(lab):
    faults.inject("camera-default-password", "cam-khalid")
    result = diagnosis.diagnose_device("cam-khalid")
    assert result["problems"] == []
    assert result["security_findings"] == ["Camera is using the default password (admin)"]
    assert "not the cause of an outage" in result["security_note"]


def test_the_steps_are_in_path_order_with_ok_flags(lab):
    faults.inject("branch-link-down", "fw-branch2")
    result = diagnosis.diagnose_connectivity("host-khalid", "sara")
    assert result["path"] == ["host-khalid", "fw-branch1", "r1", "fw-branch2", "host-sara"]
    checks = [s["check"] for s in result["steps"]]
    assert checks.index("host-khalid -> host-sara: ping") < checks.index("fw-branch2: eth1 link up")
    trace = next(s for s in result["steps"] if s["check"].endswith("traceroute"))
    assert trace["ok"] is False and "stops after 10.10.1.1" in trace["detail"]
    assert all(s["ok"] in (True, False, None) and s["detail"] and s["kind"] in ("symptom", "cause", "consequence")
               for s in result["steps"])
    assert "problem(s) found" in result["summary"]


def test_a_healthy_result_tells_the_assistant_not_to_guess(lab):
    result = diagnosis.diagnose_device("host-sara")
    assert result["problems"] == [] and "Do not guess" in result["note"]


def test_same_branch_devices_skip_the_core(lab):
    result = diagnosis.diagnose_connectivity("host-khalid", "cam-khalid")
    assert result["path"] == ["host-khalid", "cam-khalid"] and result["problems"] == []


def test_bad_names_are_explained(lab):
    assert "error" in diagnosis.diagnose_device("nobody")
    assert "error" in diagnosis.diagnose_connectivity("host-khalid", "nobody")


def test_recent_actions_show_changes_but_not_the_test_harness(lab):
    import time
    now = time.strftime("%Y-%m-%dT%H:%M:%S+0300")
    old = time.strftime("%Y-%m-%dT%H:%M:%S+0300", time.localtime(time.time() - 7200))
    log = [
        {"ts": old, "actor": "dashboard", "tool": "power_off", "args": {"name_or_owner": "host-sara"}, "status": "confirmed"},
        {"ts": now, "actor": "web", "tool": "get_status", "args": {"name_or_owner": "host-khalil"}, "status": "executed"},
        {"ts": now, "actor": "scenarios", "tool": "power_off", "args": {"name_or_owner": "host-khalil"}, "status": "executed"},
        {"ts": now, "actor": "web", "tool": "block_port", "args": {"fw_id": "fw-branch1", "port": 23}, "status": "confirmed"},
        {"ts": now, "actor": "dashboard", "tool": "power_off", "args": {"name_or_owner": "host-khalil"}, "status": "pending"},
    ]
    diagnosis.set_sources(actions=lambda: log)
    assert diagnosis.recent_actions() == [{"time": now[11:19], "actor": "web", "tool": "block_port",
                                           "device": "fw-branch1", "status": "confirmed"}]
    assert diagnosis.recent_actions(device="host") == []
    assert len(diagnosis.recent_actions(minutes=180)) == 2       # the old power_off is now in range
    result = diagnosis.diagnose_device("fw-branch1")
    assert "web ran block_port on fw-branch1" in next(s for s in result["steps"] if s["check"] == "recent changes by NetMind")["detail"]


def test_the_monitor_view_and_recent_alerts_are_part_of_the_evidence(lab):
    import time
    diagnosis.set_sources(health=lambda: [{"device": "cam-khalid", "state": "degraded", "reason": "camera stream is not answering"}],
                          alerts=lambda: [{"ts": time.time() * 1000, "kind": "device_degraded", "device": "cam-khalid",
                                           "detail": "cam-khalid: camera stream is not answering"}])
    lab.stream["cam-khalid"] = False
    result = diagnosis.diagnose_device("cam-khalid")
    assert result["steps"][0] == {"check": "cam-khalid: monitoring state", "ok": False, "kind": "symptom",
                                  "detail": "the background monitor sees cam-khalid as degraded: camera stream is not answering"}
    assert result["likely_causes"] == ["cam-khalid's video service is not running (it does not answer even directly)"]
    assert any(s["check"] == "recent alerts" and "device_degraded" in s["detail"] for s in result["steps"])


def test_a_crash_and_an_out_of_memory_kill_are_told_apart(lab, monkeypatch):
    lab.power["host-sara"] = False
    monkeypatch.setattr(Box, "attrs", property(lambda self: {"State": {"ExitCode": 1, "FinishedAt": "0001-01-01T00:00:00Z"}}))
    assert "exited with code 1: it crashed" in problems(diagnosis.diagnose_device("host-sara"))
    monkeypatch.setattr(Box, "attrs", property(lambda self: {"State": {"ExitCode": 137, "OOMKilled": True}}))
    assert "too much memory" in problems(diagnosis.diagnose_device("host-sara"))


def test_the_tools_are_registered_read_only_for_the_simulated_lab():
    import backends
    from tool_catalog import registry
    from tools import Risk
    for name in ("diagnose_connectivity", "diagnose_device", "get_recent_actions"):
        assert registry.get(name).risk == Risk.READ
        assert backends.ContainerlabBackend().supports(name)
        assert not backends.RealLanBackend().supports(name)


def test_a_verdict_can_be_recorded_on_a_run(lab):
    run = faults.inject("camera-stream-stop", "cam-khalid")
    assert faults.set_verdict(run["id"], "correct")["diagnosis"] == "correct"
    assert faults.set_verdict(run["id"], None)["diagnosis"] is None
    with pytest.raises(faults.FaultError, match="verdict must be"):
        faults.set_verdict(run["id"], "maybe")
    with pytest.raises(faults.FaultError, match="no fault run"):
        faults.set_verdict("nope", "wrong")


def test_the_verdict_api(lab, monkeypatch):
    from fastapi.testclient import TestClient
    import web_server as ws
    monkeypatch.setattr(ws, "ALERTS_PATH", None)
    run = faults.inject("camera-stream-stop", "cam-khalid")
    client = TestClient(ws.app)
    assert client.post(f"/api/faults/{run['id']}/verdict", json={"verdict": "partly"}).json()["diagnosis"] == "partly"
    assert client.post(f"/api/faults/{run['id']}/verdict", json={"verdict": "nah"}).status_code == 400


def test_a_link_down_is_one_cause_and_its_effects_are_consequences(lab):
    faults.inject("branch-link-down", "fw-branch2")
    result = diagnosis.diagnose_connectivity("host-khalid", "host-sara")
    assert result["likely_causes"] == ["fw-branch2's eth1 is switched off on fw-branch2 itself (administratively down)"]
    assert any("fw-branch2 has no route to 10.0.0.0/8, because its eth1 link is down" in c for c in result["consequences"])
    assert any("r1's eth2 has no carrier because fw-branch2's eth1, the other end of the same cable, is switched off" in c
               for c in result["consequences"])
    assert result["symptoms"][0].startswith("host-khalid cannot reach host-sara")
    assert "not separate faults" in result["note"] and result["summary"].endswith("1 likely cause(s)")


def test_a_symptom_without_a_visible_cause_says_so(lab, monkeypatch):
    monkeypatch.setattr(Lab, "reach", lambda self, *a, **k: (False, 1, 0, 0))   # broken, but no check shows why
    result = diagnosis.diagnose_connectivity("host-khalid", "host-sara")
    assert result["likely_causes"] == [] and result["symptoms"]
    assert "could not be confirmed" not in result["note"] and "no check showed its cause" in result["note"]


def test_power_off_time_is_local(lab):
    lab.power["host-sara"] = False
    detail = problems(diagnosis.diagnose_device("host-sara"))
    assert "UTC" not in detail and re.search(r"powered off at 2026-11-27 \d\d:\d\d:00 [+-]\d{4}", detail)


def test_the_prompt_forbids_power_cycling_network_devices_as_a_fix():
    import web_server as ws
    prompt = ws.MODES["simulated"]["system_prompt"]
    assert "Never power a firewall or the router off and on" in prompt
    assert "likely_causes" in prompt and "Do not guess" in prompt


def test_the_far_end_is_a_consequence_even_when_checked_first(lab):
    """The router can be checked before the firewall that caused the problem (it is on the far side
    of the path): its dead interface is still recognised as the other end of the same cable."""
    faults.inject("branch-link-down", "fw-branch1")
    result = diagnosis.diagnose_connectivity("host-sara", "host-khalid")
    assert result["likely_causes"] == ["fw-branch1's eth1 is switched off on fw-branch1 itself (administratively down)"]
    assert any(c.startswith("r1's eth1 has no carrier because fw-branch1's eth1") for c in result["consequences"])


def test_a_dead_far_end_without_a_known_cause_stays_visible(lab):
    lab.links[("r1", "eth2")] = "nocarrier"     # nothing found on our side explains it
    result = diagnosis.diagnose_device("host-sara")
    assert any("r1's eth2 is switched on but has no carrier" in c for c in result["likely_causes"])


def test_the_prompt_asks_to_group_problems_by_branch():
    import web_server as ws
    assert "same branch" in ws.MODES["simulated"]["system_prompt"]


def test_a_diagnosis_fits_the_space_sent_to_the_model(lab):
    """Results are shortened before they go to the model, so the conclusions come before the steps."""
    import json
    import agent_core as core
    faults.inject("branch-link-down", "fw-branch1")
    result = diagnosis.diagnose_connectivity("host-sara", "host-khalid")
    keys = list(result)
    assert keys.index("likely_causes") < keys.index("steps") and keys[-1] == "steps"
    assert "likely_causes" in json.dumps(result, default=str)[:core.MAX_TOOL_RESULT_CHARS]
