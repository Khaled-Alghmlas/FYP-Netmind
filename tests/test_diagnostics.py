"""Issue #23: traceroute, get_routes and get_interface_stats. Containers and the registry are faked."""
import types

import device_control as dc
import lab_network as ln
import tool_catalog
from tools import Risk

DEVICES = {
    "host-khalid": {"id": "host-khalid", "container": "c-khalid", "type": "host", "network_ip": "10.1.0.10"},
    "host-sara": {"id": "host-sara", "container": "c-sara", "type": "host", "network_ip": "10.2.0.10"},
    "r1": {"id": "r1", "container": "c-r1", "type": "router", "network_ip": None},
}

TRACE_OK = (b"traceroute to 10.2.0.10 (10.2.0.10), 8 hops max, 46 byte packets\n"
            b" 1  10.1.0.1  0.412 ms\n 2  10.10.1.1  0.733 ms\n 3  10.10.2.2  0.901 ms\n 4  10.2.0.10  1.20 ms\n")
TRACE_BROKEN = (b"traceroute to 10.2.0.10 (10.2.0.10), 8 hops max, 46 byte packets\n"
                b" 1  10.1.0.1  0.4 ms\n 2  10.10.1.1  0.7 ms\n 3  *\n 4  *\n")
PROC_NET_DEV = (b"Inter-|   Receive                                                |  Transmit\n"
                b" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
                b"    lo:     100       2    0    0    0     0          0         0      100       2    0    0    0     0       0          0\n"
                b"  eth0:   50000     400    0    1    0     0          0         0    42000     300    0    0    0     0       0          0\n"
                b"  eth1:    9000      80    3    7    0     0          0         0     8000      70    1    2    0     0       0          0\n"
                b"STATE eth0 up\nSTATE eth1 lowerlayerdown\nSTATE lo unknown\n")


class FakeContainer:
    def __init__(self, replies=None, status="running"):
        self.status, self.replies, self.commands = status, replies or {}, []

    def reload(self):
        pass

    def exec_run(self, cmd, **kwargs):
        self.commands.append(cmd)
        return self.replies.get(cmd[0], (0, b""))


def setup(monkeypatch, containers):
    def find(name):
        exact = [d for d in DEVICES.values() if d["id"] == name]
        return exact or [d for d in DEVICES.values() if d["id"].endswith("-" + name)]
    monkeypatch.setattr(dc, "find_devices", find)
    monkeypatch.setattr(dc, "_client", types.SimpleNamespace(
        containers=types.SimpleNamespace(get=lambda name: containers[name])))


# --- traceroute --------------------------------------------------------------------------
def test_traceroute_lists_the_hops_and_says_the_destination_was_reached(monkeypatch):
    c = FakeContainer({"traceroute": (0, TRACE_OK)})
    setup(monkeypatch, {"c-khalid": c})
    r = ln.traceroute("host-khalid", "host-sara")
    assert [h["ip"] for h in r["hops"]] == ["10.1.0.1", "10.10.1.1", "10.10.2.2", "10.2.0.10"]
    assert r["hops"][0]["rtt_ms"] == 0.412 and r["reached"] is True
    assert "10.2.0.10" in c.commands[-1]                       # the lab address, not the management one


def test_traceroute_shows_where_the_path_stops(monkeypatch):
    setup(monkeypatch, {"c-khalid": FakeContainer({"traceroute": (0, TRACE_BROKEN)})})
    r = ln.traceroute("host-khalid", "host-sara")
    assert r["reached"] is False and r["hops"][-1]["ip"] is None and r["hops"][1]["ip"] == "10.10.1.1"


def test_traceroute_clamps_max_hops(monkeypatch):
    c = FakeContainer({"traceroute": (0, TRACE_OK)})
    setup(monkeypatch, {"c-khalid": c})
    ln.traceroute("host-khalid", "host-sara", max_hops=500)
    cmd = c.commands[-1]
    assert cmd[cmd.index("-m") + 1] == "15"


def test_traceroute_errors_are_clear(monkeypatch):
    setup(monkeypatch, {"c-khalid": FakeContainer(status="exited")})
    assert "powered off" in ln.traceroute("host-khalid", "host-sara")["error"]
    setup(monkeypatch, {"c-khalid": FakeContainer({"traceroute": (127, b"not found")})})
    assert "not available" in ln.traceroute("host-khalid", "host-sara")["error"]
    assert "exactly one" in ln.traceroute("nobody", "host-sara")["error"]
    assert "no lab address" in ln.traceroute("host-khalid", "r1")["error"]


# --- get_routes --------------------------------------------------------------------------
def test_get_routes_reads_the_router_through_vtysh(monkeypatch):
    out = b"Codes: K - kernel route, C - connected\n\nK>* 10.1.0.0/24 [0/0] via 10.10.1.2, eth1, 00:05:10\nC>* 10.10.1.0/30 is directly connected, eth1\n"
    c = FakeContainer({"vtysh": (0, out)})
    setup(monkeypatch, {"c-r1": c})
    r = ln.get_routes()
    assert r["source"] == "vtysh" and r["router"] == "r1"
    assert any("10.1.0.0/24" in line for line in r["routes"])
    assert c.commands[0] == ["vtysh", "-c", "show ip route"]


def test_get_routes_keeps_only_route_entries(monkeypatch):
    out = (b"% Can't open configuration file /etc/frr/vtysh.conf due to 'No such file or directory'.\n"
           b"Codes: K - kernel route, C - connected, S - static, R - RIP,\n"
           b"       > - selected route, * - FIB route, q - queued, r - rejected, b - backup\n\n"
           b"K>* 0.0.0.0/0 [0/0] via 172.20.20.1, eth0, 00:50:08\n"
           b"K>* 10.1.0.0/24 [0/0] via 10.10.1.2, eth1, 00:50:04\n"
           b"S>* 10.9.0.0/24 [1/0] via 10.10.1.2, eth1, 00:01:00\n"
           b"  *                    via 10.10.2.2, eth2, 00:01:00\n"
           b"C>* 10.10.1.0/30 is directly connected, eth1, 00:50:05\n")
    setup(monkeypatch, {"c-r1": FakeContainer({"vtysh": (0, out)})})
    routes = ln.get_routes()["routes"]
    assert routes[0].startswith("K>* 0.0.0.0/0") and routes[-1].startswith("C>* 10.10.1.0/30")
    assert len(routes) == 5                                  # 4 routes + the second next hop
    assert not any("vtysh.conf" in r or r.startswith("Codes") for r in routes)


def test_get_routes_shows_everything_if_no_line_looks_like_a_route(monkeypatch):
    setup(monkeypatch, {"c-r1": FakeContainer({"vtysh": (0, b"some new output format\nwith no prefixes\n")})})
    assert ln.get_routes()["routes"] == ["some new output format", "with no prefixes"]


def test_get_routes_falls_back_to_the_kernel_table(monkeypatch):
    c = FakeContainer({"vtysh": (1, b"zebra is not running"), "ip": (0, b"10.1.0.0/24 via 10.10.1.2 dev eth1\n")})
    setup(monkeypatch, {"c-r1": c})
    r = ln.get_routes()
    assert r["source"] == "ip route" and "kernel" in r["warning"] and r["routes"] == ["10.1.0.0/24 via 10.10.1.2 dev eth1"]


def test_get_routes_long_output_is_capped(monkeypatch):
    out = "\n".join(f"K>* 10.{i}.0.0/24 via 10.10.1.2" for i in range(200)).encode()
    setup(monkeypatch, {"c-r1": FakeContainer({"vtysh": (0, out)})})
    routes = ln.get_routes()["routes"]
    assert len(routes) == ln._MAX_OUTPUT_LINES + 1 and routes[-1].startswith("... (")


# --- get_interface_stats -----------------------------------------------------------------
def test_interface_stats_parse_counters_and_link_state(monkeypatch):
    setup(monkeypatch, {"c-r1": FakeContainer({"sh": (0, PROC_NET_DEV)})})
    r = ln.get_interface_stats("r1")
    assert set(r["interfaces"]) == {"eth0", "eth1"}               # loopback is left out
    eth1 = r["interfaces"]["eth1"]
    assert eth1["rx_errors"] == 3 and eth1["rx_dropped"] == 7 and eth1["tx_packets"] == 70
    assert eth1["state"] == "lowerlayerdown" and r["interfaces"]["eth0"]["state"] == "up"


def test_interface_stats_for_one_interface_and_unknown_interface(monkeypatch):
    setup(monkeypatch, {"c-r1": FakeContainer({"sh": (0, PROC_NET_DEV)})})
    assert list(ln.get_interface_stats("r1", "eth0")["interfaces"]) == ["eth0"]
    r = ln.get_interface_stats("r1", "eth9")
    assert "no interface" in r["error"] and r["interfaces"] == ["eth0", "eth1"]


def test_interface_stats_refuse_powered_off_or_unreadable_devices(monkeypatch):
    setup(monkeypatch, {"c-r1": FakeContainer(status="exited")})
    assert "powered off" in ln.get_interface_stats("r1")["error"]
    setup(monkeypatch, {"c-r1": FakeContainer({"sh": (1, b"")})})
    assert "could not read" in ln.get_interface_stats("r1")["error"]


# --- the tools are registered, read-only, and reach the lab functions ---------------------
def test_new_diagnostic_tools_are_read_only_and_never_ask_for_confirmation():
    for name in ("ping_between", "traceroute", "get_routes", "get_interface_stats", "get_alerts"):
        spec = tool_catalog.registry.get(name)
        assert spec is not None and spec.risk == Risk.READ and not spec.needs_confirmation


def test_catalog_tools_call_through_to_lab_network(monkeypatch):
    calls = []
    monkeypatch.setattr(ln, "traceroute", lambda *a: calls.append(("traceroute", a)) or {"ok": 1})
    monkeypatch.setattr(ln, "get_routes", lambda: calls.append(("get_routes", ())) or {"ok": 2})
    monkeypatch.setattr(ln, "get_interface_stats", lambda *a: calls.append(("stats", a)) or {"ok": 3})
    fns = tool_catalog.registry.implementations()
    assert fns["traceroute"]("a", "b", 5) == {"ok": 1} and fns["get_routes"]() == {"ok": 2}
    assert fns["get_interface_stats"]("r1", "eth1") == {"ok": 3}
    assert calls == [("traceroute", ("a", "b", 5)), ("get_routes", ()), ("stats", ("r1", "eth1"))]