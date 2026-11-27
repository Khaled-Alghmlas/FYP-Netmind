"""Root-cause analysis playbooks (issue #26).

The checks run in code, the same way every time; the language model only reads the evidence and
explains it. Two playbooks:

    diagnose_device(device)            "what is wrong with host-khalil?"
    diagnose_connectivity(src, dst)    "why can't host-ahmed reach cam-fahad?"

Each returns a list of steps, {"check", "ok", "detail"}, where ok is True (passed), False (found a
problem) or None (could not be checked), plus `problems`, the failed steps in path order. Nothing
here changes the lab: every command only reads.

The checks are generic troubleshooting, not a list of known faults: is the device on, are its
links up, does its address and gateway match the lab design (the topology file), are the router's
routes there, do the firewalls on the path drop the traffic, is any link being slowed or made lossy
(tc), does the camera's service answer, is the CPU saturated, and what changed recently.

The design comparison uses the deploy commands in the topology file as "what it should be", so a
wrong gateway or a missing route is reported as a difference from the design, with both values.
"""
import re
import time
from datetime import datetime, timezone

import device_control as dc
import lab_network as ln

# Read-only views of the server's state, set by web_server (like alert_history.set_source).
_sources = {"health": lambda: [], "actions": lambda: [], "alerts": lambda: []}
HIDDEN_ACTORS = ("scenarios",)   # fault injection is a test harness, not part of the network's history


def set_sources(health=None, actions=None, alerts=None):
    for key, fn in (("health", health), ("actions", actions), ("alerts", alerts)):
        if fn is not None:
            _sources[key] = fn


# --- small helpers -----------------------------------------------------------------------------
def _text(out):
    return out.decode(errors="replace") if isinstance(out, (bytes, bytearray)) else str(out or "")


def _run(container, command):
    code, out = container.exec_run(["sh", "-c", command])
    return code, _text(out)


def _registry():
    return dc._load_registry()


def _find(name):
    matches = dc.find_devices(name)
    return matches[0] if len(matches) == 1 else None, [d["id"] for d in matches]


def _container(dev):
    try:
        c = dc._client.containers.get(dev["container"])
        c.reload()
        return c
    except Exception:
        return None


def _design(device_id):
    """What the topology file says this device should have: {iface: cidr} and [(net, via, dev)]."""
    try:
        cmds = ln._load_topology().get("nodes", {}).get(device_id, {}).get("exec", [])
    except Exception:
        return {}, []
    addrs = {dev: cidr for cidr, dev in re.findall(r"ip addr add (\S+) dev (\S+)", " ; ".join(cmds))}
    routes = re.findall(r"ip route add (\S+) via (\S+) dev (\S+)", " ; ".join(cmds))
    return addrs, routes


class _Steps(list):
    """The evidence so far, plus the links found down, so a later check can say that what it found
    is a consequence of one of them (a link taken down also loses its routes and its far end)."""

    def __init__(self):
        super().__init__()
        self.down = set()   # (device_id, interface)


# A failed step is one of: a SYMPTOM (what the user experiences: ping fails, video unreachable),
# a CAUSE (something wrong on a device), or a CONSEQUENCE (follows from a cause found earlier).
def _step(steps, check, ok, detail, kind="cause"):
    steps.append({"check": check, "ok": ok, "detail": detail, "kind": kind})
    return ok


def _peers():
    """{(device, iface): (device, iface)} for the cables between devices in the topology file
    (links to a switch or hub are left out: a bridge is not a device that can be checked)."""
    try:
        topo = ln._load_topology()
    except Exception:
        return {}
    nodes, out = topo.get("nodes", {}), {}
    for link in topo.get("links", []):
        eps = link.get("endpoints") if isinstance(link, dict) else None
        if not eps or len(eps) != 2 or any(":" not in e for e in eps):
            continue
        (a, ai), (b, bi) = (tuple(e.split(":", 1)) for e in eps)
        if nodes.get(a, {}).get("kind") == "bridge" or nodes.get(b, {}).get("kind") == "bridge":
            continue
        out[(a, ai)], out[(b, bi)] = (b, bi), (a, ai)
    return out


def _result(subject, steps, **extra):
    # an interface with no carrier whose other end was found switched off is a consequence of it,
    # whichever of the two was checked first
    down = getattr(steps, "down", set())
    peers = _peers() if down else {}
    for s in steps:
        link = s.pop("link", None)
        if link and peers.get(link) in down:
            peer = peers[link]
            s["kind"] = "consequence"
            s["detail"] = (f"{link[0]}'s {link[1]} has no carrier because {peer[0]}'s {peer[1]}, "
                           "the other end of the same cable, is switched off")
    failed = [s for s in steps if s["ok"] is False]
    problems = [s["detail"] for s in failed]
    causes = [s["detail"] for s in failed if s["kind"] == "cause"]
    # conclusions first, the step list last: if a long result is shortened, only steps are lost
    out = {**subject,
           "summary": f"{len(steps)} checks, {len(problems)} problem(s) found, {len(causes)} likely cause(s)",
           "likely_causes": causes,
           "consequences": [s["detail"] for s in failed if s["kind"] == "consequence"],
           "symptoms": [s["detail"] for s in failed if s["kind"] == "symptom"],
           "problems": problems}
    out.update(extra)
    if not problems:
        out["note"] = "No check failed. Do not guess a cause: say that the checks found nothing wrong."
    elif causes:
        out["note"] = ("Explain the symptoms with likely_causes. The consequences follow from those causes: "
                       "they are not separate faults.")
    else:
        out["note"] = "A symptom was found but no check showed its cause: say so instead of guessing."
    out["steps"] = list(steps)
    return out


def _local(utc_iso):
    """'2026-11-27T18:40:00.123Z' -> '2026-11-27 21:40:00 +0300' (server local time)."""
    try:
        when = datetime.strptime(utc_iso[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        return when.astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
    except ValueError:
        return utc_iso


# --- the individual checks --------------------------------------------------------------------
def _check_power(steps, dev):
    c = _container(dev)
    if c is None:
        _step(steps, f"{dev['id']}: container exists", False, f"{dev['id']}'s container was not found")
        return None
    if c.status == "running":
        _step(steps, f"{dev['id']}: powered on", True, f"{dev['id']} is running")
        return c
    state = (getattr(c, "attrs", None) or {}).get("State", {})
    how = ""
    if state.get("OOMKilled"):
        how = " (killed for using too much memory)"
    elif state.get("ExitCode") in (137, 143):
        how = f" (stopped by a stop request, exit code {state['ExitCode']}, not a crash)"
    elif state.get("ExitCode"):
        how = f" (its process exited with code {state['ExitCode']}: it crashed or failed)"
    when = f" at {_local(state['FinishedAt'])}" if state.get("FinishedAt", "")[:4] not in ("", "0001") else ""
    _step(steps, f"{dev['id']}: powered on", False, f"{dev['id']} is powered off{when}{how}")
    return None


def _check_links(steps, dev, c, interfaces):
    """Link state of each interface. An interface switched off on this device (its UP flag
    cleared) is a cause; one that is switched on but has no carrier only shows that the other end
    of its cable is down, and becomes a consequence once that other end is found (see _result)."""
    code, out = _run(c, "for i in /sys/class/net/eth*; do echo $(basename $i) $(cat $i/operstate) $(cat $i/flags); done")
    links = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            try:
                admin_up = bool(int(parts[2], 16) & 1) if len(parts) > 2 else None
            except ValueError:
                admin_up = None
            links[parts[0]] = (parts[1], admin_up)
    for iface in interfaces:
        state, admin_up = links.get(iface, (None, None))
        if state is None:
            _step(steps, f"{dev['id']}: {iface} present", False,
                  f"{dev['id']} has no {iface}: its lab cable is not attached")
        elif state in ("up", "unknown"):
            _step(steps, f"{dev['id']}: {iface} link up", True, f"{iface} is {state}")
        elif admin_up is False or (admin_up is None and state == "down"):
            steps.down.add((dev["id"], iface))
            _step(steps, f"{dev['id']}: {iface} link up", False,
                  f"{dev['id']}'s {iface} is switched off on {dev['id']} itself (administratively down)")
        else:   # switched on, but nothing answers at the other end of the cable
            _step(steps, f"{dev['id']}: {iface} link up", False,
                  f"{dev['id']}'s {iface} is switched on but has no carrier: the other end of its cable is down")
            steps[-1]["link"] = (dev["id"], iface)


def _check_addresses(steps, dev, c, design_addrs):
    if not design_addrs:
        return
    code, out = _run(c, "ip addr show")
    for iface, cidr in design_addrs.items():
        ok = f" {cidr} " in f" {out} " or re.search(rf"\b{re.escape(cidr)}\b", out) is not None
        _step(steps, f"{dev['id']}: address {cidr} on {iface}", ok,
              f"{iface} has {cidr}" if ok else f"{dev['id']} is missing its design address {cidr} on {iface}")


def _check_routes(steps, dev, c, design_routes, only_nets=None):
    if not design_routes:
        return
    code, out = _run(c, "ip route")
    table = {}
    for line in out.splitlines():
        parts = line.split()
        if parts and "via" in parts:
            table[parts[0]] = parts[parts.index("via") + 1]
    for net, via, iface in design_routes:
        if only_nets and net not in only_nets:
            continue
        actual = table.get(net)
        if actual == via:
            _step(steps, f"{dev['id']}: route {net}", True, f"{net} via {via} as designed")
        elif actual:
            _step(steps, f"{dev['id']}: route {net}", False,
                  f"{dev['id']} sends {net} via {actual}, but the design says via {via} (wrong gateway)")
        elif (dev["id"], iface) in getattr(steps, "down", ()):
            _step(steps, f"{dev['id']}: route {net}", False,
                  f"{dev['id']} has no route to {net}, because its {iface} link is down (Linux drops the routes of a link that is down)",
                  kind="consequence")
        else:
            _step(steps, f"{dev['id']}: route {net}", False, f"{dev['id']} has no route to {net} (design: via {via})")


def _check_shaping(steps, dev, c, interfaces):
    for iface in interfaces:
        code, out = _run(c, f"tc qdisc show dev {iface}")
        if code in (126, 127) or "not found" in out:
            return   # no tc in this image: cannot be checked here, and nothing could have set it
        if "netem" in out:
            params = re.findall(r"\b(delay|loss|duplicate|corrupt|reorder|rate)\s+(\S+)", out)
            what = ", ".join(f"{k} {v}" for k, v in params) or "an impairment"
            _step(steps, f"{dev['id']}: traffic shaping on {iface}", False,
                  f"{dev['id']}'s {iface} has a netem impairment: {what}")
        else:
            _step(steps, f"{dev['id']}: traffic shaping on {iface}", True, f"no delay or loss configured on {iface}")


_RULE = re.compile(r"^-A (\S+) (.*) -j (DROP|REJECT)\s*$")


def _check_firewall(steps, fw, c, dst_ip=None):
    """DROP/REJECT rules that can stop forwarded traffic, and rules running now that are not in
    the firewall's saved configuration (changed at run time without being saved)."""
    code, live = _run(c, "iptables -S")
    if code != 0:
        _step(steps, f"{fw['id']}: firewall rules", None, "the rules could not be read")
        return
    _code, saved = _run(c, "cat /etc/netmind-fw-rules 2>/dev/null")
    saved_rules = {line.strip() for line in saved.splitlines() if line.startswith("-A ")}
    blocking = []
    for line in live.splitlines():
        m = _RULE.match(line.strip())
        if not m or m.group(1) != "FORWARD":
            continue
        dest = re.search(r"-d (\d+\.\d+\.\d+\.\d+)", m.group(2))
        if dst_ip and dest and dest.group(1) != dst_ip:
            continue
        blocking.append(line.strip())
    unsaved = [line.strip() for line in live.splitlines()
               if line.startswith("-A ") and saved_rules and line.strip() not in saved_rules]
    if blocking:
        _step(steps, f"{fw['id']}: forwarding rules", False,
              f"{fw['id']} drops forwarded traffic: " + "; ".join(blocking))
    else:
        _step(steps, f"{fw['id']}: forwarding rules", True, "no rule drops the forwarded traffic")
    if unsaved:
        _step(steps, f"{fw['id']}: running rules match the saved configuration", False,
              f"{fw['id']} has rules that are not in its saved configuration (changed at run time): " + "; ".join(unsaved))


def _ping(c, ip, count=3):
    code, out = _run(c, f"ping -c {count} -W 2 -q {ip}")
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", out)
    if not m:
        return None, None, None
    sent, received = int(m.group(1)), int(m.group(2))
    rtt = re.search(r"=\s*[\d.]+/([\d.]+)/", out)
    return received, sent, float(rtt.group(1)) if rtt else None


def _describe_ping(src_id, dst_id, ip, received, sent, rtt):
    if received is None:
        return None, f"ping from {src_id} to {dst_id} could not run"
    loss = round(100 * (sent - received) / sent) if sent else 100
    if received == 0:
        return False, f"{src_id} cannot reach {dst_id} ({ip}): 100% packet loss"
    if loss >= 20:
        return False, f"{src_id} reaches {dst_id} with {loss}% packet loss" + (f", {rtt:.0f} ms" if rtt else "")
    if rtt is not None and rtt >= 200:
        return False, f"{src_id} reaches {dst_id} but slowly: {rtt:.0f} ms average round trip"
    return True, f"{src_id} reaches {dst_id} ({ip}), {loss}% loss" + (f", {rtt:.1f} ms" if rtt is not None else "")


def _check_camera_service(steps, cam, via=None, via_container=None):
    """The camera's service through its management address (is it running at all?) and, when a
    source is given, through the lab path (does the traffic get there?)."""
    service = dc._snapshot_ok(f"http://{cam['ip']}:8080/snapshot") if cam.get("ip") else None
    if service is not None:
        _step(steps, f"{cam['id']}: camera service running", bool(service),
              f"{cam['id']}'s video service answers" if service else f"{cam['id']}'s video service is not running (it does not answer even directly)")
    if via_container is not None and cam.get("network_ip"):
        code, _ = _run(via_container, f"wget -q -T 3 -O /dev/null http://{cam['network_ip']}:8080/snapshot")
        ok = code == 0
        if service and not ok:
            detail = f"{via['id']} cannot open {cam['id']}'s video, although the service runs: something on the path blocks port 8080"
        else:
            detail = f"{via['id']} {'can' if ok else 'cannot'} open {cam['id']}'s video over the lab network"
        _step(steps, f"{via['id']} -> {cam['id']}: video port 8080", ok, detail, kind="symptom")


def _check_cpu(steps, dev, c):
    try:
        stats = dc._cpu_mem(c.stats(stream=False))
    except Exception:
        return
    cpu = stats.get("cpu")
    if cpu is None:
        return
    _step(steps, f"{dev['id']}: CPU", cpu < 90, f"{dev['id']} CPU at {cpu:.0f}%" + (" (saturated)" if cpu >= 90 else ""))


def _recent(steps, device_ids, minutes=60):
    cutoff = time.time() - minutes * 60
    actions = [a for a in recent_actions(minutes=minutes) if not device_ids or a.get("device") in device_ids]
    if actions:
        _step(steps, "recent changes by NetMind", None,
              "; ".join(f"{a['time']} {a['actor']} ran {a['tool']} on {a.get('device') or '-'} ({a['status']})" for a in actions[:5]))
    else:
        _step(steps, "recent changes by NetMind", None, f"no NetMind action touched these devices in the last {minutes} minutes")
    alerts = [a for a in _sources["alerts"]() if a.get("ts", 0) / 1000 >= cutoff
              and (not device_ids or a.get("device") in device_ids)]
    if alerts:
        _step(steps, "recent alerts", None, "; ".join(
            f"{time.strftime('%H:%M:%S', time.localtime(a['ts'] / 1000))} {a.get('kind')} {a.get('device')}: {a.get('detail')}"
            for a in sorted(alerts, key=lambda a: a["ts"])[:6]))


# --- the playbooks ----------------------------------------------------------------------------
def _branch_firewall(dev):
    if dev["type"] == "firewall":
        return dev
    if dev["type"] == "router":
        return None
    return next((d for d in _registry() if d["type"] == "firewall" and d.get("branch") == dev.get("branch")), None)


def _router():
    return next((d for d in _registry() if d["type"] == "router"), None)


def _branch_net(fw):
    parts = (fw.get("network_ip") or "").split(".")
    return ".".join(parts[:3] + ["0"]) + "/24" if len(parts) == 4 else None


def _running_container(dev):
    c = _container(dev) if dev else None
    return c if c is not None and c.status == "running" else None


def _endpoint_checks(steps, dev, c):
    """A host's or camera's own side: cable, address, gateway, shaping."""
    addrs, routes = _design(dev["id"])
    _check_links(steps, dev, c, ["eth1"])
    _check_addresses(steps, dev, c, addrs)
    _check_routes(steps, dev, c, routes)
    _check_shaping(steps, dev, c, ["eth1"])


def _firewall_checks(steps, fw, peer_ip=None):
    c = _running_container(fw)
    if c is None:
        _check_power(steps, fw)
        return
    _step(steps, f"{fw['id']}: powered on", True, f"{fw['id']} is running")
    _addrs, routes = _design(fw["id"])
    _check_links(steps, fw, c, ["eth1", "eth2"])
    _check_routes(steps, fw, c, routes)
    _check_shaping(steps, fw, c, ["eth1", "eth2"])
    _check_firewall(steps, fw, c, peer_ip)


def _router_checks(steps, router, fws):
    """The router's side towards the given branch firewalls: its interface and its route."""
    c = _running_container(router)
    if c is None:
        _check_power(steps, router)
        return
    _addrs, routes = _design(router["id"])
    nets = {_branch_net(fw) for fw in fws if fw}
    wanted = [r for r in routes if r[0] in nets]
    _check_links(steps, router, c, sorted({iface for _net, _via, iface in wanted}))
    _check_routes(steps, router, c, wanted)


def diagnose_device(device):
    """Everything that can be wrong with one device, checked from the device out to the core."""
    dev, matches = _find(device)
    if dev is None:
        return {"error": "name must match exactly one device", "matches": matches}
    steps = _Steps()
    health = next((h for h in _sources["health"]() if h.get("device") == dev["id"]), None)
    if health and health.get("state"):
        _step(steps, f"{dev['id']}: monitoring state", health["state"] == "up",
              f"the background monitor sees {dev['id']} as {health['state']}: {health.get('reason')}", kind="symptom")
    c = _check_power(steps, dev)
    router = _router()
    if c is not None:
        if dev["type"] in ("host", "camera"):
            _endpoint_checks(steps, dev, c)
        fw = _branch_firewall(dev)
        if dev["type"] != "router":
            if fw is not None:
                _firewall_checks(steps, fw, None if fw is dev else dev.get("network_ip"))
            if router is not None:
                _router_checks(steps, router, [fw])
        else:
            _router_checks(steps, dev, [d for d in _registry() if d["type"] == "firewall"])
        rc = _running_container(router) if router and router["id"] != dev["id"] else None
        if rc is not None and dev.get("network_ip"):
            ok, detail = _describe_ping(router["id"], dev["id"], dev["network_ip"], *_ping(rc, dev["network_ip"]))
            _step(steps, f"{router['id']} -> {dev['id']}: reachable over the lab", ok, detail, kind="symptom")
        if dev["type"] == "camera":
            _check_camera_service(steps, dev, via=router, via_container=rc)
        _check_cpu(steps, dev, c)
    _recent(steps, {dev["id"]})
    try:
        security = [text for d, text, _kind in dc.get_security_findings() if d == dev["id"]]
    except Exception:
        security = []
    return _result({"device": dev["id"]}, steps, security_findings=security,
                   security_note="Security findings are listed separately: they are not the cause of an outage "
                                 "unless a failed check points to them.")


def diagnose_connectivity(src, dst):
    """Why src cannot reach dst (or reaches it badly): the symptom first, then the path hop by hop."""
    a, a_matches = _find(src)
    b, b_matches = _find(dst)
    if a is None or b is None:
        return {"error": "src and dst must each match exactly one device", "src_matches": a_matches, "dst_matches": b_matches}
    if not b.get("network_ip"):
        return {"error": f"{b['id']} has no lab address"}
    steps = _Steps()
    ac = _check_power(steps, a)
    bc = _check_power(steps, b)
    if ac is not None:
        ok, detail = _describe_ping(a["id"], b["id"], b["network_ip"], *_ping(ac, b["network_ip"]))
        _step(steps, f"{a['id']} -> {b['id']}: ping", ok, detail, kind="symptom")
        if ok is not True:
            trace = ln.traceroute(a["id"], b["id"])
            hops = [h for h in trace.get("hops", []) if h.get("ip")]
            if hops:
                route = " -> ".join(h["ip"] + (f" ({h['rtt_ms']:.0f} ms)" if h.get("rtt_ms") else "") for h in hops)
                stops = "" if trace.get("reached") else f"; the trace stops after {hops[-1]['ip']}"
                _step(steps, f"{a['id']} -> {b['id']}: traceroute", bool(trace.get("reached")),
                      f"path: {route}{stops}", kind="symptom")
            elif "error" not in trace:
                _step(steps, f"{a['id']} -> {b['id']}: traceroute", False,
                      "no hop answered: the first link or the gateway is already broken", kind="symptom")
    # the path, in order: source side, its firewall, the router, the far firewall, destination side
    fa, fb, router = _branch_firewall(a), _branch_firewall(b), _router()
    same_branch = fa is not None and fa is fb and a["type"] != "firewall" and b["type"] != "firewall"
    if ac is not None and a["type"] in ("host", "camera"):
        _endpoint_checks(steps, a, ac)
    if not same_branch:
        if fa is not None:
            _firewall_checks(steps, fa, b["network_ip"])
        if router is not None and router["id"] not in (a["id"], b["id"]):
            _router_checks(steps, router, [fa, fb])
        if fb is not None and fb is not fa:
            _firewall_checks(steps, fb, b["network_ip"])
    if bc is not None and b["type"] in ("host", "camera"):
        _endpoint_checks(steps, b, bc)
    if b["type"] == "camera":
        _check_camera_service(steps, b, via=a, via_container=ac)
    path = [d["id"] for d in ([a] + ([] if same_branch else [x for x in (fa, router, fb) if x]) + [b])]
    path = list(dict.fromkeys(path))
    _recent(steps, set(path))
    return _result({"from": a["id"], "to": b["id"], "path": path}, steps)


def recent_actions(device="", minutes=60):
    """Changes made through NetMind (power, firewall, camera actions), newest first. Read-only
    lookups and the fault-injection test harness are left out."""
    from tool_catalog import registry   # lazy: tool_catalog imports this module's callers
    changes = registry.action_names()
    cutoff = time.time() - max(1, min(int(minutes), 24 * 60)) * 60
    out = []
    for e in reversed(_sources["actions"]()):
        if e.get("actor") in HIDDEN_ACTORS or e.get("tool") not in changes \
                or e.get("status") not in ("executed", "confirmed", "error"):
            continue
        try:
            ts = time.mktime(time.strptime(e["ts"][:19], "%Y-%m-%dT%H:%M:%S"))
        except (KeyError, ValueError):
            continue
        if ts < cutoff:
            break
        args = e.get("args") or {}
        target = args.get("name_or_owner") or args.get("fw_id") or args.get("cam_id") or args.get("device") or ""
        if device and device not in str(target):
            continue
        out.append({"time": e["ts"][11:19], "actor": e.get("actor"), "tool": e.get("tool"),
                    "device": target, "status": e.get("status")})
    return out
