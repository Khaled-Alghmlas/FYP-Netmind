"""Lab-network helpers for the simulated Containerlab network.

reconnect_device(id)  re-attaches a host/camera to its switch/hub after a power
                      cycle: `docker stop` deletes the veth Containerlab created
                      and `docker start` only restores eth0 (management network).
ping_between(a, b)    pings device b from device a over the lab (data-plane)
                      address. The management address is NOT used: it survives a
                      power cycle and would hide a broken link.
traceroute(a, b)      the hop-by-hop path from device a to device b (lab addresses)
get_routes()          the routing table of the router r1, read through FRR's vtysh
get_interface_stats() per-interface packet/error/drop counters and link state of a device
All three are read-only: they only look, they never change the lab.
"""
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

import docker
import yaml

import device_control as dc

TOPOLOGY_FILE = Path(__file__).resolve().parent.parent / "topology" / "netmind-large.clab.yml"
RECONNECTABLE_TYPES = ("host", "camera")  # leaf devices with a single bridge link
HELPER = "/usr/local/sbin/netmind-reconnect"   # installed by `make setup-perms`
_VETH_CREATE = ["containerlab", "tools", "veth", "create"]


def _load_topology():
    with open(TOPOLOGY_FILE) as f:
        data = yaml.safe_load(f)
    return data.get("topology", data)


def _bridge_link(topo, device_id):
    """Returns (interface, bridge, bridge_port) for the device's link to a bridge node."""
    nodes = topo.get("nodes", {})
    for link in topo.get("links", []):
        eps = link.get("endpoints") if isinstance(link, dict) else None
        if not eps or len(eps) != 2:
            continue
        parsed = [tuple(e.split(":", 1)) for e in eps]
        for mine, other in (parsed, parsed[::-1]):
            if mine[0] == device_id and nodes.get(other[0], {}).get("kind") == "bridge":
                return mine[1], other[0], other[1]
    return None


def _as_root(cmd):
    """Run `cmd` (a `containerlab tools veth create ...` command) with the privilege it needs.
    - already root: as it is.
    - the validating helper is installed (`make setup-perms`): sudo that one command, no password.
    - otherwise plain `sudo -n`, which only works while a sudo ticket is fresh; `-n` fails fast
      instead of waiting for a password nobody can type."""
    if os.geteuid() == 0:
        return cmd
    if cmd[:4] == _VETH_CREATE and os.access(HELPER, os.X_OK):
        return ["sudo", "-n", HELPER] + cmd[4:]
    return ["sudo", "-n"] + cmd


def _has_iface(container, iface):
    code, _ = container.exec_run(["ip", "link", "show", iface])
    return code == 0


def _gateway(commands):
    """Gateway ip from a replayed route command, e.g. `ip route add 10.0.0.0/8 via 10.1.0.1 dev eth1`."""
    for c in commands:
        m = re.search(r"\bvia\s+(\d+\.\d+\.\d+\.\d+)", c)
        if m:
            return m.group(1)
    return None


def _verify_link(container, gateway, wait=5.0):
    """True once the device can ping its gateway, retrying for up to `wait` seconds.
    A freshly created veth needs a moment before it passes traffic."""
    deadline = time.time() + wait
    while True:
        code, _ = container.exec_run(["ping", "-c", "1", "-W", "1", gateway])
        if code == 0:
            return True
        if time.time() >= deadline:
            return False
        time.sleep(0.5)


def reconnect_device(device_id, veth_timeout="20s"):
    """Re-creates the link between a host/camera and its bridge after a power cycle."""
    dev = next((d for d in dc._load_registry() if d["id"] == device_id), None)
    if dev is None:
        return {"id": device_id, "error": "unknown device"}
    if dev["type"] not in RECONNECTABLE_TYPES:
        return {"id": device_id, "skipped": "only hosts and cameras are re-attached automatically"}
    if shutil.which("containerlab") is None:
        return {"id": device_id, "skipped": "containerlab is not installed on this machine"}

    try:
        container = dc._client.containers.get(dev["container"])
        container.reload()
    except docker.errors.NotFound:
        return {"id": device_id, "error": "container not found"}
    if container.status != "running":
        return {"id": device_id, "error": "device is powered off"}

    try:
        topo = _load_topology()
    except (OSError, yaml.YAMLError) as e:
        return {"id": device_id, "error": f"cannot read topology file: {e}"}
    link = _bridge_link(topo, device_id)
    if link is None:
        return {"id": device_id, "error": "no bridge link found in the topology file"}
    iface, bridge, port = link

    if _has_iface(container, iface):
        return {"id": device_id, "reconnected": False, "reason": f"{iface} is already present"}

    cmd = _as_root(["containerlab", "tools", "veth", "create",
                    "-a", f"{dev['container']}:{iface}",
                    "-b", f"bridge:{bridge}:{port}",
                    "--timeout", veth_timeout])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return {"id": device_id, "error": "veth create timed out"}
    if r.returncode != 0:
        return {"id": device_id,
                "error": "veth create failed (the server needs permission: run 'make setup-perms' once, or start it as root)",
                "detail": (r.stderr or r.stdout)[-300:]}

    container.exec_run(["ip", "link", "set", iface, "up"])
    # replay the addressing/routing commands Containerlab ran for this node at deploy time
    commands = topo.get("nodes", {}).get(device_id, {}).get("exec", [])
    for command in commands:
        container.exec_run(["sh", "-c", command])
    result = {"id": device_id, "reconnected": True, "interface": iface, "bridge_port": f"{bridge}:{port}"}
    gateway = _gateway(commands)
    if gateway:
        result["verified"] = _verify_link(container, gateway)
        result["gateway"] = gateway
        if not result["verified"]:
            result["warning"] = f"link created but {gateway} is not reachable yet"
    else:
        result["verified"] = None  # no gateway in the topology file, nothing to check against
    return result


def ping_between(src, dst, count=3):
    """Pings dst from src over the lab network. src/dst must each match one device."""
    count = max(1, min(int(count), 5))
    a, b = dc.find_devices(src), dc.find_devices(dst)
    if len(a) != 1 or len(b) != 1:
        return {"error": "src and dst must each match exactly one device",
                "src_matches": [d["id"] for d in a], "dst_matches": [d["id"] for d in b]}
    a, b = a[0], b[0]
    ip = b.get("network_ip")
    if not ip:
        return {"error": f"{b['id']} has no lab address in registry.json"}
    try:
        container = dc._client.containers.get(a["container"])
        container.reload()
    except docker.errors.NotFound:
        return {"error": f"{a['id']} not found"}
    if container.status != "running":
        return {"error": f"{a['id']} is powered off"}
    _, out = container.exec_run(["ping", "-c", str(count), "-W", "2", ip])
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", out.decode(errors="replace"))
    sent, received = (int(m.group(1)), int(m.group(2))) if m else (count, 0)
    return {"from": a["id"], "to": b["id"], "to_ip": ip,
            "sent": sent, "received": received, "reachable": received > 0}


# --- read-only diagnostics (issue #23) ---------------------------------------------------------
ROUTER_ID = "r1"
_MAX_OUTPUT_LINES = 80
_HOP_LINE = re.compile(r"^\s*(\d+)\s+(.*)$")
_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_RTT = re.compile(r"([\d.]+)\s*ms")


def _one_running(name):
    """-> (device, container, None) for a name matching exactly one powered-on device, or
    (None, None, {"error": ...}) saying why not."""
    matches = dc.find_devices(name)
    if len(matches) != 1:
        return None, None, {"error": "name must match exactly one device", "matches": [d["id"] for d in matches]}
    dev = matches[0]
    try:
        container = dc._client.containers.get(dev["container"])
        container.reload()
    except docker.errors.NotFound:
        return None, None, {"error": f"{dev['id']} not found"}
    if container.status != "running":
        return None, None, {"error": f"{dev['id']} is powered off"}
    return dev, container, None


def _text(output):
    return output.decode(errors="replace") if isinstance(output, (bytes, bytearray)) else str(output or "")


def _cap_lines(text, limit=_MAX_OUTPUT_LINES):
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    return lines[:limit] + ([f"... ({len(lines) - limit} more lines)"] if len(lines) > limit else [])


def _parse_hops(text):
    """traceroute output -> [{"hop": 1, "ip": "10.1.0.1", "rtt_ms": 0.4}, ...]. A hop that never
    answered ('* * *') has ip None. Header lines ('traceroute to ...') are skipped."""
    hops = []
    for line in text.splitlines():
        m = _HOP_LINE.match(line)
        if not m:
            continue
        rest = m.group(2)
        ip, rtt = _IPV4.search(rest), _RTT.search(rest)
        hops.append({"hop": int(m.group(1)), "ip": ip.group(1) if ip else None,
                     "rtt_ms": float(rtt.group(1)) if rtt else None})
    return hops


def traceroute(src, dst, max_hops=8):
    """Traces the path from src to dst over the lab network (the dst lab address, not management)."""
    max_hops = max(1, min(int(max_hops), 15))
    a, b = dc.find_devices(src), dc.find_devices(dst)
    if len(a) != 1 or len(b) != 1:
        return {"error": "src and dst must each match exactly one device",
                "src_matches": [d["id"] for d in a], "dst_matches": [d["id"] for d in b]}
    ip = b[0].get("network_ip")
    if not ip:
        return {"error": f"{b[0]['id']} has no lab address in registry.json"}
    dev, container, err = _one_running(a[0]["id"])
    if err:
        return err
    code, out = container.exec_run(["traceroute", "-n", "-m", str(max_hops), "-w", "1", "-q", "1", ip])
    text = _text(out)
    if code in (126, 127):
        return {"error": f"traceroute is not available inside {dev['id']}"}
    hops = _parse_hops(text)
    result = {"from": dev["id"], "to": b[0]["id"], "to_ip": ip, "hops": hops,
              "reached": bool(hops) and hops[-1]["ip"] == ip}
    if not hops:
        result["output"] = _cap_lines(text, 10)
    return result


_PREFIX = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b")
_NEXTHOP_LINE = re.compile(r"^\s+\*?\s*via\s")


def _route_lines(text):
    """Only the route entries of `show ip route`: the codes legend and vtysh notices such as
    "% Can't open configuration file /etc/frr/vtysh.conf" are dropped. Falls back to every
    line if nothing looks like a route, so an unexpected format is still shown."""
    routes = [line for line in text.splitlines() if _PREFIX.search(line) or _NEXTHOP_LINE.match(line)]
    return _cap_lines("\n".join(routes)) if routes else _cap_lines(text)


def get_routes():
    """Routing table of the router r1: FRR's `vtysh -c "show ip route"`. If vtysh does not work
    (FRR daemons not running) the kernel table from `ip route` is returned instead, and says so."""
    dev, container, err = _one_running(ROUTER_ID)
    if err:
        return err
    code, out = container.exec_run(["vtysh", "-c", "show ip route"])
    if code == 0 and _text(out).strip():
        return {"router": dev["id"], "source": "vtysh", "routes": _route_lines(_text(out))}
    code2, out2 = container.exec_run(["ip", "route"])
    if code2 != 0:
        return {"error": f"could not read the routes of {dev['id']}", "detail": _text(out)[-200:]}
    return {"router": dev["id"], "source": "ip route",
            "warning": "vtysh did not answer, so this is the kernel routing table",
            "routes": _cap_lines(_text(out2))}


_STATS_CMD = ("cat /proc/net/dev; for i in /sys/class/net/*; do "
              "echo \"STATE $(basename $i) $(cat $i/operstate 2>/dev/null)\"; done")
_COUNTERS = ("rx_bytes", "rx_packets", "rx_errors", "rx_dropped", None, None, None, None,
             "tx_bytes", "tx_packets", "tx_errors", "tx_dropped")


def _parse_interface_stats(text):
    """/proc/net/dev plus the STATE lines -> {interface: {state, rx_*, tx_*}} (loopback skipped)."""
    stats, states = {}, {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("STATE "):
            parts = line.split()
            states[parts[1]] = parts[2] if len(parts) > 2 else "unknown"
        elif ":" in line and not line.startswith(("Inter-", "face")):
            name, _, rest = line.partition(":")
            values = rest.split()
            if name.strip() == "lo" or len(values) < 12:
                continue
            stats[name.strip()] = {key: int(v) for key, v in zip(_COUNTERS, values) if key}
    for name, entry in stats.items():
        entry["state"] = states.get(name, "unknown")
    return stats


def get_interface_stats(device, interface=""):
    """Packet, error and drop counters (and link state) of a device's network interfaces."""
    dev, container, err = _one_running(device)
    if err:
        return err
    code, out = container.exec_run(["sh", "-c", _STATS_CMD])
    stats = _parse_interface_stats(_text(out)) if code == 0 else {}
    if not stats:
        return {"error": f"could not read the interface counters of {dev['id']}"}
    if interface:
        if interface not in stats:
            return {"error": f"{dev['id']} has no interface '{interface}'", "interfaces": sorted(stats)}
        stats = {interface: stats[interface]}
    return {"device": dev["id"], "interfaces": stats}