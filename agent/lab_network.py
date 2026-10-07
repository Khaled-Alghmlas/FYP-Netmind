"""Lab-network helpers for the simulated Containerlab network.

reconnect_device(id)  re-attaches a host/camera to its switch/hub after a power
                      cycle: `docker stop` deletes the veth Containerlab created
                      and `docker start` only restores eth0 (management network).
ping_between(a, b)    pings device b from device a over the lab (data-plane)
                      address. The management address is NOT used: it survives a
                      power cycle and would hide a broken link.
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
    # `sudo -n` fails fast instead of waiting for a password nobody can type
    return cmd if os.geteuid() == 0 else ["sudo", "-n"] + cmd


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
                "error": "veth create failed (the server must run as root / with sudo)",
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
