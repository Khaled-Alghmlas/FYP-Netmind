#!/usr/bin/env python3
"""Core device control functions for the NetMind agent.
Resolves device/owner names via registry.json, then checks or changes
container state via the Docker SDK — this IS the on/off state we care about."""
import json
import re
import shlex
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import docker
import requests
from pathlib import Path

REGISTRY_PATH = Path(__file__).resolve().parent.parent / "topology" / "registry.json"

class _LazyDockerClient:
    """Connects to the Docker daemon on first use, so this module can be
    imported (e.g. by unit tests / CI) on a machine with no Docker."""
    _real = None

    def __getattr__(self, name):
        if _LazyDockerClient._real is None:
            _LazyDockerClient._real = docker.from_env()
        return getattr(_LazyDockerClient._real, name)

_client = _LazyDockerClient()

def _load_registry():
    with open(REGISTRY_PATH) as f:
        return json.load(f)["devices"]

def find_devices(name_or_owner):
    """Match by exact device id first (e.g. 'host-ahmed'), else by owner name (e.g. 'ahmed' -> all their devices).
    Case-insensitive, since the UI may display names capitalized (e.g. 'Khalid')."""
    devices = _load_registry()
    needle = name_or_owner.strip().lower()
    exact = [d for d in devices if d["id"].lower() == needle]
    if exact:
        return exact
    return [d for d in devices if (d["owner"] or "").lower() == needle]

def list_devices_on_segment(segment_id):
    """List every device attached to a given switch/hub segment (e.g.
    'switch-branch1', 'hub-branch2', 'switch-branch3'). Note: switches/hubs
    themselves are plain Linux bridge interfaces on the host, not
    containers, so this only lists what's connected to one, not the
    segment's own status."""
    devices = _load_registry()
    needle = segment_id.strip().lower()
    matches = [d for d in devices if (d.get("segment") or "").lower() == needle]
    return {
        "segment": segment_id,
        "devices": [{"id": d["id"], "type": d["type"], "owner": d["owner"]} for d in matches],
    }

def _friendly_status(docker_status):
    """Map Docker's raw container status to the same online/offline
    vocabulary real-mode uses, so both modes speak consistently."""
    return "online" if docker_status == "running" else "offline"

def get_status(name_or_owner):
    results = []
    for d in find_devices(name_or_owner):
        try:
            c = _client.containers.get(d["container"])
            state = _friendly_status(c.status)
        except docker.errors.NotFound:
            state = "not found"
        results.append({"id": d["id"], "type": d["type"], "status": state})
    return results

def get_ip(name_or_owner):
    return [{"id": d["id"], "type": d["type"], "ip": d["ip"]} for d in find_devices(name_or_owner)]

def _reconnect_after_start(device_id):
    """Re-attaches a restarted host/camera to its switch. `docker stop` deletes the
    veth Containerlab created and `docker start` only restores eth0, so the device
    would otherwise come back running but cut off from the lab network.
    Never raises: a failed re-attach must not turn a successful power-on into an error."""
    try:
        import lab_network  # lazy: lab_network imports this module
        return lab_network.reconnect_device(device_id)
    except Exception as e:
        return {"id": device_id, "error": f"{type(e).__name__}: {e}"}


def power_on(name_or_owner):
    results = []
    for d in find_devices(name_or_owner):
        c = _client.containers.get(d["container"])
        was_running = c.status == "running"
        link = None
        if not was_running:
            c.start()
            _invalidate_dashboard_cache()
            link = _reconnect_after_start(d["id"])
        entry = {
            "id": d["id"],
            "already_in_that_state": was_running,
            "previous_status": _friendly_status(c.status),
            "new_status": "online",
        }
        if link is not None:
            entry["link"] = link
        results.append(entry)
    return results

def power_off(name_or_owner):
    results = []
    for d in find_devices(name_or_owner):
        c = _client.containers.get(d["container"])
        was_stopped = c.status != "running"
        if not was_stopped:
            # Lab containers run a plain sleep as PID 1 and ignore SIGTERM, so the
            # default 10 s grace period is just dead waiting; 2 s is plenty.
            c.stop(timeout=2)
            _invalidate_dashboard_cache()
        results.append({
            "id": d["id"],
            "already_in_that_state": was_stopped,
            "previous_status": _friendly_status(c.status),
            "new_status": "offline",
        })
    return results

# Ports commonly worth flagging when left open to any source.
SENSITIVE_PORTS = {22: "SSH", 23: "Telnet", 21: "FTP", 3389: "RDP"}

# INPUT filters traffic addressed to the firewall container itself; FORWARD
# filters traffic *passing through* it to hosts in other branches. Blocking
# only INPUT therefore does not stop e.g. SSH to a host behind the firewall.
FIREWALL_CHAINS = ("INPUT", "FORWARD")

def _parse_iptables_rules(raw_output, chain="INPUT"):
    """Parse `iptables -L <chain> -n --line-numbers` output into structured rules."""
    lines = raw_output.strip().split("\n")
    rules = []
    for line in lines[2:]:  # skip "Chain X (policy ...)" and the header row
        parts = line.split(None, 5)
        if len(parts) < 5:
            continue
        num, target, prot, opt, source = parts[:5]
        rest = parts[5] if len(parts) > 5 else ""
        port = None
        m = re.search(r"dpt:(\d+)", rest)
        if m:
            port = int(m.group(1))
        rules.append({
            "chain": chain,
            "rule_num": int(num),
            "action": target,
            "protocol": prot,
            "source": source,
            "port": port,
        })
    return rules

def _get_firewall_device(fw_id):
    matches = [d for d in find_devices(fw_id) if d["type"] == "firewall"]
    if not matches:
        raise ValueError(f"'{fw_id}' is not a known firewall.")
    return matches[0]

def _run_iptables(container, args):
    exit_code, output = container.exec_run(["iptables"] + args)
    if exit_code != 0:
        raise RuntimeError(f"iptables command failed: {output.decode(errors='replace').strip()}")
    return output.decode(errors="replace")

def list_firewall_rules(fw_id):
    """Rules from both the INPUT and FORWARD chains; each rule carries its chain."""
    d = _get_firewall_device(fw_id)
    c = _client.containers.get(d["container"])
    rules = []
    for chain in FIREWALL_CHAINS:
        raw = _run_iptables(c, ["-L", chain, "-n", "--line-numbers"])
        rules.extend(_parse_iptables_rules(raw, chain))
    return {"id": d["id"], "rules": rules}

def _effective_port_rules(rules):
    """iptables is first-match-wins: for each (chain, port, protocol), only the
    topmost (lowest rule_num) rule is actually in effect."""
    effective = {}
    for r in sorted(rules, key=lambda r: (r.get("chain", "INPUT"), r["rule_num"])):
        if r["port"] is None:
            continue
        key = (r.get("chain", "INPUT"), r["port"], r["protocol"])
        if key not in effective:
            effective[key] = r
    return effective

def get_open_ports(fw_id):
    rules = list_firewall_rules(fw_id)["rules"]
    effective = _effective_port_rules(rules)
    open_ports = [
        {"port": port, "protocol": proto, "chain": chain, "source": r["source"]}
        for (chain, port, proto), r in effective.items()
        if r["action"] == "ACCEPT"
    ]
    return {"id": fw_id, "open_ports": open_ports}

def audit_firewall(fw_id):
    rules = list_firewall_rules(fw_id)["rules"]
    effective = _effective_port_rules(rules)
    findings = []
    for (chain, port, proto), r in effective.items():
        if port in SENSITIVE_PORTS and r["action"] == "ACCEPT" and r["source"] in ("0.0.0.0/0", "::/0"):
            where = "to the firewall itself" if chain == "INPUT" else "through the firewall to other hosts"
            findings.append(
                f"Port {port} ({SENSITIVE_PORTS[port]}) is open to any source {where} ({chain}) — consider restricting it."
            )
    return {"id": fw_id, "findings": findings, "clean": len(findings) == 0}

def _persist_rules(container):
    exit_code, output = container.exec_run(["sh", "-c", "iptables-save > /etc/netmind-fw-rules"])
    if exit_code != 0:
        raise RuntimeError(f"Failed to persist firewall rules: {output.decode(errors='replace').strip()}")

def _set_port_rule(container, chain, protocol, port, action):
    """Make `action` the single rule for (chain, protocol, port): remove any
    existing ACCEPT/DROP rules for it, then insert the new one at the top.
    Idempotent — calling it twice leaves exactly one rule."""
    for old in ("ACCEPT", "DROP"):
        while container.exec_run(["iptables", "-C", chain, "-p", protocol, "--dport", str(port), "-j", old])[0] == 0:
            _run_iptables(container, ["-D", chain, "-p", protocol, "--dport", str(port), "-j", old])
    _run_iptables(container, ["-I", chain, "1", "-p", protocol, "--dport", str(port), "-j", action])

def _change_port(fw_id, port, protocol, action, label):
    d = _get_firewall_device(fw_id)
    c = _client.containers.get(d["container"])
    for chain in FIREWALL_CHAINS:
        _set_port_rule(c, chain, protocol, port, action)
    _persist_rules(c)
    _audit_cache.pop(d["id"], None)
    return {"id": d["id"], "port": port, "protocol": protocol,
            "chains": list(FIREWALL_CHAINS), "new_action": label}

def block_port(fw_id, port, protocol="tcp"):
    return _change_port(fw_id, port, protocol, "DROP", "blocked")

def allow_port(fw_id, port, protocol="tcp"):
    return _change_port(fw_id, port, protocol, "ACCEPT", "allowed")

CAMERA_PORT = 8080

def _get_camera_device(cam_id):
    matches = [d for d in find_devices(cam_id) if d["type"] == "camera"]
    if not matches:
        raise ValueError(f"'{cam_id}' is not a known camera.")
    return matches[0]

def get_camera_stream_status(cam_id):
    """Actually attempts a real HTTP request to the camera's IP - this tests
    whether the camera service is genuinely reachable and responding, not
    just whether the container process is alive."""
    d = _get_camera_device(cam_id)
    url = f"http://{d['ip']}:{CAMERA_PORT}/snapshot"
    try:
        resp = requests.get(url, timeout=2)
        streaming = resp.status_code == 200
    except requests.exceptions.RequestException:
        streaming = False
    return {"id": d["id"], "streaming": streaming, "url": url}

def start_camera_stream(cam_id):
    d = _get_camera_device(cam_id)
    c = _client.containers.get(d["container"])
    exit_code, output = c.exec_run(["/start_camera.sh"])
    if exit_code != 0:
        raise RuntimeError(f"Failed to start camera stream: {output.decode(errors='replace').strip()}")
    return {"id": d["id"], "streaming": True}

def stop_camera_stream(cam_id):
    d = _get_camera_device(cam_id)
    c = _client.containers.get(d["container"])
    exit_code, output = c.exec_run(["/stop_camera.sh"])
    if exit_code != 0:
        raise RuntimeError(f"Failed to stop camera stream: {output.decode(errors='replace').strip()}")
    return {"id": d["id"], "streaming": False}

def check_camera_credentials(cam_id):
    d = _get_camera_device(cam_id)
    c = _client.containers.get(d["container"])
    exit_code, output = c.exec_run(["cat", "/etc/netmind-camera-creds"])
    if exit_code != 0:
        raise RuntimeError(f"Failed to read camera credentials: {output.decode(errors='replace').strip()}")
    password = output.decode(errors="replace").strip()
    is_default = password == "admin"
    findings = []
    if is_default:
        findings.append("Camera is using the default password (admin) — consider changing it.")
    return {"id": d["id"], "using_default_credentials": is_default, "findings": findings, "clean": not is_default}

def change_camera_credentials(cam_id, new_password):
    d = _get_camera_device(cam_id)
    c = _client.containers.get(d["container"])
    safe_password = shlex.quote(new_password)
    exit_code, output = c.exec_run(["sh", "-c", f"printf '%s' {safe_password} > /etc/netmind-camera-creds"])
    if exit_code != 0:
        raise RuntimeError(f"Failed to update camera credentials: {output.decode(errors='replace').strip()}")
    return {"id": d["id"], "credentials_changed": True}

def list_devices():
    devices = _load_registry()
    results = []
    for d in devices:
        try:
            c = _client.containers.get(d["container"])
            state = _friendly_status(c.status)
        except docker.errors.NotFound:
            state = "not found"
        results.append({"id": d["id"], "owner": d["owner"], "type": d["type"], "status": state})
    return results

def _container_cpu_percent(container):
    """Best-effort single-sample CPU % via the Docker stats API. Returns None on
    failure (e.g. container just started and has no precpu sample yet)."""
    try:
        stats = container.stats(stream=False)
        cpu_delta = (stats["cpu_stats"]["cpu_usage"]["total_usage"]
                     - stats["precpu_stats"]["cpu_usage"]["total_usage"])
        system_delta = (stats["cpu_stats"]["system_cpu_usage"]
                         - stats["precpu_stats"]["system_cpu_usage"])
        online_cpus = stats["cpu_stats"].get("online_cpus") or len(
            stats["cpu_stats"]["cpu_usage"].get("percpu_usage", [1])
        )
        if system_delta > 0 and cpu_delta >= 0:
            return (cpu_delta / system_delta) * online_cpus * 100.0
    except Exception:
        pass
    return None


# The dashboard polls every few seconds. Asking Docker for CPU stats one container
# at a time made every poll take 15+ seconds and starved every other request
# (power, confirm, chat tools). So: fetch the container list once, read CPU stats
# in parallel, and share one short-lived cached result between callers.
DASHBOARD_TTL = 3.0
_dash_cache = {"ts": 0.0, "data": None, "gen": 0}
_dash_lock = threading.Lock()


def _invalidate_dashboard_cache():
    # Bump the generation too: a computation that started before this call must not
    # store its (now stale) result as fresh when it finishes.
    _dash_cache["gen"] += 1
    _dash_cache["ts"] = 0.0


def _compute_dashboard():
    devices = _load_registry()
    try:
        containers = {c.name: c for c in _client.containers.list(all=True)}
    except docker.errors.DockerException:
        containers = {}
    running = [d for d in devices
               if d["container"] in containers and containers[d["container"]].status == "running"]
    with ThreadPoolExecutor(max_workers=8) as pool:
        cpu_values = list(pool.map(lambda d: _container_cpu_percent(containers[d["container"]]), running))
    cpu_by_id = {d["id"]: v for d, v in zip(running, cpu_values)}

    results = []
    for d in devices:
        c = containers.get(d["container"])
        if c is not None and c.status == "running":
            cpu = cpu_by_id.get(d["id"])
            cpu = round(cpu) if cpu is not None else 0
            status = "warning" if cpu >= 80 else "online"
        else:
            cpu = 0
            status = "offline"
        results.append({
            "id": d["id"],
            "name": d["id"],
            "type": d["type"],
            "ip": d.get("ip", ""),
            "status": status,
            "cpu": cpu,
            "traffic": 0,
        })
    return results


def list_devices_dashboard():
    """Device list shaped for the web Dashboard (id, name, type, ip, status, cpu).
    Cached for DASHBOARD_TTL seconds; concurrent callers share one computation."""
    with _dash_lock:
        if _dash_cache["data"] is None or time.monotonic() - _dash_cache["ts"] >= DASHBOARD_TTL:
            gen = _dash_cache["gen"]
            data = _compute_dashboard()
            _dash_cache["data"] = data
            # If a power change invalidated the cache while we were computing, this
            # snapshot may predate it: serve it once, but do not keep it as fresh.
            _dash_cache["ts"] = time.monotonic() if gen == _dash_cache["gen"] else 0.0
            return [dict(d) for d in data]
        return [dict(d) for d in _dash_cache["data"]]


_audit_cache = {}


def _cached_audit(fw_id, ttl=10.0):
    """audit_firewall() runs iptables in the container; don't repeat it on every poll."""
    hit = _audit_cache.get(fw_id)
    if hit and time.monotonic() - hit[0] < ttl:
        return hit[1]
    result = audit_firewall(fw_id)
    _audit_cache[fw_id] = (time.monotonic(), result)
    return result


def get_alerts():
    """Derives live alerts from device status plus real firewall-audit findings."""
    alerts = []
    now = int(time.time() * 1000)

    for d in list_devices_dashboard():
        if d["status"] == "offline":
            alerts.append({"id": f"offline-{d['id']}", "title": "Device Offline",
                            "detail": d["id"], "ts": now, "level": "offline"})
        elif d["status"] == "warning":
            alerts.append({"id": f"cpu-{d['id']}", "title": "High CPU Usage",
                            "detail": f"{d['id']} ({d['cpu']}%)", "ts": now, "level": "warning"})

    for d in _load_registry():
        if d["type"] != "firewall":
            continue
        try:
            audit = _cached_audit(d["id"])
        except Exception:
            continue
        for finding in audit["findings"]:
            alerts.append({
                "id": f"fw-{d['id']}-{abs(hash(finding)) % 10000}",
                "title": "Firewall Finding",
                "detail": finding,
                "ts": now,
                "level": "warning",
            })

    return alerts


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: device_control.py <status|ip|on|off> <name_or_owner>")
        sys.exit(1)
    action, target = sys.argv[1], sys.argv[2]
    if action == "status":
        print(get_status(target))
    elif action == "ip":
        print(get_ip(target))
    elif action == "on":
        print(power_on(target))
    elif action == "off":
        print(power_off(target))
