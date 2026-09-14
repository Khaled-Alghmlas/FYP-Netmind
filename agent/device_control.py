#!/usr/bin/env python3
"""Core device control functions for the NetMind agent.
Resolves device/owner names via registry.json, then checks or changes
container state via the Docker SDK — this IS the on/off state we care about."""
import json
import re
import shlex
import docker
import requests
from pathlib import Path

REGISTRY_PATH = Path(__file__).resolve().parent.parent / "topology" / "registry.json"

_client = docker.from_env()

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

def get_status(name_or_owner):
    results = []
    for d in find_devices(name_or_owner):
        try:
            c = _client.containers.get(d["container"])
            state = c.status  # 'running', 'exited', etc.
        except docker.errors.NotFound:
            state = "not found"
        results.append({"id": d["id"], "type": d["type"], "status": state})
    return results

def get_ip(name_or_owner):
    return [{"id": d["id"], "type": d["type"], "ip": d["ip"]} for d in find_devices(name_or_owner)]

def power_on(name_or_owner):
    results = []
    for d in find_devices(name_or_owner):
        c = _client.containers.get(d["container"])
        was_running = c.status == "running"
        if not was_running:
            c.start()
        results.append({
            "id": d["id"],
            "already_in_that_state": was_running,
            "previous_status": c.status,
            "new_status": "running",
        })
    return results

def power_off(name_or_owner):
    results = []
    for d in find_devices(name_or_owner):
        c = _client.containers.get(d["container"])
        was_stopped = c.status != "running"
        if not was_stopped:
            c.stop()
        results.append({
            "id": d["id"],
            "already_in_that_state": was_stopped,
            "previous_status": c.status,
            "new_status": "exited",
        })
    return results

# Ports commonly worth flagging when left open to any source.
SENSITIVE_PORTS = {22: "SSH", 23: "Telnet", 21: "FTP", 3389: "RDP"}

def _parse_iptables_rules(raw_output):
    """Parse `iptables -L INPUT -n --line-numbers` output into structured rules."""
    lines = raw_output.strip().split("\n")
    rules = []
    for line in lines[2:]:  # skip "Chain INPUT..." and the header row
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
    d = _get_firewall_device(fw_id)
    c = _client.containers.get(d["container"])
    raw = _run_iptables(c, ["-L", "INPUT", "-n", "--line-numbers"])
    return {"id": d["id"], "rules": _parse_iptables_rules(raw)}

def _effective_port_rules(rules):
    """iptables is first-match-wins: for each (port, protocol), only the
    topmost (lowest rule_num) rule is actually in effect."""
    effective = {}
    for r in rules:
        if r["port"] is None:
            continue
        key = (r["port"], r["protocol"])
        if key not in effective:
            effective[key] = r
    return effective

def get_open_ports(fw_id):
    rules = list_firewall_rules(fw_id)["rules"]
    effective = _effective_port_rules(rules)
    open_ports = [
        {"port": port, "protocol": proto, "source": r["source"]}
        for (port, proto), r in effective.items()
        if r["action"] == "ACCEPT"
    ]
    return {"id": fw_id, "open_ports": open_ports}

def audit_firewall(fw_id):
    rules = list_firewall_rules(fw_id)["rules"]
    effective = _effective_port_rules(rules)
    findings = []
    for (port, proto), r in effective.items():
        if port in SENSITIVE_PORTS and r["action"] == "ACCEPT" and r["source"] in ("0.0.0.0/0", "::/0"):
            findings.append(
                f"Port {port} ({SENSITIVE_PORTS[port]}) is open to any source — consider restricting it."
            )
    return {"id": fw_id, "findings": findings, "clean": len(findings) == 0}

def _persist_rules(container):
    exit_code, output = container.exec_run(["sh", "-c", "iptables-save > /etc/netmind-fw-rules"])
    if exit_code != 0:
        raise RuntimeError(f"Failed to persist firewall rules: {output.decode(errors='replace').strip()}")

def block_port(fw_id, port, protocol="tcp"):
    d = _get_firewall_device(fw_id)
    c = _client.containers.get(d["container"])
    _run_iptables(c, ["-I", "INPUT", "1", "-p", protocol, "--dport", str(port), "-j", "DROP"])
    _persist_rules(c)
    return {"id": d["id"], "port": port, "protocol": protocol, "new_action": "blocked"}

def allow_port(fw_id, port, protocol="tcp"):
    d = _get_firewall_device(fw_id)
    c = _client.containers.get(d["container"])
    _run_iptables(c, ["-I", "INPUT", "1", "-p", protocol, "--dport", str(port), "-j", "ACCEPT"])
    _persist_rules(c)
    return {"id": d["id"], "port": port, "protocol": protocol, "new_action": "allowed"}

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

def list_devices():
    devices = _load_registry()
    results = []
    for d in devices:
        try:
            c = _client.containers.get(d["container"])
            state = c.status
        except docker.errors.NotFound:
            state = "not found"
        results.append({"id": d["id"], "owner": d["owner"], "type": d["type"], "status": state})
    return results
