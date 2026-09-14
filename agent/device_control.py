#!/usr/bin/env python3
"""Core device control functions for the NetMind agent.
Resolves device/owner names via registry.json, then checks or changes
container state via the Docker SDK — this IS the on/off state we care about."""
import json
import os
import docker
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

def get_memory(name_or_owner):
    results = []
    for d in find_devices(name_or_owner):
        c = _client.containers.get(d["container"])
        limit_bytes = c.attrs["HostConfig"]["Memory"]
        results.append({
            "id": d["id"],
            "memory_limit_mb": (limit_bytes // (1024 * 1024)) if limit_bytes > 0 else None,
            "unlimited": limit_bytes == 0,
        })
    return results

def set_memory(name_or_owner, mb):
    results = []
    for d in find_devices(name_or_owner):
        c = _client.containers.get(d["container"])
        previous_bytes = c.attrs["HostConfig"]["Memory"]
        c.update(mem_limit=f"{mb}m")
        c.reload()
        new_bytes = c.attrs["HostConfig"]["Memory"]
        results.append({
            "id": d["id"],
            "previous_memory_mb": (previous_bytes // (1024 * 1024)) if previous_bytes > 0 else None,
            "new_memory_mb": new_bytes // (1024 * 1024),
        })
    return results

def _host_core_count():
    return os.cpu_count()

def _parse_cpuset(cpuset_str):
    """Parse a Docker CpusetCpus string like '0-3' or '0,1,2' into a core count."""
    if not cpuset_str:
        return None
    total = 0
    for part in cpuset_str.split(","):
        if "-" in part:
            start, end = part.split("-")
            total += int(end) - int(start) + 1
        else:
            total += 1
    return total

def get_cpu_cores(name_or_owner):
    host_cores = _host_core_count()
    results = []
    for d in find_devices(name_or_owner):
        c = _client.containers.get(d["container"])
        cpuset = c.attrs["HostConfig"].get("CpusetCpus", "")
        pinned = _parse_cpuset(cpuset)
        results.append({
            "id": d["id"],
            "pinned_cores": pinned,  # None means unrestricted (can use all host cores)
            "cpuset": cpuset or None,
            "host_total_cores": host_cores,
        })
    return results

def set_cpu_cores(name_or_owner, cores):
    host_cores = _host_core_count()
    if cores < 1 or cores > host_cores:
        raise ValueError(f"Requested {cores} cores, but the host only has {host_cores} cores available.")
    cpuset = f"0-{cores - 1}" if cores > 1 else "0"
    results = []
    for d in find_devices(name_or_owner):
        c = _client.containers.get(d["container"])
        previous_cpuset = c.attrs["HostConfig"].get("CpusetCpus", "")
        c.update(cpuset_cpus=cpuset)
        c.reload()
        results.append({
            "id": d["id"],
            "previous_pinned_cores": _parse_cpuset(previous_cpuset),
            "new_pinned_cores": cores,
            "host_total_cores": host_cores,
        })
    return results

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
