#!/usr/bin/env python3
"""Core device control functions for the NetMind agent.
Resolves device/owner names via registry.json, then checks or changes
container state via the Docker SDK — this IS the on/off state we care about."""
import json
import docker
from pathlib import Path

REGISTRY_PATH = Path(__file__).resolve().parent.parent / "topology" / "registry.json"

_client = docker.from_env()

def _load_registry():
    with open(REGISTRY_PATH) as f:
        return json.load(f)["devices"]

def find_devices(name_or_owner):
    """Match by exact device id first (e.g. 'host-ahmed'), else by owner name (e.g. 'ahmed' -> all their devices)."""
    devices = _load_registry()
    exact = [d for d in devices if d["id"] == name_or_owner]
    if exact:
        return exact
    return [d for d in devices if d["owner"] == name_or_owner]

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
        c.start()
        results.append(d["id"])
    return results

def power_off(name_or_owner):
    results = []
    for d in find_devices(name_or_owner):
        c = _client.containers.get(d["container"])
        c.stop()
        results.append(d["id"])
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
