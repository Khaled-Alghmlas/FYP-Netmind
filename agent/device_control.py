#!/usr/bin/env python3
"""Device control functions for the NetMind agent.

The logic lives in services.py (DeviceService, FirewallService, CameraService) and returns
typed models from models.py. This module wires those services to the real Docker daemon and the
registry file, and keeps the plain function API (get_status, power_off, block_port, ...) that the
agent tools, the dashboard and the tests call: each function dumps the service's model to a dict.
Docker is reached lazily, so this module can be imported on a machine with no Docker.
"""
import json
import threading
import time
from pathlib import Path

import docker
import requests

from iptables import FIREWALL_CHAINS, SENSITIVE_PORTS, effective_port_rules, parse_rules  # noqa: F401
from models import FirewallRule
from services import CAMERA_PORT, CameraService, DeviceService, FirewallService, friendly_status  # noqa: F401

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


# --- wiring ------------------------------------------------------------------------------
# The services call these small functions, which look the real objects up at call time. That is
# what lets tests swap `_client`, `_load_registry`, `find_devices` ... with monkeypatch.
def _get_client():
    return _client


def _registry():
    return _load_registry()


def _resolve(name_or_owner):
    return find_devices(name_or_owner)


def _on_power_change():
    _invalidate_dashboard_cache()


def _after_start(device_id):
    return _reconnect_after_start(device_id)


def _forget_audit(fw_id):
    _audit_cache.pop(fw_id, None)


def _forget_camera(cam_id):
    _camera_cache.pop(cam_id, None)


def _snapshot_ok(url):
    try:
        return requests.get(url, timeout=2).status_code == 200
    except requests.exceptions.RequestException:
        return False


_devices = DeviceService(_registry, _get_client, resolver=_resolve, reconnect=_after_start,
                         on_change=_on_power_change, not_found=(docker.errors.NotFound,),
                         runtime_errors=(docker.errors.DockerException,))
_firewalls = FirewallService(_resolve, _get_client, on_change=_forget_audit)
_cameras = CameraService(_resolve, _get_client, _snapshot_ok, on_change=_forget_camera)


def _dump(models, **kwargs):
    return [m.model_dump(**kwargs) for m in models]


# --- devices -----------------------------------------------------------------------------
def find_devices(name_or_owner):
    """Match by exact device id first (e.g. 'host-ahmed'), else by owner name, else a clear typo."""
    return _dump(_devices.find(name_or_owner))


def list_devices_on_segment(segment_id):
    return _devices.list_on_segment(segment_id).model_dump()


def _friendly_status(docker_status):
    return friendly_status(docker_status)


def get_status(name_or_owner):
    return _dump(_devices.status(name_or_owner))


def get_ip(name_or_owner):
    return _dump(_devices.ip(name_or_owner))


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
    return _dump(_devices.power_on(name_or_owner), exclude_none=True)


def power_off(name_or_owner):
    return _dump(_devices.power_off(name_or_owner), exclude_none=True)


def list_devices():
    return _dump(_devices.list_all())


# --- firewalls ---------------------------------------------------------------------------
def _parse_iptables_rules(raw_output, chain="INPUT"):
    """Parse `iptables -L <chain> -n --line-numbers` output into rule dicts."""
    return _dump(parse_rules(raw_output, chain))


def _effective_port_rules(rules):
    """First-match-wins view of rule dicts: {(chain, port, protocol): rule dict}."""
    models = [FirewallRule(**{**r, "chain": r.get("chain", "INPUT")}) for r in rules]
    return {key: r.model_dump() for key, r in effective_port_rules(models).items()}


def list_firewall_rules(fw_id):
    return _firewalls.list_rules(fw_id).model_dump()


def get_open_ports(fw_id):
    return _firewalls.open_ports(fw_id).model_dump()


def audit_firewall(fw_id):
    return _firewalls.audit(fw_id).model_dump()


def block_port(fw_id, port, protocol="tcp"):
    return _firewalls.block_port(fw_id, port, protocol).model_dump()


def allow_port(fw_id, port, protocol="tcp"):
    return _firewalls.allow_port(fw_id, port, protocol).model_dump()


# --- cameras -----------------------------------------------------------------------------
def get_camera_stream_status(cam_id):
    return _cameras.stream_status(cam_id).model_dump()


def start_camera_stream(cam_id):
    return _cameras.start_stream(cam_id).model_dump()


def stop_camera_stream(cam_id):
    return _cameras.stop_stream(cam_id).model_dump()


def check_camera_credentials(cam_id):
    return _cameras.check_credentials(cam_id).model_dump()


def change_camera_credentials(cam_id, new_password):
    return _cameras.change_credentials(cam_id, new_password).model_dump()


# --- dashboard (polling caches on top of the services) -----------------------------------
# The dashboard polls every few seconds, so it fetches the container list once and
# shares one short-lived cached result between callers.
DASHBOARD_TTL = 3.0
_dash_cache = {"ts": 0.0, "data": None, "gen": 0}
_dash_lock = threading.Lock()


def _invalidate_dashboard_cache():
    # Bump the generation too: a computation that started before this call must not
    # store its (now stale) result as fresh when it finishes.
    _dash_cache["gen"] += 1
    _dash_cache["ts"] = 0.0


def _compute_dashboard():
    return _dump(_devices.dashboard_rows())


def list_devices_dashboard():
    """Device list shaped for the web Dashboard (id, name, type, ip, status).
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


def get_security_findings():
    """Current audit findings as (device_id, text, kind) triples: firewall misconfigurations
    and cameras still on their default password. Devices that cannot be checked are skipped."""
    found = []
    for d in _load_registry():
        try:
            if d["type"] == "firewall":
                found += [(d["id"], f, "firewall_finding") for f in _cached_audit(d["id"])["findings"]]
            elif d["type"] == "camera":
                found += [(d["id"], f, "camera_finding") for f in _cached_camera_check(d["id"])["findings"]]
        except Exception:
            continue
    return found


_camera_cache = {}


def _cached_camera_check(cam_id, ttl=10.0):
    hit = _camera_cache.get(cam_id)
    if hit and time.monotonic() - hit[0] < ttl:
        return hit[1]
    result = check_camera_credentials(cam_id)
    _camera_cache[cam_id] = (time.monotonic(), result)
    return result


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
