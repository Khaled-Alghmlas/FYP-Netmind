"""Per-device health for the background collector (issue #19).

Pure Python, no Docker: a *sample* is a plain dict describing what the collector saw for one
device, and this module turns a stream of samples into UP / DEGRADED / DOWN states and the
transitions between them. The collector (collector.py) gathers the samples; the web server turns
the transitions into alerts.

A sample has these keys (all optional except `container`):
    container  Docker status of the device's container: "running", "exited", "missing", ...
    stream     cameras only: True if the camera answered GET /snapshot, False if it did not
    reachable  True/False if the device answered a ping on its management address
    cpu, mem   CPU and memory use in percent, when metrics are being collected

Debounce: a device only changes state after `confirm` samples in a row agree on the new state,
so one slow answer never raises an alert. Deduplication follows from the same rule: an alert is
only produced on a change of state, never for a device that stays in the state it is in.
"""
import time

UP, DEGRADED, DOWN = "up", "degraded", "down"
PROTECTED_TYPES = ("router", "firewall")
CPU_LIMIT = 90.0   # percent; sustained use above this marks a device degraded
MEM_LIMIT = 90.0


def classify(device_type, sample):
    """-> (state, reason) for one sample of one device."""
    container = sample.get("container")
    if container != "running":
        what = "container not found" if container == "missing" else "container is not running"
        return DOWN, what
    if device_type == "camera" and sample.get("stream") is False:
        return DEGRADED, "camera stream is not answering"
    if sample.get("reachable") is False:
        return DEGRADED, "not answering ping"
    cpu, mem = sample.get("cpu"), sample.get("mem")
    if cpu is not None and cpu >= CPU_LIMIT:
        return DEGRADED, f"CPU at {cpu:.0f}%"
    if mem is not None and mem >= MEM_LIMIT:
        return DEGRADED, f"memory at {mem:.0f}%"
    return UP, "healthy"


def severity(device_type, state):
    """Severity of entering `state`, by the device's role: losing a router or firewall cuts off a
    whole branch, so it is critical; a degraded device still works, so it is a warning."""
    if state == DOWN:
        return "critical" if device_type in PROTECTED_TYPES else "warning"
    if state == DEGRADED:
        return "warning"
    return "info"


class HealthTracker:
    """Keeps the confirmed state of every device and reports confirmed changes.

    observe(devices_and_samples) -> list of transitions, each a dict:
        device, type, from (None the first time a device is seen), to, reason,
        since_ms (when the previous state began, None if unknown), at_ms
    The first confirmed state of a device is reported too, with from=None: a fault that exists
    when the server starts is still alerted, and an alert left open by an earlier run can be
    closed if the device is found healthy. The caller decides what None -> UP means (usually
    nothing)."""

    def __init__(self, confirm=2, clock=time.time):
        self.confirm = max(1, int(confirm))
        self._clock = clock
        self._devices = {}

    def _now_ms(self):
        return int(self._clock() * 1000)

    def observe(self, devices_and_samples):
        now = self._now_ms()
        transitions, seen = [], set()
        for device, sample in devices_and_samples:
            did, dtype = device["id"], device.get("type")
            seen.add(did)
            state, reason = classify(dtype, sample)
            entry = self._devices.setdefault(did, {"state": None, "since": None, "reason": None,
                                                   "type": dtype, "candidate": None, "count": 0,
                                                   "sample": {}})
            entry["type"], entry["sample"] = dtype, dict(sample)
            if state == entry["state"]:
                entry["candidate"], entry["count"] = None, 0
                entry["reason"] = reason   # e.g. CPU 93% -> 95%: same state, fresher reason
                continue
            if entry["candidate"] == state:
                entry["count"] += 1
            else:
                entry["candidate"], entry["count"] = state, 1
            if entry["count"] < self.confirm:
                continue
            previous, previous_since = entry["state"], entry["since"]
            entry.update(state=state, since=now, reason=reason, candidate=None, count=0)
            transitions.append({"device": did, "type": dtype, "from": previous, "to": state,
                                "reason": reason, "since_ms": previous_since, "at_ms": now})
        for did in list(self._devices):
            if did not in seen:   # removed from the registry: forget it, do not report it
                del self._devices[did]
        return transitions

    def state(self, device_id):
        entry = self._devices.get(device_id)
        return entry["state"] if entry else None

    def snapshot(self):
        """Current confirmed state of every device, for the API."""
        return [{"device": did, "type": e["type"], "state": e["state"], "reason": e["reason"],
                 "since": e["since"], "pending": e["candidate"], "sample": e["sample"]}
                for did, e in sorted(self._devices.items())]
