import time
from types import SimpleNamespace as NS

import device_control as dc


class FakeContainer:
    def __init__(self, name, status="running", stats_delay=0.3):
        self.name, self.status, self._delay = name, status, stats_delay
        self.stopped_with = None

    def stats(self, stream=False):
        time.sleep(self._delay)  # a real Docker stats call blocks about a second
        return {"cpu_stats": {"cpu_usage": {"total_usage": 200}, "system_cpu_usage": 2000, "online_cpus": 1},
                "precpu_stats": {"cpu_usage": {"total_usage": 100}, "system_cpu_usage": 1000}}

    def stop(self, timeout=10):
        self.stopped_with = timeout
        self.status = "exited"

    def start(self):
        self.status = "running"


def setup(monkeypatch, n=12):
    registry = [{"id": f"host-{i}", "type": "host", "owner": f"o{i}", "container": f"c{i}", "ip": f"1.1.1.{i}"}
                for i in range(n)]
    boxes = {f"c{i}": FakeContainer(f"c{i}") for i in range(n)}
    calls = {"list": 0}

    def list_(all=False):
        calls["list"] += 1
        return list(boxes.values())

    monkeypatch.setattr(dc, "_load_registry", lambda: registry)
    monkeypatch.setattr(dc, "_client", NS(containers=NS(list=list_, get=lambda name: boxes[name])))
    dc._invalidate_dashboard_cache()
    return boxes, calls


def test_dashboard_reads_stats_in_parallel(monkeypatch):
    setup(monkeypatch, n=12)  # sequential would take 12 x 0.3 = 3.6 s
    t = time.monotonic()
    devices = dc.list_devices_dashboard()
    assert time.monotonic() - t < 1.5
    assert len(devices) == 12 and all(d["status"] == "online" for d in devices)


def test_dashboard_is_cached_and_power_off_invalidates(monkeypatch):
    boxes, calls = setup(monkeypatch, n=3)
    dc.list_devices_dashboard()
    dc.list_devices_dashboard()
    assert calls["list"] == 1                      # second call served from cache
    dc.power_off("host-1")
    assert boxes["c1"].stopped_with == 2           # no 10 s wait for SIGTERM
    states = {d["id"]: d["status"] for d in dc.list_devices_dashboard()}
    assert states["host-1"] == "offline" and states["host-0"] == "online"


def test_alerts_reuse_cached_devices(monkeypatch):
    boxes, calls = setup(monkeypatch, n=3)
    boxes["c2"].status = "exited"
    dc.list_devices_dashboard()
    alerts = dc.get_alerts()
    assert calls["list"] == 1 and any(a["detail"] == "host-2" for a in alerts)


def test_invalidation_during_a_running_computation_is_not_lost(monkeypatch):
    """A poll that started before power_off must not leave its stale snapshot cached as fresh."""
    import threading
    boxes, calls = setup(monkeypatch, n=2)
    started, release = threading.Event(), threading.Event()
    real = dc._compute_dashboard

    def slow():
        snapshot = real()               # reads state before the power-off below
        started.set()
        release.wait(5)
        return snapshot

    monkeypatch.setattr(dc, "_compute_dashboard", slow)
    result = {}
    t = threading.Thread(target=lambda: result.update(first=dc.list_devices_dashboard()))
    t.start()
    assert started.wait(5)
    boxes["c1"].stop(timeout=2)         # device goes down while the poll is in flight
    dc._invalidate_dashboard_cache()
    release.set()
    t.join()
    assert {d["id"]: d["status"] for d in result["first"]}["host-1"] == "online"  # the stale snapshot itself
    monkeypatch.setattr(dc, "_compute_dashboard", real)
    states = {d["id"]: d["status"] for d in dc.list_devices_dashboard()}
    assert states["host-1"] == "offline"  # the next call recomputes instead of reusing it
