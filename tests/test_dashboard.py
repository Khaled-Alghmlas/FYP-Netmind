from types import SimpleNamespace as NS

import device_control as dc


class FakeContainer:
    def __init__(self, name, status="running"):
        self.name, self.status = name, status
        self.stopped_with = None

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


def test_dashboard_has_no_cpu_data_and_makes_one_docker_call(monkeypatch):
    boxes, calls = setup(monkeypatch, n=12)
    devices = dc.list_devices_dashboard()
    assert calls["list"] == 1
    assert len(devices) == 12 and all(d["status"] == "online" for d in devices)
    assert all("cpu" not in d and "traffic" not in d for d in devices)


def test_dashboard_is_cached_and_power_off_invalidates(monkeypatch):
    boxes, calls = setup(monkeypatch, n=3)
    dc.list_devices_dashboard()
    dc.list_devices_dashboard()
    assert calls["list"] == 1                      # second call served from cache
    dc.power_off("host-1")
    assert boxes["c1"].stopped_with == 2           # no 10 s wait for SIGTERM
    states = {d["id"]: d["status"] for d in dc.list_devices_dashboard()}
    assert states["host-1"] == "offline" and states["host-0"] == "online"


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
