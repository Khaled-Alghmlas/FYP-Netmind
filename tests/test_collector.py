"""Issue #19: background collector, UP/DEGRADED/DOWN state machine, alerts, acknowledgement,
SQLite storage, /api/health and server-sent events. Docker and the network are faked."""
import asyncio
import json
import sqlite3
import time
from types import SimpleNamespace as NS

import pytest
from fastapi.testclient import TestClient

import device_control as dc
import health
import web_server as ws
from collector import Collector
from settings import Settings
from storage import SCHEMA_VERSION, Database

CAM = {"id": "cam-khalid", "type": "camera", "container": "c-cam", "ip": "10.0.0.5"}
FW = {"id": "fw-branch1", "type": "firewall", "container": "c-fw", "ip": "10.0.0.2"}
HOST = {"id": "host-ahmed", "type": "host", "container": "c-host", "ip": "10.0.0.7"}

UP_CAM = {"container": "running", "stream": True, "reachable": True}
STREAM_DOWN = {"container": "running", "stream": False, "reachable": True}
STOPPED = {"container": "exited"}


# --- state machine -------------------------------------------------------------------------
@pytest.mark.parametrize("dtype, sample, state, reason", [
    ("camera", UP_CAM, health.UP, "healthy"),
    ("camera", STOPPED, health.DOWN, "container is not running"),
    ("host", {"container": "missing"}, health.DOWN, "container not found"),
    ("camera", STREAM_DOWN, health.DEGRADED, "camera stream is not answering"),
    ("host", {"container": "running", "reachable": False}, health.DEGRADED, "not answering ping"),
    ("host", {"container": "running", "cpu": 97.0}, health.DEGRADED, "CPU at 97%"),
    ("host", {"container": "running", "cpu": 10.0, "mem": 95.0}, health.DEGRADED, "memory at 95%"),
    ("host", {"container": "running", "stream": False}, health.UP, "healthy"),   # only cameras stream
])
def test_classify(dtype, sample, state, reason):
    assert health.classify(dtype, sample) == (state, reason)


def test_severity_depends_on_the_device_role():
    assert health.severity("firewall", health.DOWN) == "critical"
    assert health.severity("router", health.DOWN) == "critical"
    assert health.severity("camera", health.DOWN) == "warning"
    assert health.severity("firewall", health.DEGRADED) == "warning"
    assert health.severity("host", health.UP) == "info"


def test_a_state_changes_only_after_enough_samples_agree():
    t = health.HealthTracker(confirm=2)
    assert [x["to"] for x in t.observe([(CAM, UP_CAM)]) + t.observe([(CAM, UP_CAM)])] == [health.UP]
    assert t.observe([(CAM, STOPPED)]) == []                        # one bad sample: no alert yet
    assert t.observe([(CAM, UP_CAM)]) == []                         # it was a blip
    assert t.observe([(CAM, STOPPED)]) == []
    [change] = t.observe([(CAM, STOPPED)])                          # two in a row: confirmed
    assert (change["from"], change["to"], change["reason"]) == (health.UP, health.DOWN, "container is not running")
    assert t.observe([(CAM, STOPPED)]) == [] and t.observe([(CAM, STOPPED)]) == []   # no duplicates
    assert t.state("cam-khalid") == health.DOWN


def test_first_observation_is_reported_and_removed_devices_are_forgotten():
    t = health.HealthTracker(confirm=1)
    [first] = t.observe([(FW, STOPPED)])
    assert first["from"] is None and first["to"] == health.DOWN
    t.observe([])
    assert t.state("fw-branch1") is None and t.snapshot() == []


# --- collector -----------------------------------------------------------------------------
def test_a_failed_round_keeps_the_last_states():
    seen = []

    def broken():
        raise RuntimeError("docker daemon not reachable")

    c = Collector(broken, seen.append, confirm=1)
    assert c.run_once() == [] and seen == []
    assert "docker daemon not reachable" in c.status()["last_error"] and c.rounds == 0


def test_metrics_are_merged_into_the_samples():
    c = Collector(lambda: [(HOST, {"container": "running"})], lambda t: None, confirm=1,
                  metrics=lambda: {"host-ahmed": {"cpu": 99.0}})
    c.refresh_metrics()
    [change] = c.run_once()
    assert change["to"] == health.DEGRADED and change["reason"] == "CPU at 99%"


def test_a_broken_metrics_source_is_ignored():
    def boom():
        raise RuntimeError("stats failed")

    c = Collector(lambda: [(HOST, {"container": "running"})], lambda t: None, confirm=1, metrics=boom)
    c.refresh_metrics()
    assert c.run_once()[0]["to"] == health.UP


def test_a_handler_error_is_recorded_and_the_collector_keeps_going():
    def bad_handler(transitions):
        raise ValueError("bug")

    c = Collector(lambda: [(HOST, {"container": "running"})], bad_handler, confirm=1)
    c.run_once()
    assert "handler" in c.status()["last_error"] and c.rounds == 1


def test_the_collector_runs_in_the_background_until_stopped():
    rounds = []
    c = Collector(lambda: [(HOST, {"container": "running"})], rounds.append, interval=0.01,
                  metrics=lambda: {}, metrics_interval=0.01)
    c.start()
    try:
        deadline = time.time() + 3
        while len(rounds) < 3 and time.time() < deadline:
            time.sleep(0.01)
        assert c.running and len(rounds) >= 3
    finally:
        c.stop()
    assert not c.running


# --- alerts from the collector (the issue's acceptance criterion) --------------------------
@pytest.fixture
def lab(monkeypatch):
    """A fake lab that the test changes between collector rounds."""
    monkeypatch.setattr(ws, "ALERTS_PATH", None)
    monkeypatch.setattr(ws, "TELEGRAM_BOT_TOKEN", None)
    monkeypatch.setattr(dc, "get_security_findings", lambda: [])
    for state in (ws.ALERT_LOG, ws._down_alert, ws._down_since, ws._degraded_alert,
                  ws._finding_open, ws._last_sim_status):
        state.clear()
    samples = {"cam-khalid": dict(UP_CAM), "fw-branch1": {"container": "running"}}
    devices = {"cam-khalid": CAM, "fw-branch1": FW}
    collector = Collector(lambda: [(devices[i], dict(s)) for i, s in samples.items()], ws._on_transitions, confirm=2)

    def rounds(n=2):
        for _ in range(n):
            collector.run_once()

    rounds()
    return NS(samples=samples, rounds=rounds, collector=collector)


def kinds():
    return [a["kind"] for a in ws.ALERT_LOG]


def test_a_healthy_lab_raises_no_alert(lab):
    lab.rounds(3)
    assert ws.ALERT_LOG == []


def test_stopping_a_camera_container_raises_an_offline_alert(lab):
    lab.samples["cam-khalid"] = dict(STOPPED)
    lab.rounds()
    [alert] = ws.ALERT_LOG
    assert alert["kind"] == "device_offline" and alert["device"] == "cam-khalid" and alert["active"]
    assert alert["severity"] == "warning" and "container is not running" in alert["detail"]
    assert alert["acknowledged"] is False


def test_stopping_only_the_camera_stream_raises_a_degraded_alert(lab):
    lab.samples["cam-khalid"] = dict(STREAM_DOWN)
    lab.rounds()
    [alert] = ws.ALERT_LOG
    assert alert["kind"] == "device_degraded" and alert["device"] == "cam-khalid"
    assert alert["reason"] == "camera stream is not answering" and alert["severity"] == "warning"
    lab.samples["cam-khalid"] = dict(UP_CAM)                         # stream restarted
    lab.rounds()
    assert kinds() == ["device_recovered", "device_degraded"]
    assert ws.ALERT_LOG[1]["active"] is False and ws.ALERT_LOG[0]["active"] is False


def test_a_firewall_going_down_is_critical_and_its_recovery_reports_the_downtime(lab):
    lab.samples["fw-branch1"] = dict(STOPPED)
    lab.rounds()
    assert ws.ALERT_LOG[0]["severity"] == "critical"
    ws._down_since["fw-branch1"] -= 65_000
    lab.samples["fw-branch1"] = {"container": "running"}
    lab.rounds()
    online, offline = ws.ALERT_LOG
    assert online["kind"] == "device_online" and online["severity"] == "info" and offline["active"] is False
    assert 65 <= online["down_seconds"] < 75 and "1m 0" in online["detail"]


def test_a_degraded_device_that_goes_down_does_not_report_a_recovery(lab):
    lab.samples["cam-khalid"] = dict(STREAM_DOWN)
    lab.rounds()
    lab.samples["cam-khalid"] = dict(STOPPED)
    lab.rounds()
    assert kinds() == ["device_offline", "device_degraded"] and ws.ALERT_LOG[1]["active"] is False
    lab.samples["cam-khalid"] = dict(STREAM_DOWN)                    # back up, stream still broken
    lab.rounds()
    assert kinds() == ["device_degraded", "device_online", "device_offline", "device_degraded"]


def test_a_problem_that_lasts_is_alerted_once(lab):
    lab.samples["cam-khalid"] = dict(STOPPED)
    lab.rounds(6)
    assert kinds() == ["device_offline"]


def test_an_alert_left_open_by_an_earlier_run_is_closed_when_the_device_is_found_healthy(monkeypatch):
    monkeypatch.setattr(ws, "ALERTS_PATH", None)
    monkeypatch.setattr(ws, "TELEGRAM_BOT_TOKEN", None)
    for state in (ws.ALERT_LOG, ws._down_alert, ws._down_since, ws._degraded_alert):
        state.clear()
    with ws._alert_lock:
        ws._open_offline("cam-khalid", "cam-khalid", "camera")
    ws._on_transitions([{"device": "cam-khalid", "type": "camera", "from": None, "to": health.UP,
                         "reason": "healthy", "since_ms": None, "at_ms": 0}])
    assert kinds() == ["device_online", "device_offline"] and not ws._down_alert


def test_alerts_carry_severity_and_local_time_to_telegram(monkeypatch):
    sent = []
    monkeypatch.setattr(ws, "_send_telegram_async", sent.append)
    alert = {"kind": "device_degraded", "title": "Device Degraded", "detail": "cam-khalid: camera stream is not answering",
             "device": "cam-khalid", "ts": 1_795_700_000_000, "severity": "warning"}
    ws._notify_telegram_alert(alert, device_type="camera")
    [text] = sent
    assert "Severity: Warning" in text and "Device: cam-khalid" in text
    assert text.splitlines()[-1].startswith("Time: 2026-") and "UTC" not in text   # local time with an offset


@pytest.fixture
def telegram(monkeypatch):
    sent, active = [], {"now": 0, "max": 0}
    monkeypatch.setattr(ws, "TELEGRAM_BOT_TOKEN", "t")
    monkeypatch.setattr(ws, "TELEGRAM_CHAT_ID", "c")
    monkeypatch.setattr(ws, "TELEGRAM_GAP_SECONDS", 0)

    def fake_send(text):
        active["now"] += 1
        active["max"] = max(active["max"], active["now"])
        time.sleep(0.05)
        sent.append(text)
        active["now"] -= 1

    monkeypatch.setattr(ws, "_send_telegram", fake_send)

    def wait_for(n):
        deadline = time.time() + 5
        while len(sent) < n and time.time() < deadline:
            time.sleep(0.01)
        return sent

    return NS(sent=sent, active=active, wait_for=wait_for)


def test_telegram_is_sent_in_the_background(telegram):
    started = time.monotonic()
    ws._send_telegram_async("hello")
    assert time.monotonic() - started < 0.04          # the caller does not wait for Telegram
    assert telegram.wait_for(1) == ["hello"]


def test_a_burst_of_alerts_is_sent_one_at_a_time_in_order(telegram):
    for i in range(6):                                # e.g. every finding at server start
        ws._send_telegram_async(f"m{i}")
    assert telegram.wait_for(6) == [f"m{i}" for i in range(6)]
    assert telegram.active["max"] == 1                # never two requests at once: Telegram drops bursts


def test_telegram_is_retried_when_it_asks_us_to_slow_down(monkeypatch):
    import io
    import urllib.error
    monkeypatch.setattr(ws, "TELEGRAM_BOT_TOKEN", "t")
    monkeypatch.setattr(ws, "TELEGRAM_CHAT_ID", "c")
    waits, calls = [], []

    def fake_urlopen(request, timeout):
        calls.append(request)
        if len(calls) == 1:
            body = io.BytesIO(b'{"ok": false, "parameters": {"retry_after": 2}}')
            raise urllib.error.HTTPError(request.full_url, 429, "Too Many Requests", {}, body)
        return NS()

    monkeypatch.setattr(ws.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(ws.time, "sleep", waits.append)
    assert ws._send_telegram("hi") is True and len(calls) == 2 and waits == [2]

    def always_bad(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 400, "Bad Request", {}, io.BytesIO(b"{}"))

    monkeypatch.setattr(ws.urllib.request, "urlopen", always_bad)
    assert ws._send_telegram("hi") is False


def test_the_camera_service_can_restart_right_after_answering_requests():
    """The collector checks /snapshot every few seconds; each answer leaves the port in TIME_WAIT.
    A stopped stream must still be able to start again at once on the same port."""
    import importlib.util
    import threading
    import urllib.request
    from pathlib import Path
    path = Path(__file__).resolve().parent.parent / "docker" / "camera" / "camera_server.py"
    spec = importlib.util.spec_from_file_location("camera_server", path)
    cam = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cam)                      # the main guard keeps it from serving on import
    first = cam.Server(("127.0.0.1", 0), cam.Handler)
    port = first.server_address[1]
    threading.Thread(target=first.serve_forever, daemon=True).start()
    for _ in range(3):
        assert urllib.request.urlopen(f"http://127.0.0.1:{port}/snapshot", timeout=2).status == 200
    first.shutdown()
    first.server_close()                              # "stop the stream"
    second = cam.Server(("127.0.0.1", port), cam.Handler)   # "start the stream": same port, at once
    second.server_close()


# --- API -----------------------------------------------------------------------------------
def test_an_alert_can_be_acknowledged(lab):
    lab.samples["cam-khalid"] = dict(STOPPED)
    lab.rounds()
    client = TestClient(ws.app)
    alert_id = ws.ALERT_LOG[0]["id"]
    body = client.post(f"/api/alerts/{alert_id}/ack").json()
    assert body["acknowledged"] is True and body["ack_by"] == "dashboard" and body["active"] is True
    assert client.post("/api/alerts/nope/ack").status_code == 404


def test_devices_carry_their_health_while_the_collector_runs(lab, monkeypatch):
    lab.samples["cam-khalid"] = dict(STREAM_DOWN)
    lab.rounds()
    monkeypatch.setattr(ws, "COLLECTOR", lab.collector)
    monkeypatch.setattr(ws, "_collector_on", lambda: True)
    monkeypatch.setattr(dc, "list_devices_dashboard", lambda: [{"id": "cam-khalid", "status": "online"},
                                                               {"id": "fw-branch1", "status": "online"}])
    monkeypatch.setattr(ws, "_track_sim_status", lambda devices: pytest.fail("the collector detects changes, not the poll"))
    rows = {d["id"]: d for d in TestClient(ws.app).get("/api/devices").json()}
    assert rows["cam-khalid"]["health"] == "degraded" and rows["cam-khalid"]["health_reason"] == "camera stream is not answering"
    assert rows["fw-branch1"]["health"] == "up"
    health_body = TestClient(ws.app).get("/api/health").json()
    assert health_body["collector"]["rounds"] == 4
    assert {d["device"]: d["state"] for d in health_body["devices"]} == {"cam-khalid": "degraded", "fw-branch1": "up"}


def test_without_the_collector_the_poll_still_detects_changes(monkeypatch):
    monkeypatch.setattr(ws, "_collector_on", lambda: False)
    called = []
    monkeypatch.setattr(dc, "list_devices_dashboard", lambda: [{"id": "host-ahmed", "status": "online"}])
    monkeypatch.setattr(ws, "_track_sim_status", called.append)
    TestClient(ws.app).get("/api/devices")
    assert called


class FakeRequest:
    def __init__(self, disconnect_after=None):
        self.calls, self.disconnect_after = 0, disconnect_after

    async def is_disconnected(self):
        self.calls += 1
        return self.disconnect_after is not None and self.calls > self.disconnect_after


def collect(gen, bump_at=None):
    async def run():
        out = []
        async for chunk in gen:
            out.append(chunk)
            if bump_at is not None and len(out) == bump_at:
                ws._bump_events()
        return out
    return asyncio.run(run())


def test_server_sent_events_announce_changes():
    chunks = collect(ws._event_stream(FakeRequest(), poll=0.01, keepalive=100, lifetime=0.2), bump_at=1)
    assert chunks[0].startswith("retry:")
    updates = [c for c in chunks if c.startswith("event: update")]
    assert len(updates) == 1 and json.loads(updates[0].split("data: ")[1])["version"] == ws._EVENTS["version"]


def test_server_sent_events_keep_alive_and_stop_when_the_client_leaves():
    chunks = collect(ws._event_stream(FakeRequest(disconnect_after=5), poll=0.01, keepalive=0.02, lifetime=10))
    assert any(c.startswith(": keep-alive") for c in chunks)


def test_the_events_endpoint_streams():
    response = asyncio.run(ws.api_events(FakeRequest()))
    assert response.media_type == "text/event-stream" and response.headers["cache-control"] == "no-cache"


# --- storage -------------------------------------------------------------------------------
def test_alerts_are_stored_in_sqlite_and_survive_a_restart(lab, monkeypatch, tmp_path):
    db = Database(tmp_path / "netmind.db")
    monkeypatch.setattr(ws, "ALERTS_DB", db)
    monkeypatch.setattr(ws, "ALERTS_PATH", tmp_path / "alerts.json")
    lab.samples["cam-khalid"] = dict(STREAM_DOWN)
    lab.rounds()
    ws.ALERT_LOG[0]["acknowledged"] = True
    with ws._alert_lock:
        ws._save_alerts()
    assert not (tmp_path / "alerts.json").exists()                  # the database is used, not the file
    for state in (ws.ALERT_LOG, ws._degraded_alert):
        state.clear()
    ws._saved_alerts["payload"] = None
    monkeypatch.setattr(ws, "ALERTS_DB", Database(tmp_path / "netmind.db"))   # a restart
    ws._load_alerts()
    assert kinds() == ["device_degraded"] and ws.ALERT_LOG[0]["acknowledged"] is True
    assert "cam-khalid" in ws._degraded_alert                       # still open after the restart


def test_an_old_alerts_file_is_imported_into_the_database_once(monkeypatch, tmp_path):
    old = [{"id": "a7", "kind": "device_offline", "title": "Device Offline", "detail": "host-ahmed went offline",
            "device": "host-ahmed", "ts": 1000, "active": True}]
    (tmp_path / "alerts.json").write_text(json.dumps(old), encoding="utf-8")
    db = Database(tmp_path / "netmind.db")
    monkeypatch.setattr(ws, "ALERTS_DB", db)
    monkeypatch.setattr(ws, "ALERTS_PATH", tmp_path / "alerts.json")
    ws._load_alerts()
    assert db.alert_count() == 1 and kinds() == ["device_offline"] and "host-ahmed" in ws._down_alert
    (tmp_path / "alerts.json").write_text("[]", encoding="utf-8")
    ws._load_alerts()                                               # not imported again
    assert db.alert_count() == 1 and kinds() == ["device_offline"]


def test_a_version_1_database_is_upgraded_without_losing_data(tmp_path):
    path = tmp_path / "netmind.db"
    conn = sqlite3.connect(path)
    conn.executescript("CREATE TABLE sessions (key TEXT PRIMARY KEY, last REAL NOT NULL);"
                       "CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT,"
                       " tool TEXT NOT NULL, args TEXT, status TEXT NOT NULL, result TEXT);"
                       "INSERT INTO audit(ts, tool, status) VALUES ('t', 'power_off', 'executed');"
                       "PRAGMA user_version = 1;")
    conn.commit()
    conn.close()
    db = Database(path)
    assert db.audit_count() == 1 and db.alert_count() == 0
    db.save_alerts([{"id": "a1", "ts": 5, "kind": "device_offline"}, {"id": "a2", "ts": 9, "kind": "device_online"}])
    db.save_alerts([{"id": "a1", "ts": 5, "kind": "device_offline", "active": False}])
    assert [a["id"] for a in db.recent_alerts(10)] == ["a2", "a1"] and db.recent_alerts(10)[1]["active"] is False
    assert sqlite3.connect(path).execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 2


# --- sampling the real lab (Docker and the network faked) ----------------------------------
class Box:
    def __init__(self, name, status="running", stats=None):
        self.name, self.status, self._stats = name, status, stats

    def stats(self, stream=False):
        if self._stats is None:
            raise RuntimeError("no stats")
        return self._stats


def fake_lab(monkeypatch, boxes, registry):
    monkeypatch.setattr(dc, "_load_registry", lambda: registry)
    monkeypatch.setattr(dc, "_client", NS(containers=NS(
        list=lambda all=False: [b for b in boxes if all or b.status == "running"])))


def test_sample_lab_checks_streams_and_pings_only_running_devices(monkeypatch):
    registry = [CAM, FW, HOST, {"id": "host-sara", "type": "host", "container": "c-sara", "ip": "10.0.0.8"}]
    fake_lab(monkeypatch, [Box("c-cam"), Box("c-fw"), Box("c-host", "exited")], registry)
    asked = []
    monkeypatch.setattr(dc, "_snapshot_ok", lambda url: asked.append(url) or False)
    monkeypatch.setattr(dc, "_ping_ok", lambda ip: asked.append(ip) or True)
    samples = {d["id"]: s for d, s in dc.sample_lab()}
    assert samples["cam-khalid"] == {"container": "running", "stream": False, "reachable": True}
    assert samples["fw-branch1"] == {"container": "running"}         # firewalls are not pinged
    assert samples["host-ahmed"] == {"container": "exited"}
    assert samples["host-sara"] == {"container": "missing"}
    assert sorted(asked) == ["10.0.0.5", "http://10.0.0.5:8080/snapshot"]


def test_sample_lab_without_ping_and_with_ping_unavailable(monkeypatch):
    fake_lab(monkeypatch, [Box("c-host")], [HOST])
    monkeypatch.setattr(dc, "_ping_ok", lambda ip: None)            # ping cannot run: unknown, not a failure
    assert dc.sample_lab()[0][1] == {"container": "running"}
    monkeypatch.setattr(dc, "_ping_ok", lambda ip: pytest.fail("ping disabled"))
    assert dc.sample_lab(ping=False)[0][1] == {"container": "running"}


def test_sample_lab_raises_when_docker_cannot_be_read(monkeypatch):
    def boom(all=False):
        raise RuntimeError("Cannot connect to the Docker daemon")

    monkeypatch.setattr(dc, "_load_registry", lambda: [HOST])
    monkeypatch.setattr(dc, "_client", NS(containers=NS(list=boom)))
    with pytest.raises(RuntimeError):
        dc.sample_lab()


STATS = {"cpu_stats": {"cpu_usage": {"total_usage": 3_000}, "system_cpu_usage": 20_000, "online_cpus": 2},
         "precpu_stats": {"cpu_usage": {"total_usage": 1_000}, "system_cpu_usage": 10_000},
         "memory_stats": {"usage": 600, "limit": 1000, "stats": {"inactive_file": 100}}}


def test_cpu_and_memory_are_computed_like_docker_stats():
    assert dc._cpu_mem(STATS) == {"cpu": 40.0, "mem": 50.0}
    assert dc._cpu_mem({}) == {"cpu": 0.0}


def test_lab_metrics_reads_every_running_lab_container(monkeypatch):
    fake_lab(monkeypatch, [Box("c-cam", stats=STATS), Box("c-host", stats=None), Box("other", stats=STATS),
                           Box("c-fw", "exited", stats=STATS)], [CAM, HOST, FW])
    assert dc.lab_metrics() == {"cam-khalid": {"cpu": 40.0, "mem": 50.0}, "host-ahmed": {}}
    fake_lab(monkeypatch, [], [CAM])
    assert dc.lab_metrics() == {}


def test_ping_ok_handles_a_missing_ping_binary(monkeypatch):
    def missing(*a, **k):
        raise FileNotFoundError("ping")

    monkeypatch.setattr(dc.subprocess, "run", missing)
    assert dc._ping_ok("10.0.0.1") is None
    monkeypatch.setattr(dc.subprocess, "run", lambda *a, **k: NS(returncode=1))
    assert dc._ping_ok("10.0.0.1") is False


# --- settings ------------------------------------------------------------------------------
def test_collector_settings_come_from_the_environment():
    s = Settings.from_env({"NETMIND_COLLECTOR": "0", "NETMIND_COLLECT_INTERVAL": "10",
                           "NETMIND_COLLECT_CONFIRM": "3", "NETMIND_COLLECT_PING": "off"})
    assert (s.collector_enabled, s.collector_interval, s.collector_confirm, s.collector_ping) == (False, 10.0, 3, False)
    d = Settings.from_env({"NETMIND_COLLECT_INTERVAL": "fast"})
    assert d.collector_enabled and d.collector_interval == 5.0 and d.collector_confirm == 2 and d.collector_ping
