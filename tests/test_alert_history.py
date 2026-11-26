"""Issue #23: the get_alerts tool answers questions about the past from the alert history."""
from datetime import datetime

import alert_history as ah
import backends
import tool_catalog
import web_server as ws

HOUR = 3_600_000
NOW = int(datetime(2026, 11, 25, 9, 0).astimezone().timestamp() * 1000)   # 09:00 local


def alert(n, kind, device, hours_ago, active=False, **extra):
    return {"id": f"a{n}", "kind": kind, "title": kind, "detail": f"{device} {kind}", "device": device,
            "ts": NOW - int(hours_ago * HOUR), "active": active, **extra}


# newest first, like ALERT_LOG
ALERTS = [
    alert(5, "firewall_finding", "fw-branch1", 1, active=True),
    alert(4, "device_online", "cam-khalid", 4, down_seconds=1800.0),
    alert(3, "device_offline", "cam-khalid", 4.5),
    alert(2, "device_offline", "host-ahmed", 30),
    alert(1, "device_online", "host-ahmed", 29),
]


def use(monkeypatch, alerts=ALERTS):
    monkeypatch.setattr(ah, "_source", lambda: list(alerts))


def test_what_happened_to_a_camera_last_night(monkeypatch):
    use(monkeypatch)
    r = ah.get_alerts(device="cam-khalid", start="2026-11-25T00:00", end="2026-11-25T06:00", now_ms=NOW)
    assert [a["kind"] for a in r["alerts"]] == ["device_online", "device_offline"]
    assert r["alerts"][0]["down_seconds"] == 1800.0 and r["total_matching"] == 2
    assert r["now"].startswith("2026-11-25T09:00")


def test_hours_back_is_the_default_window(monkeypatch):
    use(monkeypatch)
    r = ah.get_alerts(now_ms=NOW)                       # last 24 h: the two host-ahmed alerts are older
    assert [a["device"] for a in r["alerts"]] == ["fw-branch1", "cam-khalid", "cam-khalid"]
    assert ah.get_alerts(hours_back=48, now_ms=NOW)["total_matching"] == 5


def test_filters_by_device_part_kind_and_open_alerts(monkeypatch):
    use(monkeypatch)
    assert ah.get_alerts(device="CAM", hours_back=48, now_ms=NOW)["total_matching"] == 2
    assert ah.get_alerts(kind="device_offline", hours_back=48, now_ms=NOW)["total_matching"] == 2
    open_only = ah.get_alerts(active_only=True, hours_back=48, now_ms=NOW)
    assert [a["device"] for a in open_only["alerts"]] == ["fw-branch1"]


def test_limit_caps_the_list_but_not_the_total(monkeypatch):
    use(monkeypatch)
    r = ah.get_alerts(hours_back=48, limit=2, now_ms=NOW)
    assert r["count"] == 2 and len(r["alerts"]) == 2 and r["total_matching"] == 5


def test_history_starts_tells_how_far_back_alerts_go(monkeypatch):
    use(monkeypatch)
    assert ah.get_alerts(now_ms=NOW)["history_starts"].startswith("2026-11-24T03:00")
    use(monkeypatch, [])
    r = ah.get_alerts(now_ms=NOW)
    assert r["history_starts"] is None and r["alerts"] == []


def test_a_bad_date_is_reported_not_raised(monkeypatch):
    use(monkeypatch)
    assert "ISO" in ah.get_alerts(start="last night", now_ms=NOW)["error"]


def test_alerts_without_a_timestamp_are_ignored(monkeypatch):
    use(monkeypatch, [{"kind": "device_offline", "device": "x"}, alert(1, "device_offline", "y", 1)])
    assert ah.get_alerts(now_ms=NOW)["total_matching"] == 1


def test_without_a_source_the_saved_file_is_read(monkeypatch, tmp_path):
    import json
    f = tmp_path / "alerts.json"
    f.write_text(json.dumps(ALERTS))
    monkeypatch.setattr(ah, "_source", None)
    monkeypatch.setattr(ah, "ALERTS_FILE", f)
    assert ah.get_alerts(hours_back=48, now_ms=NOW)["total_matching"] == 5
    monkeypatch.setattr(ah, "ALERTS_FILE", tmp_path / "missing.json")
    assert ah.get_alerts(now_ms=NOW)["alerts"] == []


def test_the_server_feeds_its_live_alert_log_to_the_tool(monkeypatch):
    monkeypatch.setattr(ws, "ALERTS_PATH", None)
    monkeypatch.setattr(ws, "_send_telegram", lambda text: None)   # never message a real chat from a test
    ws.ALERT_LOG.clear()
    ws._add_alert("device_offline", "Device Offline", "cam-khalid went offline", "cam-khalid")
    r = tool_catalog.registry.implementations()["get_alerts"](device="cam-khalid")
    assert r["total_matching"] == 1 and r["alerts"][0]["detail"] == "cam-khalid went offline"
    ws.ALERT_LOG.clear()


def test_only_the_simulated_lab_has_alert_history():
    assert backends.ContainerlabBackend().supports("get_alerts")
    assert not backends.RealLanBackend().supports("get_alerts")
    assert not backends.RealLanBackend().supports("traceroute")


def test_odd_argument_values_from_the_model_are_tolerated(monkeypatch):
    use(monkeypatch)
    r = ah.get_alerts(device=None, kind=None, active_only="false", hours_back="48", start=None, end=None,
                      limit="abc", now_ms=NOW)
    assert r["total_matching"] == 5                      # "false" is not True, "48" is 48 hours
    assert ah.get_alerts(active_only="true", hours_back=48, now_ms=NOW)["total_matching"] == 1
    assert ah.get_alerts(hours_back=None, limit=None, now_ms=NOW)["total_matching"] == 3   # defaults: 24 h / 20