"""Alert history: offline/back-online alerts are permanent and carry the downtime."""
import pytest

import web_server as ws


@pytest.fixture(autouse=True)
def no_disk(monkeypatch):
    monkeypatch.setattr(ws, "ALERTS_PATH", None)


def reset():
    ws.ALERT_LOG.clear()
    ws._down_alert.clear()
    ws._down_since.clear()
    ws._finding_open.clear()
    ws._last_sim_status.clear()


def dev(status):
    return [{"id": "host-1", "name": "host-1", "status": status}]


def test_offline_then_online_keeps_both_alerts_and_reports_downtime(monkeypatch):
    reset()
    ws._track_sim_status(dev("online"))
    assert ws.ALERT_LOG == []
    ws._track_sim_status(dev("offline"))
    assert [a["kind"] for a in ws.ALERT_LOG] == ["device_offline"] and ws.ALERT_LOG[0]["active"]
    ws._down_since["host-1"] -= 75_000          # pretend it was down for 75 s
    ws._track_sim_status(dev("online"))
    kinds = [a["kind"] for a in ws.ALERT_LOG]
    assert kinds == ["device_online", "device_offline"]            # history is kept, newest first
    online, offline = ws.ALERT_LOG
    assert 75 <= online["down_seconds"] < 80 and "1m 1" in online["detail"] and "back online" in online["detail"]
    assert offline["active"] is False and online["active"] is False


def test_device_already_offline_at_startup_raises_an_alert():
    reset()
    ws._track_sim_status(dev("offline"))
    assert [a["kind"] for a in ws.ALERT_LOG] == ["device_offline"]
    ws._track_sim_status(dev("offline"))                            # still down: no duplicate
    assert len(ws.ALERT_LOG) == 1


def test_firewall_findings_are_logged_once_with_a_stable_timestamp(monkeypatch):
    reset()
    monkeypatch.setattr(ws.dc, "get_security_findings", lambda: [("fw-a", "Port 22 open", "firewall_finding"), ("fw-b", "Port 22 open", "firewall_finding")])
    ws._track_findings()
    first = [(a["detail"], a["ts"]) for a in ws.ALERT_LOG]
    ws._track_findings()
    assert [(a["detail"], a["ts"]) for a in ws.ALERT_LOG] == first and len(first) == 2
    assert {a["detail"] for a in ws.ALERT_LOG} == {"fw-a: Port 22 open", "fw-b: Port 22 open"}
    monkeypatch.setattr(ws.dc, "get_security_findings", lambda: [("fw-b", "Port 22 open", "firewall_finding")])
    ws._track_findings()
    assert len(ws.ALERT_LOG) == 2 and sorted(a["active"] for a in ws.ALERT_LOG) == [False, True]


def test_alert_history_survives_a_restart(tmp_path, monkeypatch):
    monkeypatch.setattr(ws, "ALERTS_PATH", tmp_path / "alerts.json")
    reset()
    ws._track_sim_status(dev("offline"))                       # host-1 goes down; saved to disk
    # "restart": memory is wiped, only the saved file remains
    ws.ALERT_LOG.clear()
    ws._down_alert.clear()
    ws._down_since.clear()
    ws._load_alerts()
    assert [a["kind"] for a in ws.ALERT_LOG] == ["device_offline"] and "host-1" in ws._down_alert
    ws._last_sim_status.clear()
    ws._track_sim_status(dev("online"))                        # recovery is reported against the old alert
    assert [a["kind"] for a in ws.ALERT_LOG] == ["device_online", "device_offline"]
    assert ws.ALERT_LOG[1]["active"] is False


def test_camera_default_password_becomes_an_alert(monkeypatch):
    reset()
    monkeypatch.setattr(ws.dc, "get_security_findings",
                        lambda: [("cam-1", "Camera is using the default password (admin)", "camera_finding")])
    ws._track_findings()
    assert ws.ALERT_LOG[0]["kind"] == "camera_finding" and ws.ALERT_LOG[0]["title"] == "Camera Finding"
