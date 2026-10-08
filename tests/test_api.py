"""Endpoint-level tests: web_server with a fake model client and fake devices."""
from types import SimpleNamespace as NS

import pytest
from fastapi.testclient import TestClient

import agent_core as core
import web_server as ws


def msg(content=None, calls=()):
    tcs = [NS(id=f"c{i}", function=NS(name=n, arguments=a)) for i, (n, a) in enumerate(calls)] or None
    return NS(content=content, tool_calls=tcs)


@pytest.fixture
def api(monkeypatch):
    scripted = []

    def create(**kwargs):
        return NS(choices=[NS(message=scripted.pop(0))])

    monkeypatch.setattr(ws, "client", NS(chat=NS(completions=NS(create=create))))
    monkeypatch.setattr(ws, "SESSIONS", core.SessionStore())
    audit = core.AuditLog()
    monkeypatch.setattr(ws, "AUDIT_LOG", audit)
    called = []
    dev = {"id": "host-ahmed", "type": "host", "owner": "ahmed"}
    monkeypatch.setitem(ws.GUARDS, "simulated", core.Guard(
        {"get_status": lambda **k: [{"status": "online"}],
         "power_off": lambda **k: called.append(k) or [{"new_status": "offline"}]},
        lambda n: [dev], audit))
    return NS(client=TestClient(ws.app), script=scripted, called=called, audit=audit)


def chat(api, text="hello"):
    return api.client.post("/api/chat", json={"session_id": "s1", "message": text, "mode": "simulated"})


def test_malformed_tool_arguments_do_not_cause_500(api):
    api.script += [msg(calls=[("get_status", "{oops")]), msg("sorry, retrying failed")]
    r = chat(api)
    assert r.status_code == 200
    assert "Malformed JSON" in r.json()["steps"][0]["result"]["error"]


def test_destructive_action_requires_confirmation_via_api(api):
    api.script += [msg(calls=[("power_off", '{"name_or_owner": "host-ahmed"}')]), msg("Please confirm.")]
    body = chat(api, "turn off ahmed").json()
    assert api.called == []
    pending = body["pending"][0]
    r = api.client.post("/api/confirm", json={"pending_id": pending["pending_id"], "approve": True})
    assert r.json()["status"] == "executed" and len(api.called) == 1
    statuses = [e["status"] for e in api.client.get("/api/audit").json()]
    assert statuses == ["pending", "confirmed"]


def test_dashboard_power_off_needs_confirmation(api):
    r = api.client.post("/api/devices/host-ahmed/power", json={"state": "off"})
    assert r.json()["status"] == "pending_confirmation" and api.called == []


def test_confirmation_outcome_is_added_to_chat_history(api):
    api.script += [msg(calls=[("power_off", '{"name_or_owner": "host-ahmed"}')]), msg("Please confirm.")]
    body = chat(api, "turn off ahmed").json()
    api.client.post("/api/confirm", json={"pending_id": body["pending"][0]["pending_id"], "approve": True})
    history = ws.SESSIONS.get("s1:simulated", "x")
    assert "no longer pending" in history[-1]["content"] and "executed" in history[-1]["content"]


def test_cross_site_requests_are_refused(api):
    host = {"host": "testserver"}
    ok = api.client.post("/api/devices/host-ahmed/power", json={"state": "off"},
                         headers={**host, "origin": "http://testserver"})
    assert ok.status_code == 200
    for evil in ("http://evil.example", "null"):
        r = api.client.post("/api/devices/host-ahmed/power", json={"state": "off"},
                            headers={**host, "origin": evil})
        assert r.status_code == 403
    r = api.client.get("/api/devices", headers={"origin": "http://evil.example"})
    assert r.status_code == 403 and "access-control-allow-origin" not in r.headers
    assert api.client.post("/api/confirm", json={"pending_id": "x"}, headers={"origin": "http://evil.example"}).status_code == 403


def test_logs_page_shows_actions_not_lookups(api):
    api.audit.record("chat:s1", "get_status", {"name_or_owner": "host-ahmed"}, [], "executed")
    api.audit.record("dashboard", "power_off", {"name_or_owner": "host-ahmed"}, {"summary": "Power off: host-ahmed"}, "pending")
    api.audit.record("user", "power_off", {"name_or_owner": "host-ahmed"}, [], "confirmed")
    logs = api.client.get("/api/logs").json()
    assert [(x["who"], x["tool"], x["status"], x["target"]) for x in logs] == [
        ("user", "power_off", "confirmed", "host-ahmed"), ("dashboard", "power_off", "pending", "host-ahmed")]
    assert logs[1]["detail"] == "Power off: host-ahmed"


def test_audit_history_is_reloaded_from_disk(tmp_path):
    path = tmp_path / "audit.jsonl"
    core.AuditLog(path=path).record("user", "power_off", {"name_or_owner": "x"}, None, "cancelled")
    assert [e["status"] for e in core.AuditLog(path=path).list()] == ["cancelled"]


def test_report_summarises_state(api, monkeypatch):
    monkeypatch.setattr(ws, "ALERTS_PATH", None)
    ws.ALERT_LOG.clear()
    ws._down_alert.clear()
    ws._down_since.clear()
    ws._finding_open.clear()
    ws._last_sim_status.clear()
    monkeypatch.setattr(ws.dc, "list_devices_dashboard", lambda: [{"id": "host-1", "name": "host-1", "status": "online"}])
    monkeypatch.setattr(ws.dc, "get_security_findings", lambda: [("fw-1", "Port 22 open", "firewall_finding")])
    r = api.client.get("/api/report").json()
    assert r["devices"] == {"total": 1, "online": 1}
    assert r["findings"] == [{"device": "fw-1", "kind": "firewall_finding", "finding": "Port 22 open"}]
    assert r["reliability"]["outages"] == 0 and r["reliability"]["avg_recovery_seconds"] is None
