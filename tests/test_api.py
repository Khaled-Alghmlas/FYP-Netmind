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
    ws.GUARDS["simulated"] = core.Guard(
        {"get_status": lambda **k: [{"status": "online"}],
         "power_off": lambda **k: called.append(k) or [{"new_status": "offline"}]},
        lambda n: [dev], audit)
    monkeypatch.setattr(ws, "GUARDS", ws.GUARDS)
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
