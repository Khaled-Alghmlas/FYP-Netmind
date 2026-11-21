"""Issue #13: what a backend may do is enforced in code, not only in the prompt."""
import pytest

import agent_core as core
import backends
import web_server as ws


class FakeBackend(backends.NetworkBackend):
    name = "fake"
    capabilities = frozenset({backends.Cap.INVENTORY})

    def __init__(self):
        self.calls = []

    def implementations(self):
        return {
            "list_devices": lambda: self.calls.append("list_devices") or [],
            "power_off": lambda name_or_owner: self.calls.append("power_off"),
        }

    def resolve(self, name_or_owner):
        return []


def test_unsupported_tool_raises_and_never_runs():
    b = FakeBackend()
    with pytest.raises(backends.CapabilityError, match="power"):
        b.call("power_off", name_or_owner="x")
    assert b.calls == []


def test_supported_tool_runs():
    b = FakeBackend()
    assert b.call("list_devices") == []
    assert b.calls == ["list_devices"]


def test_dispatch_covers_every_tool_but_blocked_ones_raise():
    b = FakeBackend()
    table = b.dispatch()
    assert set(table) == set(backends.TOOL_CAPABILITY)
    with pytest.raises(backends.CapabilityError):
        table["block_port"](fw_id="fw-1", port=22)


def test_unknown_tool_is_refused():
    with pytest.raises(backends.CapabilityError, match="not a known tool"):
        FakeBackend().call("format_disk")


def test_real_backend_has_no_power_firewall_or_camera_capability():
    real = backends.RealLanBackend()
    for tool in ("power_on", "power_off", "block_port", "allow_port", "change_camera_credentials"):
        assert not real.supports(tool)
    assert real.supports("list_devices") and real.supports("get_status")


def test_real_mode_shows_the_model_only_read_tools():
    names = {t["function"]["name"] for t in ws.MODES["real"]["tools"]}
    assert names == {"list_devices", "get_status", "get_ip"}


def test_simulated_mode_keeps_every_tool():
    names = {t["function"]["name"] for t in ws.MODES["simulated"]["tools"]}
    assert names == set(backends.TOOL_CAPABILITY)


def test_guard_denies_power_off_on_real_even_if_the_model_calls_it(monkeypatch):
    audit = core.AuditLog()
    guard = ws.GUARDS["real"]
    monkeypatch.setattr(guard, "audit", audit)
    r = guard.call("power_off", {"name_or_owner": "192.168.1.5"}, actor="chat:s1")
    assert "not available on the real network" in r["error"]
    assert guard.list_pending() == []                      # nothing queued for confirmation
    assert [e["status"] for e in audit.list()] == ["denied"]


def test_real_mode_through_the_chat_api_cannot_power_off(monkeypatch):
    from types import SimpleNamespace as NS
    from fastapi.testclient import TestClient

    scripted = [
        NS(content=None, tool_calls=[NS(id="c0", function=NS(name="power_off", arguments='{"name_or_owner": "192.168.1.5"}'))]),
        NS(content="I can't do that on a real network.", tool_calls=None),
    ]
    from llm import ChatCompletionsProvider
    fake = NS(chat=NS(completions=NS(create=lambda **k: NS(choices=[NS(message=scripted.pop(0))]))))
    monkeypatch.setattr(ws, "provider", ChatCompletionsProvider(fake, "test"))
    monkeypatch.setattr(ws, "SESSIONS", core.SessionStore())
    monkeypatch.setattr(ws.GUARDS["real"], "audit", core.AuditLog())   # keep logs/audit.jsonl untouched
    body = TestClient(ws.app).post("/api/chat", json={"session_id": "s", "message": "turn off 192.168.1.5", "mode": "real"}).json()
    assert body["pending"] == []
    assert "not available on the real network" in body["steps"][0]["result"]["error"]


def test_guard_still_works_without_a_capability_check():
    audit = core.AuditLog()
    guard = core.Guard({"get_status": lambda **k: "ok"}, lambda n: [], audit)   # supports=None
    assert guard.call("get_status", {}, "t") == "ok"
