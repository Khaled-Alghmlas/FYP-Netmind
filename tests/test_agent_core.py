import json
from types import SimpleNamespace as NS

import agent_core as core


def make_msg(content=None, calls=()):
    tool_calls = [
        NS(id=f"call_{i}", function=NS(name=name, arguments=args))
        for i, (name, args) in enumerate(calls)
    ] or None
    return NS(content=content, tool_calls=tool_calls)


class FakeClient:
    """Returns the scripted assistant messages one per request."""

    def __init__(self, messages):
        self._messages = list(messages)
        self.chat = NS(completions=NS(create=self._create))

    def _create(self, **kwargs):
        msg = self._messages.pop(0) if len(self._messages) > 1 else self._messages[0]
        return NS(choices=[NS(message=msg)])


def run(client, call_tool, steps=None, max_rounds=5):
    history = [{"role": "system", "content": "sys"}]
    reply = core.run_query(client, "m", "hi", history, [], call_tool, steps=steps, max_rounds=max_rounds)
    return reply, history


# ---- #5: agent loop hardening ---------------------------------------------
def test_malformed_arguments_return_error_not_exception():
    client = FakeClient([make_msg(calls=[("get_status", "{not json")]), make_msg("done")])
    steps = []
    reply, history = run(client, lambda n, a: {"ok": True}, steps)
    assert reply == "done"
    assert "Malformed JSON" in steps[0]["result"]["error"]
    tool_msg = [m for m in history if m["role"] == "tool"][0]
    assert "Malformed JSON" in json.loads(tool_msg["content"])["error"]


def test_non_object_arguments_are_rejected():
    client = FakeClient([make_msg(calls=[("get_status", "[1, 2]")]), make_msg("done")])
    steps = []
    run(client, lambda n, a: {"ok": True}, steps)
    assert "JSON object" in steps[0]["result"]["error"]


def test_tool_exception_is_reported_to_model():
    def boom(name, args):
        raise RuntimeError("docker down")

    client = FakeClient([make_msg(calls=[("get_status", "{}")]), make_msg("done")])
    steps = []
    run(client, boom, steps)
    assert steps[0]["result"] == {"error": "docker down"}


def test_history_holds_plain_dicts_only():
    client = FakeClient([make_msg("ok", calls=[("get_status", '{"a": 1}')]), make_msg("done")])
    _, history = run(client, lambda n, a: {"ok": True})
    assert all(isinstance(m, dict) for m in history)
    json.dumps(history)  # must be JSON-serialisable


def test_round_cap_returns_partial_results():
    client = FakeClient([make_msg(calls=[("get_status", '{"x": "r1"}')])])  # loops forever
    reply, history = run(client, lambda n, a: {"status": "online"}, max_rounds=3)
    assert "limit of 3" in reply
    assert "get_status" in reply and "online" in reply
    assert history[-1] == {"role": "assistant", "content": reply}


def test_model_error_is_returned_as_text():
    class Bad:
        chat = NS(completions=NS(create=lambda **k: (_ for _ in ()).throw(RuntimeError("429"))))

    reply, _ = run(Bad(), lambda n, a: {})
    assert "429" in reply


# ---- sessions --------------------------------------------------------------
def test_session_ttl_expires_old_sessions():
    now = [0]
    store = core.SessionStore(ttl=10, clock=lambda: now[0])
    store.get("a", "sys")
    now[0] = 100
    store.get("b", "sys")
    assert len(store) == 1


def test_session_cap():
    store = core.SessionStore(max_sessions=3)
    for i in range(10):
        store.get(f"s{i}", "sys")
    assert len(store) <= 3


def test_trim_keeps_system_and_never_starts_with_orphan_tool():
    history = [{"role": "system", "content": "s"}]
    for i in range(30):
        history.append({"role": "assistant", "content": "", "tool_calls": [{"id": str(i)}]})
        history.append({"role": "tool", "tool_call_id": str(i), "content": "{}"})
    trimmed = core.trim_history(history, max_messages=11)
    assert trimmed[0]["role"] == "system"
    assert trimmed[1]["role"] == "assistant"
    assert len(trimmed) <= 12


# ---- #8: guard, confirmation, protected devices, audit ---------------------
DEVICES = {
    "host-ahmed": {"id": "host-ahmed", "type": "host", "owner": "ahmed"},
    "fw-branch1": {"id": "fw-branch1", "type": "firewall", "owner": None},
    "r1": {"id": "r1", "type": "router", "owner": None},
    "cam-ahmed": {"id": "cam-ahmed", "type": "camera", "owner": "ahmed"},
}


def make_guard(calls):
    def rec(name):
        def f(**kw):
            calls.append((name, kw))
            return {"done": name}
        return f

    dispatch = {n: rec(n) for n in
                ["get_status", "power_off", "block_port", "allow_port", "change_camera_credentials"]}
    return core.Guard(dispatch, lambda n: [DEVICES[n]] if n in DEVICES else [], core.AuditLog())


def test_readonly_tool_runs_immediately():
    calls = []
    g = make_guard(calls)
    assert g.call("get_status", {"name_or_owner": "host-ahmed"}, "chat:1") == {"done": "get_status"}
    assert calls


def test_destructive_tool_is_not_executed_until_confirmed():
    calls = []
    g = make_guard(calls)
    res = g.call("power_off", {"name_or_owner": "host-ahmed"}, "chat:1", "k")
    assert res["status"] == "pending_confirmation" and res["executed"] is False
    assert calls == []
    out = g.confirm(res["pending_id"], True, "user")
    assert out["status"] == "executed"
    assert calls == [("power_off", {"name_or_owner": "host-ahmed"})]


def test_cancel_does_not_execute():
    calls = []
    g = make_guard(calls)
    res = g.call("power_off", {"name_or_owner": "host-ahmed"}, "chat:1")
    assert g.confirm(res["pending_id"], False, "user")["status"] == "cancelled"
    assert calls == []
    assert "error" in g.confirm(res["pending_id"], True, "user")  # cannot reuse


def test_protected_devices_need_explicit_acknowledgement():
    calls = []
    g = make_guard(calls)
    for target in ("r1", "fw-branch1"):
        res = g.call("power_off", {"name_or_owner": target}, "chat:1")
        assert res["requires_protected_ack"] and target in res["protected"]
        denied = g.confirm(res["pending_id"], True, "user")
        assert denied["requires_protected_ack"] and calls == []
        assert g.confirm(res["pending_id"], True, "user", acknowledge_protected=True)["status"] == "executed"
        calls.clear()


def test_unknown_target_is_denied_without_pending():
    g = make_guard([])
    res = g.call("power_off", {"name_or_owner": "nobody"}, "chat:1")
    assert "error" in res and g.list_pending() == []


def test_pending_actions_expire():
    now = [0]
    audit = core.AuditLog()
    g = core.Guard({"power_off": lambda **k: {}}, lambda n: [DEVICES["host-ahmed"]], audit, clock=lambda: now[0])
    res = g.call("power_off", {"name_or_owner": "host-ahmed"}, "chat:1")
    now[0] = core.PENDING_TTL_SECONDS + 1
    assert "error" in g.confirm(res["pending_id"], True, "user")
    assert audit.list()[-1]["status"] == "expired"


def test_audit_log_records_who_what_args_result_when_and_redacts_password():
    calls = []
    g = make_guard(calls)
    res = g.call("change_camera_credentials", {"cam_id": "cam-ahmed", "new_password": "hunter2"}, "chat:7")
    g.confirm(res["pending_id"], True, "user")
    entries = g.audit.list()
    assert [e["status"] for e in entries] == ["pending", "confirmed"]
    for e in entries:
        assert {"ts", "actor", "tool", "args", "status", "result"} <= e.keys()
        assert e["args"]["new_password"] == "***"
    assert entries[0]["actor"] == "chat:7" and entries[1]["actor"] == "user"
    assert calls[0][1]["new_password"] == "hunter2"  # real value still reaches the tool


def test_audit_log_writes_jsonl(tmp_path):
    path = tmp_path / "logs" / "audit.jsonl"
    log = core.AuditLog(path=path)
    log.record("chat:1", "get_status", {"a": 1}, {"ok": 1}, "executed")
    assert json.loads(path.read_text().splitlines()[0])["tool"] == "get_status"


# ---- model talks about an action but never calls the tool -----------------
DESTRUCTIVE_TOOLS_SCHEMA = [{"function": {"name": n}} for n in
                            ("get_status", "block_port", "power_off")]


def run_with_tools(client, call_tool, user_input, tools):
    history = [{"role": "system", "content": "sys"}]
    steps = []
    reply = core.run_query(client, "m", user_input, history, tools, call_tool, steps=steps)
    return reply, steps, history


def test_fake_pending_claim_without_tool_call_is_retried():
    client = FakeClient([
        make_msg("I've queued that - please press Confirm."),            # no tool call!
        make_msg(calls=[("block_port", '{"fw_id": "fw-branch1", "port": 2222}')]),
        make_msg("Waiting for your confirmation."),
    ])
    calls = []
    reply, steps, history = run_with_tools(
        client, lambda n, a: calls.append(n) or {"status": "pending_confirmation"},
        "block port 2222 on fw-branch1", DESTRUCTIVE_TOOLS_SCHEMA)
    assert calls == ["block_port"] and reply == "Waiting for your confirmation."
    assert any("System note" in m.get("content", "") for m in history if m["role"] == "user")


def test_refusal_of_action_request_is_retried():
    client = FakeClient([make_msg("I can't modify firewall rules."),
                         make_msg(calls=[("block_port", "{}")]), make_msg("ok")])
    calls = []
    run_with_tools(client, lambda n, a: calls.append(n) or {}, "block port 22 on fw-branch1",
                   DESTRUCTIVE_TOOLS_SCHEMA)
    assert calls == ["block_port"]


def test_plain_question_is_not_retried_more_than_once_and_real_mode_never():
    client = FakeClient([make_msg("A firewall filters traffic.")])
    reply, steps, _ = run_with_tools(client, lambda n, a: {}, "what does block mean?",
                                     DESTRUCTIVE_TOOLS_SCHEMA)
    assert reply == "A firewall filters traffic." and steps == []   # one retry, then returned
    real_tools = [{"function": {"name": "list_devices"}}]
    client = FakeClient([make_msg("I can't block ports on real devices.")])
    assert not core.needs_tool_retry("block port 22", "I can't block ports on real devices.", real_tools, [])
