"""Issue #15: chat sessions and the audit log live in SQLite and survive a restart."""
import json
import os
import sqlite3
import stat
from types import SimpleNamespace as NS

import pytest

import agent_core as core
from llm import ChatCompletionsProvider
from settings import Settings
from storage import SCHEMA_VERSION, Database, StorageError, open_database

SYSTEM = "You are NetMind."


@pytest.fixture
def path(tmp_path):
    return tmp_path / "logs" / "netmind.db"


def restart(path, **kwargs):
    """What a server restart looks like: a brand-new store on the same database file."""
    return core.SessionStore(db=Database(path), **kwargs)


# --- sessions ------------------------------------------------------------------------------
def test_a_conversation_survives_a_restart(path):
    store = restart(path)
    history = store.get("s1:simulated", SYSTEM)
    history += [{"role": "user", "content": "status of host-ahmed"},
                {"role": "assistant", "content": "", "tool_calls": [
                    {"id": "c1", "type": "function", "function": {"name": "get_status", "arguments": '{"name_or_owner": "host-ahmed"}'}}]},
                {"role": "tool", "tool_call_id": "c1", "content": '[{"status": "online"}]'},
                {"role": "assistant", "content": "host-ahmed is online."}]
    store.save("s1:simulated", history)

    after = restart(path).get("s1:simulated", SYSTEM)
    assert after == history                                   # identical, tool call and result included
    assert restart(path).get("other:simulated", SYSTEM) == [{"role": "system", "content": SYSTEM}]


def test_a_reloaded_conversation_gets_the_current_system_prompt(path):
    store = restart(path)
    history = store.get("s", "old prompt")
    history.append({"role": "user", "content": "hi"})
    store.save("s", history)
    after = restart(path).get("s", "new prompt")
    assert after[0] == {"role": "system", "content": "new prompt"} and after[1]["content"] == "hi"


def test_an_expired_conversation_is_not_reloaded_and_is_deleted(path):
    now = [1000.0]
    store = restart(path, ttl=60, clock=lambda: now[0])
    history = store.get("s", SYSTEM)
    history.append({"role": "user", "content": "hi"})
    store.save("s", history)
    now[0] += 61
    fresh = restart(path, ttl=60, clock=lambda: now[0])
    assert fresh.get("s", SYSTEM) == [{"role": "system", "content": SYSTEM}]
    assert fresh.db.session_count() == 0


def test_only_the_trimmed_history_is_stored(path):
    store = restart(path)
    history = store.get("s", SYSTEM)
    history += [{"role": "user", "content": f"m{i}"} for i in range(60)]
    store.save("s", history)
    stored = restart(path).get("s", SYSTEM)
    assert len(stored) == core.MAX_HISTORY_MESSAGES + 1 and stored[-1]["content"] == "m59"


def test_append_is_stored_too(path):
    store = restart(path)
    store.get("s", SYSTEM)
    store.save("s", store.get("s", SYSTEM))
    store.append("s", {"role": "user", "content": "[System note: the user pressed Confirm]"})
    assert restart(path).get("s", SYSTEM)[-1]["content"].startswith("[System note")


def test_secrets_in_tool_call_arguments_never_reach_the_disk(path):
    store = restart(path)
    history = store.get("s", SYSTEM)
    history.append({"role": "assistant", "content": "", "tool_calls": [
        {"id": "c1", "type": "function", "function": {
            "name": "change_camera_credentials", "arguments": '{"cam_id": "cam-khalid", "new_password": "hunter2"}'}}]})
    store.save("s", history)
    raw = sqlite3.connect(path).execute("SELECT body FROM messages").fetchall()
    assert "hunter2" not in json.dumps(raw)
    assert '"new_password": "***"' in raw[-1][0].replace('\\"', '"')
    assert "hunter2" in history[-1]["tool_calls"][0]["function"]["arguments"]   # memory keeps the real value


def test_a_broken_database_never_breaks_the_conversation():
    class Broken:
        def __getattr__(self, name):
            def fail(*a, **k):
                raise sqlite3.OperationalError("disk I/O error")
            return fail

    store = core.SessionStore(db=Broken())
    history = store.get("s", SYSTEM)
    history.append({"role": "user", "content": "hi"})
    store.save("s", history)
    store.append("s", {"role": "assistant", "content": "ok"})
    assert store.get("s", SYSTEM)[-1]["content"] == "ok"


# --- audit ---------------------------------------------------------------------------------
def test_the_audit_log_survives_a_restart_with_secrets_masked(path):
    log = core.AuditLog(db=Database(path))
    log.record("chat:1", "change_camera_credentials", {"cam_id": "cam-khalid", "new_password": "hunter2"}, None, "pending")
    log.record("user", "power_off", {"name_or_owner": "host-sara"}, {"new_status": "offline"}, "confirmed")

    after = core.AuditLog(db=Database(path)).list()
    assert [(e["actor"], e["tool"], e["status"]) for e in after] == [
        ("chat:1", "change_camera_credentials", "pending"), ("user", "power_off", "confirmed")]
    assert after[0]["args"]["new_password"] == "***" and after[1]["result"] == {"new_status": "offline"}
    assert "hunter2" not in open(path, "rb").read().decode("latin-1")


def test_only_the_newest_entries_are_loaded(path):
    log = core.AuditLog(db=Database(path))
    for i in range(5):
        log.record("a", "get_status", {"i": i}, None, "executed")
    assert [e["args"]["i"] for e in core.AuditLog(db=Database(path), max_entries=3).list()] == [2, 3, 4]


def test_the_old_jsonl_is_imported_once_and_left_in_place(tmp_path, path):
    old = tmp_path / "audit.jsonl"
    old.write_text("\n".join([
        json.dumps({"ts": "2026-10-01T10:00:00+0300", "actor": "user", "tool": "power_off", "args": {}, "status": "confirmed", "result": None}),
        "not json",
        json.dumps({"ts": "2026-10-01T10:05:00+0300", "actor": "user", "tool": "block_port", "args": {}, "status": "cancelled", "result": None}),
    ]) + "\n")
    first = core.AuditLog(path=old, db=Database(path))
    assert [e["tool"] for e in first.list()] == ["power_off", "block_port"]
    first.record("user", "allow_port", {}, None, "executed")
    again = core.AuditLog(path=old, db=Database(path))
    assert [e["tool"] for e in again.list()] == ["power_off", "block_port", "allow_port"]   # not imported twice
    assert old.exists() and len(old.read_text().splitlines()) == 3                          # and never rewritten


def test_if_the_database_fails_the_entry_still_goes_to_the_jsonl(tmp_path):
    class Broken:
        def audit_count(self):
            return 1

        def recent_audit(self, limit):
            return []

        def add_audit(self, entry):
            raise sqlite3.OperationalError("database is locked")

    jsonl = tmp_path / "audit.jsonl"
    core.AuditLog(path=jsonl, db=Broken()).record("u", "power_off", {}, None, "pending")
    assert json.loads(jsonl.read_text())["tool"] == "power_off"


# --- the database itself -------------------------------------------------------------------
def test_the_file_is_private_and_versioned(path):
    Database(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert sqlite3.connect(path).execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION


def test_a_database_from_a_newer_version_is_refused(path):
    Database(path).close()
    conn = sqlite3.connect(path)
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    conn.commit()
    with pytest.raises(StorageError, match="newer NetMind"):
        Database(path)


def test_open_database_falls_back_to_none_instead_of_crashing(tmp_path, capsys):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    assert open_database(blocker / "netmind.db") is None          # "logs" is a file, not a directory
    assert "will not be saved" in capsys.readouterr().out


def test_settings_know_where_the_database_lives():
    assert Settings.from_env({}).database_path.name == "netmind.db"
    assert str(Settings.from_env({"NETMIND_DB": "/tmp/x.db"}).database_path) == "/tmp/x.db"


# --- acceptance: history survives a restart, through the real API -------------------------------
def test_chat_history_survives_a_server_restart_through_the_api(monkeypatch, path):
    from fastapi.testclient import TestClient

    import web_server as ws

    scripted = [NS(content="host-ahmed is online.", tool_calls=None)]

    def create(**kwargs):
        return NS(choices=[NS(message=scripted.pop(0))])

    monkeypatch.setattr(ws, "provider", ChatCompletionsProvider(NS(chat=NS(completions=NS(create=create))), "test"))
    monkeypatch.setattr(ws, "SESSIONS", core.SessionStore(db=Database(path)))
    monkeypatch.setattr(ws, "AUDIT_LOG", core.AuditLog())
    body = TestClient(ws.app).post("/api/chat", json={"session_id": "abc", "message": "is host-ahmed up?", "mode": "simulated"}).json()
    assert body["reply"] == "host-ahmed is online."

    reborn = restart(path).get("abc:simulated", "whatever")                # a new process, same file
    assert [m["role"] for m in reborn] == ["system", "user", "assistant"]
    assert reborn[1]["content"] == "is host-ahmed up?" and reborn[2]["content"] == "host-ahmed is online."
