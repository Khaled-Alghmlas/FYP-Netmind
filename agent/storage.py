"""SQLite storage for what must survive a restart: chat sessions (with their messages) and the audit log.

Standard library only. One connection shared by the server's threads, guarded by a lock. The file
holds chat text, so it is created readable by its owner only. A storage failure never breaks a
request: callers (agent_core) catch StorageError and carry on in memory.
"""
import json
import os
import sqlite3
import threading
from pathlib import Path

StorageError = sqlite3.Error
SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE sessions (
    key  TEXT PRIMARY KEY,
    last REAL NOT NULL
);
CREATE INDEX sessions_by_last ON sessions(last);
CREATE TABLE messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_key TEXT NOT NULL REFERENCES sessions(key) ON DELETE CASCADE,
    role        TEXT NOT NULL,
    body        TEXT NOT NULL
);
CREATE INDEX messages_by_session ON messages(session_key, id);
CREATE TABLE audit (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     TEXT NOT NULL,
    actor  TEXT,
    tool   TEXT NOT NULL,
    args   TEXT,
    status TEXT NOT NULL,
    result TEXT
);
"""


class Database:
    def __init__(self, path):
        self.path = str(path)
        in_memory = self.path == ":memory:"
        if not in_memory:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.execute("PRAGMA foreign_keys = ON")
        if not in_memory:
            self._conn.execute("PRAGMA journal_mode = WAL")
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        self._migrate()

    def _migrate(self):
        with self._lock:
            version = self._conn.execute("PRAGMA user_version").fetchone()[0]
            if version > SCHEMA_VERSION:
                raise sqlite3.DatabaseError(
                    f"{self.path} was written by a newer NetMind (schema {version}); refusing to touch it.")
            if version == 0:
                self._conn.executescript(_SCHEMA)
                self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                self._conn.commit()

    def close(self):
        with self._lock:
            self._conn.close()

    # -- sessions ------------------------------------------------------------------------
    def save_session(self, key, messages, last):
        """Replace the stored messages of a session (the history is small and already trimmed)."""
        rows = [(key, m.get("role", ""), json.dumps(m, default=str)) for m in messages]
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO sessions(key, last) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET last = excluded.last", (key, last))
            self._conn.execute("DELETE FROM messages WHERE session_key = ?", (key,))
            self._conn.executemany(
                "INSERT INTO messages(session_key, role, body) VALUES (?, ?, ?)", rows)

    def load_session(self, key):
        """-> (messages, last) or None."""
        with self._lock:
            row = self._conn.execute("SELECT last FROM sessions WHERE key = ?", (key,)).fetchone()
            if row is None:
                return None
            bodies = self._conn.execute(
                "SELECT body FROM messages WHERE session_key = ? ORDER BY id", (key,)).fetchall()
        return [json.loads(b[0]) for b in bodies], row[0]

    def delete_session(self, key):
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM sessions WHERE key = ?", (key,))

    def delete_sessions_before(self, cutoff):
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM sessions WHERE last < ?", (cutoff,))

    def session_count(self):
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]

    # -- audit ---------------------------------------------------------------------------
    def add_audit(self, entry):
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO audit(ts, actor, tool, args, status, result) VALUES (?, ?, ?, ?, ?, ?)",
                (entry.get("ts", ""), entry.get("actor"), entry.get("tool", ""),
                 json.dumps(entry.get("args"), default=str), entry.get("status", ""),
                 json.dumps(entry.get("result"), default=str)))

    def recent_audit(self, limit):
        """The newest `limit` entries, oldest first."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, actor, tool, args, status, result FROM audit ORDER BY id DESC LIMIT ?",
                (limit,)).fetchall()
        return [{"ts": ts, "actor": actor, "tool": tool, "args": json.loads(args),
                 "status": status, "result": json.loads(result)}
                for ts, actor, tool, args, status, result in reversed(rows)]

    def audit_count(self):
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0]


def open_database(path):
    """Open the database, or return None (with a warning) if it cannot be opened, so the app still
    starts - without persistence - instead of failing, e.g. when logs/ is owned by another user."""
    try:
        return Database(path)
    except (OSError, StorageError) as e:
        print(f"[storage] cannot open {path}: {e} - sessions and the audit log will not be saved")
        return None
