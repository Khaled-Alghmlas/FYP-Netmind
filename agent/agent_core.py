"""Core of the NetMind agent: the tool-calling loop, session storage, the
safety guard (confirmation + protected devices) and the audit log.

Deliberately free of FastAPI / Groq / Docker imports so it can be unit-tested
without a lab or an API key. web_server.py wires the real client and the real
device functions into it.
"""
import json
import threading
import time
import uuid
from collections import deque
from pathlib import Path

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
MAX_ROUNDS = 5
SESSION_TTL_SECONDS = 2 * 60 * 60      # drop sessions idle for 2 hours
MAX_HISTORY_MESSAGES = 40              # system prompt + the most recent N messages
MAX_SESSIONS = 200                     # hard cap so memory cannot grow without bound
PENDING_TTL_SECONDS = 5 * 60           # a confirmation request expires after 5 minutes

# Tools that change state and therefore need explicit user confirmation.
# Maps tool name -> name of the argument that identifies the target device(s).
DESTRUCTIVE_TOOLS = {
    "power_off": "name_or_owner",
    "block_port": "fw_id",
    "allow_port": "fw_id",
    "change_camera_credentials": "cam_id",
}

# Device ids that are always protected, in addition to every device whose
# registry type is "firewall" or "router".
PROTECTED_IDS = {"r1"}
PROTECTED_TYPES = {"firewall", "router"}

# Arguments that must never be written to the audit log in clear text.
SENSITIVE_ARGS = {"new_password"}


# ---------------------------------------------------------------------------
# Messages / sessions
# ---------------------------------------------------------------------------
def msg_to_dict(msg):
    """Convert an SDK assistant message into a plain, JSON-serialisable dict."""
    d = {"role": "assistant", "content": getattr(msg, "content", None) or ""}
    tool_calls = getattr(msg, "tool_calls", None)
    if tool_calls:
        d["tool_calls"] = [
            {
                "id": c.id,
                "type": "function",
                "function": {"name": c.function.name, "arguments": c.function.arguments or "{}"},
            }
            for c in tool_calls
        ]
    return d


def trim_history(history, max_messages=MAX_HISTORY_MESSAGES):
    """Keep the system prompt plus the newest messages. The kept tail never
    starts with an orphaned 'tool' message (the API rejects those)."""
    if len(history) <= max_messages + 1:
        return history
    system, rest = history[:1], history[1:]
    tail = rest[-max_messages:]
    while tail and tail[0].get("role") == "tool":
        tail = tail[1:]
    return system + tail


class SessionStore:
    """In-memory chat histories with a TTL and a size cap."""

    def __init__(self, ttl=SESSION_TTL_SECONDS, max_sessions=MAX_SESSIONS, clock=time.time):
        self._data = {}          # key -> {"history": [...], "last": ts}
        self._lock = threading.Lock()
        self.ttl = ttl
        self.max_sessions = max_sessions
        self._clock = clock

    def get(self, key, system_prompt):
        now = self._clock()
        with self._lock:
            self._prune(now)
            entry = self._data.get(key)
            if entry is None:
                entry = {"history": [{"role": "system", "content": system_prompt}], "last": now}
                self._data[key] = entry
            entry["last"] = now
            return entry["history"]

    def save(self, key, history):
        with self._lock:
            if key in self._data:
                self._data[key]["history"][:] = trim_history(history)

    def append(self, key, message):
        """Add a message to an existing session (no-op if it has expired)."""
        with self._lock:
            if key in self._data:
                self._data[key]["history"].append(message)

    def _prune(self, now):
        expired = [k for k, v in self._data.items() if now - v["last"] > self.ttl]
        for k in expired:
            del self._data[k]
        if len(self._data) >= self.max_sessions:
            oldest = sorted(self._data, key=lambda k: self._data[k]["last"])
            for k in oldest[: len(self._data) - self.max_sessions + 1]:
                del self._data[k]

    def __len__(self):
        return len(self._data)


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------
def _redact(args):
    if not isinstance(args, dict):
        return args
    return {k: ("***" if k in SENSITIVE_ARGS else v) for k, v in args.items()}


class AuditLog:
    """Records every tool call: who, what, arguments, result, when.
    Kept in memory (for the API) and appended to a JSONL file (for evidence)."""

    def __init__(self, path=None, max_entries=1000):
        self.path = Path(path) if path else None
        self.entries = deque(maxlen=max_entries)
        self._lock = threading.Lock()

    def record(self, actor, tool, args, result, status):
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "actor": actor,
            "tool": tool,
            "args": _redact(args),
            "status": status,   # executed | error | pending | confirmed | cancelled | denied | expired
            "result": result,
        }
        with self._lock:
            self.entries.append(entry)
            if self.path:
                try:
                    self.path.parent.mkdir(parents=True, exist_ok=True)
                    with open(self.path, "a", encoding="utf-8") as f:
                        f.write(json.dumps(entry, default=str) + "\n")
                except OSError:
                    pass  # never let logging break the request
        return entry

    def list(self):
        with self._lock:
            return list(self.entries)


# ---------------------------------------------------------------------------
# Safety guard: confirmation + protected devices
# ---------------------------------------------------------------------------
class Guard:
    """Sits between the model and the device functions.

    Read-only tools run immediately. Destructive tools are NOT executed when
    the model asks for them: a pending action is created and returned instead,
    and only an explicit confirm() from the user (via the UI / REST API, never
    via the model) runs it."""

    def __init__(self, dispatch, resolver, audit, clock=time.time):
        self.dispatch = dispatch      # tool name -> callable
        self.resolver = resolver      # name_or_owner -> [device dicts]
        self.audit = audit
        self._pending = {}
        self._lock = threading.Lock()
        self._clock = clock

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def is_protected(device):
        return device.get("id") in PROTECTED_IDS or device.get("type") in PROTECTED_TYPES

    def _targets(self, tool, args):
        arg_name = DESTRUCTIVE_TOOLS[tool]
        value = args.get(arg_name)
        if not isinstance(value, str) or not value.strip():
            return []
        return self.resolver(value) or []

    @staticmethod
    def _summary(tool, args, targets):
        ids = ", ".join(t["id"] for t in targets)
        if tool == "power_off":
            return f"Power off: {ids}"
        if tool in ("block_port", "allow_port"):
            verb = "Block" if tool == "block_port" else "Allow"
            return f"{verb} {args.get('protocol', 'tcp')}/{args.get('port')} on firewall {ids} (INPUT and FORWARD)"
        if tool == "change_camera_credentials":
            return f"Change the password of camera {ids}"
        return f"{tool} on {ids}"

    def _expire(self):
        now = self._clock()
        for pid in [p for p, a in self._pending.items() if now - a["created"] > PENDING_TTL_SECONDS]:
            a = self._pending.pop(pid)
            self.audit.record(a["actor"], a["tool"], a["args"], None, "expired")

    # -- model-facing ------------------------------------------------------
    def call(self, tool, args, actor, session_key=None):
        """Called for every tool call the model makes."""
        fn = self.dispatch.get(tool)
        if fn is None:
            result = {"error": f"Unknown tool '{tool}'."}
            self.audit.record(actor, tool, args, result, "error")
            return result

        if tool not in DESTRUCTIVE_TOOLS:
            return self._execute(fn, tool, args, actor, "executed")

        targets = self._targets(tool, args)
        if not targets:
            result = {"error": f"No device matches '{args.get(DESTRUCTIVE_TOOLS[tool])}'. Nothing was changed."}
            self.audit.record(actor, tool, args, result, "denied")
            return result

        return self.request(tool, args, actor, session_key, targets)

    def request(self, tool, args, actor, session_key=None, targets=None):
        """Create a pending action (also used directly by the dashboard)."""
        if targets is None:
            targets = self._targets(tool, args)
        protected = [t["id"] for t in targets if self.is_protected(t)]
        pid = uuid.uuid4().hex[:12]
        pending = {
            "pending_id": pid,
            "tool": tool,
            "args": args,
            "targets": [t["id"] for t in targets],
            "protected": protected,
            "summary": self._summary(tool, args, targets),
            "session_key": session_key,
            "actor": actor,
            "created": self._clock(),
        }
        with self._lock:
            self._expire()
            self._pending[pid] = pending
        self.audit.record(actor, tool, args, {"pending_id": pid, "summary": pending["summary"]}, "pending")
        return self.public(pending)

    @staticmethod
    def public(p):
        return {
            "status": "pending_confirmation",
            "executed": False,
            "pending_id": p["pending_id"],
            "tool": p["tool"],
            "summary": p["summary"],
            "targets": p["targets"],
            "protected": p["protected"],
            "requires_protected_ack": bool(p["protected"]),
            "message": "NOT executed yet. The user must confirm this action in the UI.",
        }

    # -- user-facing -------------------------------------------------------
    def list_pending(self, session_key=None):
        with self._lock:
            self._expire()
            return [self.public(p) for p in self._pending.values()
                    if session_key is None or p["session_key"] == session_key]

    def confirm(self, pending_id, approve, actor, acknowledge_protected=False):
        with self._lock:
            self._expire()
            p = self._pending.get(pending_id)
            if p is None:
                return {"error": "Unknown or expired pending action."}
            if approve and p["protected"] and not acknowledge_protected:
                return {"error": "This action touches protected device(s) "
                                 f"({', '.join(p['protected'])}); explicit acknowledgement is required.",
                        "requires_protected_ack": True}
            del self._pending[pending_id]

        if not approve:
            self.audit.record(actor, p["tool"], p["args"], None, "cancelled")
            return {"status": "cancelled", "summary": p["summary"], "session_key": p["session_key"]}

        result = self._execute(self.dispatch[p["tool"]], p["tool"], p["args"], actor, "confirmed")
        return {"status": "error" if isinstance(result, dict) and "error" in result else "executed",
                "summary": p["summary"], "result": result, "session_key": p["session_key"]}

    def _execute(self, fn, tool, args, actor, ok_status):
        try:
            result = fn(**args)
        except Exception as e:  # noqa: BLE001 - tool failures are reported to the model
            result = {"error": str(e)}
            self.audit.record(actor, tool, args, result, "error")
            return result
        self.audit.record(actor, tool, args, result, ok_status)
        return result


# ---------------------------------------------------------------------------
# The tool-calling loop
# ---------------------------------------------------------------------------
def _parse_args(raw):
    """Return (args_dict, error_message). Never raises."""
    if not raw:
        return {}, None
    try:
        args = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as e:
        return {}, f"Malformed JSON in tool arguments: {e}"
    if not isinstance(args, dict):
        return {}, "Tool arguments must be a JSON object."
    return args, None


def _brief(result, limit=160):
    text = json.dumps(result, default=str)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def partial_summary(steps, rounds):
    lines = [f"I reached the limit of {rounds} tool-call rounds before I could finish. "
             "Here is what I gathered so far:"]
    for s in steps:
        lines.append(f"- {s['tool']}({json.dumps(s['args'], default=str)}) → {_brief(s['result'])}")
    lines.append("Ask me to continue, or narrow the request, and I will pick up from here.")
    return "\n".join(lines)


def run_query(client, model, user_input, history, tools, call_tool, steps=None,
              max_rounds=MAX_ROUNDS):
    """Run one user turn.

    call_tool(name, args) -> result executes (or guards) a tool call.
    `steps`, when given, receives every executed call as {"tool","args","result"}.
    Always returns a string; never raises on bad model output.
    """
    history.append({"role": "user", "content": user_input})
    turn_steps = []

    for _ in range(max_rounds):
        try:
            response = client.chat.completions.create(
                model=model, messages=history, tools=tools, tool_choice="auto",
            )
        except Exception as e:  # noqa: BLE001
            return f"Sorry, I hit an error talking to the model: {e}"

        msg = response.choices[0].message
        history.append(msg_to_dict(msg))

        if not msg.tool_calls:
            return msg.content or ""

        for call in msg.tool_calls:
            fn_name = call.function.name
            args, err = _parse_args(call.function.arguments)
            if err:
                result = {"error": f"{err} (tool '{fn_name}'). Please retry with valid JSON arguments."}
            else:
                try:
                    result = call_tool(fn_name, args)
                except Exception as e:  # noqa: BLE001
                    result = {"error": str(e)}
            history.append({
                "role": "tool",
                "tool_call_id": call.id,
                "content": json.dumps(result, default=str),
            })
            record = {"tool": fn_name, "args": args, "result": result}
            turn_steps.append(record)
            if steps is not None:
                steps.append(record)

    reply = partial_summary(turn_steps, max_rounds)
    history.append({"role": "assistant", "content": reply})
    return reply
