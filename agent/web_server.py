#!/usr/bin/env python3
"""FastAPI web server exposing the NetMind agent as a simple browser chat.
Supports two modes:
  - "simulated": the containerlab lab, via device_control.py (full control)
  - "real": the actual LAN this machine is on, via network_scanner.py
            (discovery + online/offline only — no power control, since we're
            just a guest on a real network, not its administrator)
"""
import json
from contextlib import asynccontextmanager
import os
import threading
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, urlencode

from dotenv import load_dotenv
from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import agent_core as core
import backends
from llm import GroqProvider
from storage import open_database
import alert_history
from settings import Settings
import device_control as dc
import network_scanner as ns
from tool_catalog import registry

load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / ".env")

settings = Settings.from_env()
provider = GroqProvider(settings.groq_api_key, settings.model)   # connects on first use, not at import

# ---------------------------------------------------------------------------
# ADDED — Telegram notifications (doctor requirement: "Send alert and
# recovery notifications outside the browser through Telegram, webhook or
# email. Include device, severity and timestamp. Acceptance: a test alert
# reaches a configured destination within the defined detection window.")
#
# Both env vars are optional — if unset, _send_telegram() silently does
# nothing, so the app behaves exactly as before for anyone who hasn't
# configured a bot. Hooked into the existing alert system (_add_alert, used
# by every device_offline/device_online/firewall_finding/camera_finding
# alert) and the real-network event log (_log_event) rather than adding a
# second, parallel notification path.
# ---------------------------------------------------------------------------
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

SEVERITY_EMOJI = {"critical": "\U0001F534", "warning": "\U0001F7E1", "info": "\U0001F7E2"}

ALERT_KIND_SEVERITY = {
    "device_online": "info",        # recovery
    "firewall_finding": "critical",  # open sensitive port / misconfiguration
    "camera_finding": "warning",     # default credentials still in use
}

PROTECTED_DEVICE_TYPES = ("firewall", "router")


def _send_telegram(text):
    """Fire-and-forget POST to the Telegram Bot API using only the stdlib
    (no new dependency to install/pin in requirements.txt). Any failure is
    logged to the console and swallowed — a notification problem should
    never break the request that triggered it."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = urlencode({"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"}).encode()
    try:
        urllib.request.urlopen(urllib.request.Request(url, data=data, method="POST"), timeout=5)
    except Exception as e:
        print(f"[telegram] failed to send notification: {e}")


def _alert_severity(alert, device_type=None):
    if alert["kind"] == "device_offline":
        return "critical" if device_type in PROTECTED_DEVICE_TYPES else "warning"
    return ALERT_KIND_SEVERITY.get(alert["kind"], "warning")


def _notify_telegram_alert(alert, device_type=None, network="Simulated Lab"):
    severity = _alert_severity(alert, device_type)
    emoji = SEVERITY_EMOJI.get(severity, "⚪")
    ts_str = datetime.fromtimestamp(alert["ts"] / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    text = (
        f"{emoji} <b>NetMind Alert</b>\n"
        f"Network: {network}\n"
        f"Device: {alert.get('device') or '-'}\n"
        f"Event: {alert['title']}\n"
        f"Severity: {severity.capitalize()}\n"
        f"Details: {alert['detail']}\n"
        f"Time: {ts_str}"
    )
    _send_telegram(text)


def _notify_telegram_event(entry, network="Real Network"):
    severity = "critical" if entry["type"] == "device_lost" else "info"
    emoji = SEVERITY_EMOJI.get(severity, "⚪")
    ts_str = datetime.fromtimestamp(entry["ts"] / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    text = (
        f"{emoji} <b>NetMind Alert</b>\n"
        f"Network: {network}\n"
        f"Device: {entry.get('device_name') or entry.get('device_id') or '-'}\n"
        f"Event: {entry['type'].replace('_', ' ').title()}\n"
        f"Severity: {severity.capitalize()}\n"
        f"Details: {entry['detail']}\n"
        f"Time: {ts_str}"
    )
    _send_telegram(text)

# ---------------------------------------------------------------------------
# Prompts. The tools themselves (schemas, risk, capability) are registered in tool_catalog.py.
# ---------------------------------------------------------------------------

SIMULATED_PROMPT = (
    "You are NetMind, a network operations assistant for a SIMULATED lab network "
    "(built with containerlab). Use the provided tools to answer questions about "
    "device status, IPs, firewalls, and cameras, and to power devices on/off. "
    "Be concise. For connectivity problems use the read-only diagnostic tools: ping_between "
    "and traceroute (does the path work, and where does it stop), get_routes (what the core "
    "router r1 knows) and get_interface_stats (errors and drops on a link). For questions about "
    "the past (\"what happened to the camera last night\", \"was host-ahmed down yesterday\") call "
    "get_alerts and read its 'now' and 'history_starts' fields: if the period asked about is "
    "before history_starts, say that nothing was recorded then instead of saying nothing happened. "
    "Tool results for power_on/power_off include an already_in_that_state "
    "field — if true, tell the user the device was already in that state and nothing "
    "changed, rather than implying an action just happened. "
    "Destructive tools (power_off, block_port, allow_port, change_camera_credentials) "
    "are NOT executed when you call them: they return status 'pending_confirmation'. "
    "To block/allow a port, power a device off, or change a camera password you MUST call "
    "the tool; never say an action is pending, queued, done or impossible unless you called "
    "the tool in this turn and its result says so. After the tool returns "
    "'pending_confirmation', tell the user what is waiting for their confirmation and that they "
    "must press Confirm in the chat; never claim the action was done until the user has confirmed."
)

# ---------------------------------------------------------------------------
# REAL network tools — discovery/status only, no power control
# ---------------------------------------------------------------------------
REAL_PROMPT = (
    "You are NetMind, a network operations assistant for a REAL local network. "
    "You can only discover devices and check whether they are online or offline — "
    "you have NO power control over real devices, because you are a guest on this "
    "network, not its administrator. If asked to turn a device on/off, politely "
    "explain that this isn't possible on a real network and offer to check its "
    "status instead. Be concise. "
    "When reporting a device list, tool results include a 'method' field "
    "('arp+ping' when both ran, or 'ping' alone), a 'count' of devices, and for "
    "each device 'found_by' (which methods saw it) and 'ipv6' (its IPv6 addresses). "
    "Always mention the method at the end of your reply as a short standalone line "
    "in the exact format 'Scan method: ARP + Ping' or 'Scan method: Ping (ARP "
    "unavailable)'. This matters because ARP results include a real MAC address "
    "(more reliable). Also state how many devices were found, from 'count'. "
    "When listing multiple devices, ALWAYS format them as a Markdown table "
    "with columns: IP Address | MAC Address | Hostname | Status | Found by (no IPv6 "
    "column: it is too wide; show the 'ipv6' addresses only if the user asks). Use '-' for "
    "any missing value (e.g. no hostname). Put the 'Scan method: ...' line "
    "after the table, not inside it."
)

COMMON_PROMPT_SUFFIX = (
    " CRITICAL: Always respond in the exact same language as the user's most recent "
    "message — if they write in English, respond only in English; if Arabic, respond "
    "only in Arabic. Never switch to any other language under any circumstances, even "
    "mid-conversation. You only handle questions about this network and its devices. "
    "If asked something unrelated (general knowledge, homework, math, or any topic "
    "with no connection to the network), politely decline and redirect the user back "
    "to network-related tasks — do not answer the unrelated question."
)

# One backend per mode. What each mode may do is enforced in backends.py (code
# level), not only by the prompt: the real-LAN backend has no power capability.
BACKENDS = {
    "simulated": backends.ContainerlabBackend(),
    "real": backends.RealLanBackend(),
}

MODES = {
    "simulated": {
        "tools": BACKENDS["simulated"].tools(),
        "dispatch": BACKENDS["simulated"].dispatch(),
        "system_prompt": SIMULATED_PROMPT + COMMON_PROMPT_SUFFIX,
    },
    "real": {
        "tools": BACKENDS["real"].tools(),
        "dispatch": BACKENDS["real"].dispatch(),
        "system_prompt": REAL_PROMPT + COMMON_PROMPT_SUFFIX,
    },
}

# Chat history per (session_id, mode) pair: in memory, saved to SQLite, with TTL + trimming.
# If the database cannot be opened DB is None and everything runs in memory, as before.
DB = open_database(settings.database_path)
SESSIONS = core.SessionStore(db=DB)

# Audit log of every tool call (in memory + SQLite; an old logs/audit.jsonl is imported once) and the safety
# guard that requires confirmation for destructive tools.
AUDIT_LOG = core.AuditLog(path=Path(__file__).resolve().parent.parent / "logs" / "audit.jsonl", db=DB)
GUARDS = {
    mode: core.Guard(MODES[mode]["dispatch"], BACKENDS[mode].resolve, AUDIT_LOG,
                     supports=BACKENDS[mode].supports)
    for mode in MODES
}

# ============================================================================
# ADDED — Logs page support.
#
# There's no persistent event store in this project (everything is
# in-memory, same as SESSIONS above — see Chapter 6 Limitations), so this
# keeps a simple in-memory, most-recent-first list of device status
# transitions for each mode, capped at MAX_LOG_ENTRIES. It is populated by
# diffing each device list against the previously seen one every time
# /api/devices or /api/real-devices is polled (the dashboard already polls
# every 5s), so it captures a status change regardless of what caused it —
# a dashboard power button, a chat command ("turn off host-ahmed"), or
# (on the real network) a device simply joining/leaving — not just explicit
# button clicks.
# ============================================================================
REAL_EVENT_LOG = []  # real-network: devices appearing/disappearing
MAX_LOG_ENTRIES = 300

_last_sim_status = {}   # device_id -> last seen status (simulated mode)
_last_real_status = {}  # device_id -> last seen status (real mode)


def _log_event(log, event_type, device_id, device_name, detail):
    entry = {
        "ts": datetime.now(timezone.utc).timestamp() * 1000,  # ms, matches the frontend's Date.now()-style timestamps
        "type": event_type,  # "power_on" | "power_off" | "status_change" | "device_seen" | "device_lost"
        "device_id": device_id,
        "device_name": device_name,
        "detail": detail,
    }
    log.insert(0, entry)
    del log[MAX_LOG_ENTRIES:]
    _notify_telegram_event(entry)  # ADDED — Telegram notification (real-network events)


ALERT_LOG = []        # simulated-mode alert history, newest first (never removed on recovery)
MAX_ALERTS = 500
ALERTS_PATH = Path(__file__).resolve().parent.parent / "logs" / "alerts.json"   # None disables saving
_alert_lock = threading.Lock()
_alert_seq = 0
_down_alert = {}      # device_id -> its still-open "offline" alert
_down_since = {}      # device_id -> ms timestamp it was first seen offline
_finding_open = {}    # (device_id, finding) -> its still-open finding alert


def _alerts_snapshot():
    with _alert_lock:
        return [dict(a) for a in ALERT_LOG]


alert_history.set_source(_alerts_snapshot)   # the get_alerts tool reads the live alert log


def _save_alerts():
    """Called with _alert_lock held. History survives restarts; saving never breaks a request."""
    if not ALERTS_PATH:
        return
    try:
        ALERTS_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = ALERTS_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(ALERT_LOG), encoding="utf-8")
        tmp.replace(ALERTS_PATH)
    except OSError:
        pass


def _load_alerts():
    """Restores saved history and the 'still open' bookkeeping, so a device that is down
    across a restart keeps its original alert and its downtime keeps counting."""
    global _alert_seq
    if not ALERTS_PATH or not Path(ALERTS_PATH).exists():
        return
    try:
        saved = json.loads(Path(ALERTS_PATH).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    ALERT_LOG[:] = [a for a in saved if isinstance(a, dict)][:MAX_ALERTS]
    _down_alert.clear()
    _down_since.clear()
    _finding_open.clear()
    for a in ALERT_LOG:
        try:
            _alert_seq = max(_alert_seq, int(str(a.get("id", "a0"))[1:]))
        except ValueError:
            pass
        if not a.get("active"):
            continue
        if a.get("kind") == "device_offline":
            _down_alert[a["device"]] = a
            _down_since[a["device"]] = a["ts"]
        elif a.get("kind") in ("firewall_finding", "camera_finding"):
            _finding_open[(a["device"], a.get("finding", ""))] = a


def _add_alert(kind, title, detail, device_id=None, device_type=None, **extra):
    global _alert_seq
    _alert_seq += 1
    alert = {"id": f"a{_alert_seq}", "kind": kind, "title": title, "detail": detail,
             "device": device_id, "ts": int(time.time() * 1000), "active": kind != "device_online"}
    alert.update(extra)
    ALERT_LOG.insert(0, alert)
    del ALERT_LOG[MAX_ALERTS:]
    _notify_telegram_alert(alert, device_type=device_type)  # ADDED — Telegram notification
    return alert


def _fmt_duration(seconds):
    seconds = int(round(seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60:02d}s"
    return f"{seconds // 3600}h {(seconds % 3600) // 60:02d}m"


def _track_alerts(did, name, old_status, new_status, device_type=None):
    """Alerts are a permanent history: going offline raises one, coming back raises
    another (with how long the device was down) and the earlier one is kept, just closed."""
    if new_status == "offline" and did not in _down_alert:
        _down_since[did] = int(time.time() * 1000)
        _down_alert[did] = _add_alert("device_offline", "Device Offline", f"{name} went offline", did, device_type=device_type)
    elif new_status == "online" and did in _down_alert:
        _down_alert.pop(did)["active"] = False
        secs = (int(time.time() * 1000) - _down_since.pop(did, int(time.time() * 1000))) / 1000
        _add_alert("device_online", "Device Back Online",
                   f"{name} is back online after {_fmt_duration(secs)}", did, device_type=device_type, down_seconds=round(secs, 1))


def _track_sim_status(devices):
    """Diffs the simulated-lab device list against what we last saw and raises/closes
    alerts on any status transition. Called on every /api/devices request."""
    with _alert_lock:
        for d in devices:
            did = d.get("id")
            name = d.get("name", did)
            new_status = d.get("status")
            old_status = _last_sim_status.get(did)
            _track_alerts(did, name, old_status, new_status, device_type=d.get("type"))
            _last_sim_status[did] = new_status
        _save_alerts()
    return devices


def _track_findings():
    current = {(dev, text): kind for dev, text, kind in dc.get_security_findings()}
    with _alert_lock:
        for key in list(_finding_open):
            if key not in current:
                _finding_open.pop(key)["active"] = False
        for (dev, text), kind in sorted(current.items()):
            if (dev, text) not in _finding_open:
                title = "Camera Finding" if kind == "camera_finding" else "Firewall Finding"
                _finding_open[(dev, text)] = _add_alert(kind, title, f"{dev}: {text}", dev, finding=text)
        _save_alerts()


def _track_real_status(devices):
    """Same idea for the real network: logs a device appearing for the first
    time in a scan, or dropping out of a scan it was previously seen in.
    Called on every /api/real-devices request."""
    seen_ids = set()
    for d in devices:
        did = d.get("id")
        if not did:
            continue
        seen_ids.add(did)
        name = d.get("name", did)
        if did not in _last_real_status:
            _log_event(REAL_EVENT_LOG, "device_seen", did, name, f"{name} ({d.get('ip', '?')}) appeared on the network")
        elif _last_real_status[did] == "lost":
            _log_event(REAL_EVENT_LOG, "device_seen", did, name, f"{name} ({d.get('ip', '?')}) reappeared on the network")
        _last_real_status[did] = d.get("status", "online")

    for did, status in list(_last_real_status.items()):
        if did not in seen_ids and status != "lost":
            _log_event(REAL_EVENT_LOG, "device_lost", did, did, f"{did} no longer responding")
            _last_real_status[did] = "lost"
    return devices

def run_query(user_input, history, tools, guard, actor, session_key, steps=None):
    """Thin wrapper binding the LLM provider + guard to agent_core.run_query."""
    return core.run_query(
        provider, user_input, history, tools,
        call_tool=lambda name, args: guard.call(name, args, actor, session_key),
        steps=steps,
    )

@asynccontextmanager
async def _lifespan(_app):
    _load_alerts()   # restore saved alert history before serving
    yield


router = APIRouter()


async def same_origin_only(request: Request, call_next):
    """The dashboard and the API are served by this one app, so no other website has any
    business calling it. A browser tags cross-site requests with an Origin header that
    differs from our own host; refuse those (this is what stops a random web page from
    powering devices off or confirming actions through the user's browser). No CORS
    headers are sent either, so other sites cannot read responses."""
    origin = request.headers.get("origin")
    if origin and origin != "null" and urlparse(origin).netloc != request.headers.get("host", ""):
        return JSONResponse({"error": "cross-origin requests are not allowed"}, status_code=403)
    if origin == "null":
        return JSONResponse({"error": "cross-origin requests are not allowed"}, status_code=403)
    return await call_next(request)

class ChatRequest(BaseModel):
    session_id: str
    message: str
    mode: str = "simulated"  # "simulated" or "real"

@router.post("/api/chat")
def chat(req: ChatRequest):
    mode = req.mode if req.mode in MODES else "simulated"
    config = MODES[mode]

    key = f"{req.session_id}:{mode}"
    history = SESSIONS.get(key, config["system_prompt"])

    # ADDED — collects the evidence chain (every tool call + its result) for
    # this turn, so the UI can show the diagnostic steps behind the reply.
    steps = []
    reply = run_query(req.message, history, config["tools"], GUARDS[mode],
                      actor=f"chat:{req.session_id}", session_key=key, steps=steps)
    SESSIONS.save(key, history)
    pending = [s["result"] for s in steps
               if isinstance(s["result"], dict) and s["result"].get("status") == "pending_confirmation"]
    return {"reply": reply, "mode": mode, "steps": steps, "pending": pending}


class ConfirmRequest(BaseModel):
    pending_id: str
    approve: bool = True
    acknowledge_protected: bool = False


@router.post("/api/confirm")
def api_confirm(req: ConfirmRequest):
    """User-side confirmation of a destructive action. Only this endpoint (never
    the model) can execute a pending action."""
    out = GUARDS["simulated"].confirm(req.pending_id, req.approve, actor="user",
                                      acknowledge_protected=req.acknowledge_protected)
    # Tell the model what happened, otherwise it keeps saying "still pending".
    key = out.pop("session_key", None)
    if key and out.get("status") in ("executed", "cancelled", "error"):
        SESSIONS.append(key, {"role": "user", "content": (
            f"[System note: the user pressed {'Cancel' if out['status'] == 'cancelled' else 'Confirm'} in the UI. "
            f"Outcome: {out['status']} - {out['summary']}. This action is no longer pending.]")})
    return out


@router.get("/api/pending")
def api_pending():
    return GUARDS["simulated"].list_pending()


ACTION_TOOLS = registry.action_names()   # every tool that is not read-only


def _who(actor):
    actor = actor or ""
    if actor.startswith("chat"):
        return "chat"
    return actor if actor in ("dashboard", "user") else "system"


def _action_trail():
    """The audit log without the read-only lookups, newest first, shaped for the Logs page."""
    out = []
    for e in reversed(AUDIT_LOG.list()):
        if e.get("tool") not in ACTION_TOOLS:
            continue
        args = e.get("args") or {}
        target = args.get("name_or_owner") or args.get("fw_id") or args.get("cam_id") or ""
        if "port" in args:
            target = f"{target} {args.get('protocol', 'tcp')}/{args['port']}"
        result = e.get("result")
        detail = ""
        if isinstance(result, dict):
            detail = result.get("summary") or result.get("error") or ""
        try:
            ts = datetime.strptime(e["ts"], "%Y-%m-%dT%H:%M:%S%z").timestamp() * 1000
        except (KeyError, ValueError):
            ts = 0
        out.append({"ts": ts, "who": _who(e.get("actor")), "actor": e.get("actor"), "tool": e["tool"],
                    "target": target.strip(), "status": e.get("status"), "detail": detail})
    return out


@router.get("/api/report")
def api_report():
    """One-page security and reliability summary for the Reports view (simulated lab)."""
    devices = dc.list_devices_dashboard()
    _track_sim_status(devices)
    _track_findings()
    with _alert_lock:
        alerts = [dict(a) for a in ALERT_LOG]
    recoveries = [a["down_seconds"] for a in alerts if a["kind"] == "device_online" and "down_seconds" in a]
    trail = _action_trail()
    outcomes = {}
    for t in trail:
        outcomes[t["status"]] = outcomes.get(t["status"], 0) + 1
    return {
        "generated": int(time.time() * 1000),
        "devices": {"total": len(devices), "online": sum(d["status"] == "online" for d in devices)},
        "findings": [{"device": a["device"], "kind": a["kind"], "finding": a.get("finding", a["detail"])}
                     for a in alerts if a["kind"] in ("firewall_finding", "camera_finding") and a["active"]],
        "reliability": {
            "outages": sum(a["kind"] == "device_offline" for a in alerts),
            "open_outages": sum(a["kind"] == "device_offline" and a["active"] for a in alerts),
            "avg_recovery_seconds": round(sum(recoveries) / len(recoveries), 1) if recoveries else None,
            "longest_recovery_seconds": max(recoveries) if recoveries else None,
        },
        "actions": {"total": len(trail), "by_status": outcomes},
    }


@router.get("/api/audit")
def api_audit():
    """Audit log of every tool call: who, what, arguments, result, when."""
    return AUDIT_LOG.list()


@router.post("/api/notify-test")
def api_notify_test():
    """ADDED — manual test button for the Telegram integration (doctor's
    acceptance criterion: 'a test alert reaches a configured destination')."""
    configured = bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)
    if configured:
        _send_telegram(
            "\U0001F514 <b>NetMind Test Alert</b>\n"
            "This is a test notification — if you can see this, Telegram "
            "alerts are configured correctly."
        )
    return {"sent": configured}

# ============================================================================
# ADDED — REST endpoints for the live web Dashboard (agent/web/Dashboard.html).
# Reuses the exact same dc./ns. functions the chat tools above already call —
# nothing here duplicates logic, and nothing above this line is touched.
# ============================================================================

class PowerRequest(BaseModel):
    state: str  # "on" or "off"


@router.get("/api/devices")
def api_devices():
    """Live device list for the Dashboard (simulated lab), from registry.json + Docker."""
    devices = dc.list_devices_dashboard()
    _track_sim_status(devices)  # ADDED — feeds the Logs page
    return devices


@router.get("/api/alerts")
def api_alerts():
    """Alert history for the Dashboard (simulated lab), newest first."""
    _track_sim_status(dc.list_devices_dashboard())
    _track_findings()
    with _alert_lock:
        return [dict(a) for a in ALERT_LOG]


@router.get("/api/logs")
def api_logs():
    """Audit trail for the Logs page (simulated lab): what was asked, by whom, and the outcome."""
    return _action_trail()


@router.post("/api/devices/{device_id}/power")
def api_power(device_id: str, req: PowerRequest):
    """Powers a simulated-lab device on/off. Power-on runs immediately; power-off
    only creates a pending action that must be confirmed via /api/confirm."""
    guard = GUARDS["simulated"]
    if req.state == "on":
        return {"result": guard.call("power_on", {"name_or_owner": device_id}, actor="dashboard")}
    if req.state == "off":
        return guard.call("power_off", {"name_or_owner": device_id}, actor="dashboard")
    return {"error": "state must be 'on' or 'off'"}


@router.get("/api/real-devices")
def api_real_devices():
    """Live devices on the real physical LAN (ARP/mDNS scan), shaped like /api/devices."""
    raw = ns.list_devices()
    items = raw.get("devices", []) if isinstance(raw, dict) else raw
    shaped = [
        {
            "id": d.get("ip"),
            "name": d.get("hostname") or d.get("ip"),
            "type": "real-device",
            "ip": d.get("ip"),
            "mac": d.get("mac"),
            "status": d.get("status", "online"),
            "found_by": d.get("found_by", []),
            "ipv6": d.get("ipv6", []),
        }
        for d in items
    ]
    _track_real_status(shaped)  # ADDED — feeds the Logs page
    return shaped


@router.get("/api/real-alerts")
def api_real_alerts():
    """Real-network mode is read-only monitoring, so no alerts yet."""
    return []


@router.get("/api/real-logs")
def api_real_logs():
    """ADDED — Device appear/disappear history for the Logs page (real network)."""
    return REAL_EVENT_LOG


def create_app():
    """Build the FastAPI application. Nothing here talks to Docker or Groq."""
    application = FastAPI(lifespan=_lifespan)
    application.middleware("http")(same_origin_only)
    application.include_router(router)
    application.mount("/", StaticFiles(directory=Path(__file__).parent / "web", html=True), name="web")
    return application


app = create_app()