"""Read-only view of the alert history, for the agent's `get_alerts` tool (issue #23).

The alerts themselves are raised and stored by web_server.py (ALERT_LOG, saved to logs/alerts.json).
This module only filters them, so it needs no Docker, FastAPI or model client. web_server registers
where the alerts come from with set_source(); without it the saved file is read.

Alerts are raised by the polling that the dashboard does, so history only exists for the periods
when the dashboard (or /api/alerts) was being polled. `history_starts` in the result says where it begins.
"""
import json
from datetime import datetime
from pathlib import Path

ALERTS_FILE = Path(__file__).resolve().parent.parent / "logs" / "alerts.json"
DEFAULT_LIMIT = 20
MAX_LIMIT = 100
MAX_HOURS = 24 * 30

_source = None


def set_source(fn):
    """fn() -> list of alert dicts (newest first). Called by web_server at import time."""
    global _source
    _source = fn


def _all_alerts():
    if _source is not None:
        return list(_source())
    try:
        saved = json.loads(ALERTS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [a for a in saved if isinstance(a, dict)]


def _iso(ts_ms):
    return datetime.fromtimestamp(ts_ms / 1000).astimezone().isoformat(timespec="seconds")


def _parse_time(text):
    """ISO date or date-time (server local time unless it carries an offset) -> ms, or None."""
    try:
        dt = datetime.fromisoformat(text.strip())
    except ValueError:
        return None
    return int(dt.astimezone().timestamp() * 1000)


def filter_alerts(alerts, device="", kind="", active_only=False, since_ms=None, until_ms=None):
    """The alerts matching every given filter, order kept. `device` matches by id or part of it."""
    device, kind = device.strip().lower(), kind.strip().lower()
    out = []
    for a in alerts:
        ts = a.get("ts")
        if not isinstance(ts, (int, float)):
            continue
        if device and device not in str(a.get("device") or "").lower():
            continue
        if kind and kind != str(a.get("kind") or "").lower():
            continue
        if active_only and not a.get("active"):
            continue
        if since_ms is not None and ts < since_ms:
            continue
        if until_ms is not None and ts > until_ms:
            continue
        out.append(a)
    return out


def _as_bool(value):
    """Models sometimes send "false" or null for a boolean argument; "false" must not count as True."""
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes")
    return bool(value)


def _as_int(value, default, low, high):
    """An integer argument clamped to [low, high]; anything that is not a number gives the default."""
    try:
        return max(low, min(int(value), high))
    except (TypeError, ValueError):
        return default


def _shape(alert):
    item = {"time": _iso(alert["ts"]), "kind": alert.get("kind"), "title": alert.get("title"),
            "detail": alert.get("detail"), "device": alert.get("device"), "active": bool(alert.get("active"))}
    if "down_seconds" in alert:
        item["down_seconds"] = alert["down_seconds"]
    return item


def get_alerts(device="", kind="", active_only=False, hours_back=24, start="", end="", limit=DEFAULT_LIMIT, now_ms=None):
    """Alert history, newest first. `start`/`end` (ISO) take priority over `hours_back`."""
    import time
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    device, kind, start, end = (str(v or "") for v in (device, kind, start, end))
    limit = _as_int(limit, DEFAULT_LIMIT, 1, MAX_LIMIT)
    since_ms = until_ms = None
    for label, text in (("start", start), ("end", end)):
        if text and _parse_time(text) is None:
            return {"error": f"'{label}' must be an ISO date or date-time such as 2026-11-24 or 2026-11-24T22:00"}
    if start or end:
        since_ms = _parse_time(start) if start else None
        until_ms = _parse_time(end) if end else None
    else:
        since_ms = now_ms - _as_int(hours_back, 24, 1, MAX_HOURS) * 3_600_000
    alerts = _all_alerts()
    matching = filter_alerts(alerts, device, kind, _as_bool(active_only), since_ms, until_ms)
    stamps = [a["ts"] for a in alerts if isinstance(a.get("ts"), (int, float))]
    return {"now": _iso(now_ms), "history_starts": _iso(min(stamps)) if stamps else None,
            "total_matching": len(matching), "count": min(len(matching), limit),
            "alerts": [_shape(a) for a in matching[:limit]]}