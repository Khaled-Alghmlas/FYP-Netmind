#!/usr/bin/env python3
"""FastAPI web server exposing the NetMind agent as a simple browser chat.
Supports two modes:
  - "simulated": the containerlab lab, via device_control.py (full control)
  - "real": the actual LAN this machine is on, via network_scanner.py
            (discovery + online/offline only — no power control, since we're
            just a guest on a real network, not its administrator)
"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from groq import Groq

import device_control as dc
import network_scanner as ns

load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / ".env")

client = Groq(api_key=os.environ["GROQ_API_KEY"])
MODEL = "openai/gpt-oss-120b"

# ---------------------------------------------------------------------------
# SIMULATED (containerlab) tools — unchanged, full control
# ---------------------------------------------------------------------------
SIMULATED_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_status",
            "description": "Check whether a device (or all devices belonging to an owner) is on or off.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name_or_owner": {"type": "string", "description": "Device id (e.g. 'host-ahmed') or owner name (e.g. 'ahmed')"}
                },
                "required": ["name_or_owner"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_ip",
            "description": "Get the IP address of a device (or all devices belonging to an owner).",
            "parameters": {
                "type": "object",
                "properties": {
                    "name_or_owner": {"type": "string", "description": "Device id or owner name"}
                },
                "required": ["name_or_owner"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "power_on",
            "description": "Turn on a device or all devices belonging to an owner.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name_or_owner": {"type": "string", "description": "Device id or owner name"}
                },
                "required": ["name_or_owner"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "power_off",
            "description": "Turn off / shut down a device or all devices belonging to an owner.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name_or_owner": {"type": "string", "description": "Device id or owner name"}
                },
                "required": ["name_or_owner"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_devices",
            "description": "List every device in the network with its owner, type, and on/off status.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_devices_on_segment",
            "description": "List every device connected to a given switch or hub segment (e.g. 'switch-branch1', 'hub-branch2', 'switch-branch3'). Note: switches/hubs are plain network bridges, not controllable devices themselves.",
            "parameters": {
                "type": "object",
                "properties": {
                    "segment_id": {"type": "string", "description": "Segment name, e.g. 'switch-branch1'"}
                },
                "required": ["segment_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_firewall_rules",
            "description": "List the raw firewall rules configured on a firewall device (e.g. fw-branch1).",
            "parameters": {
                "type": "object",
                "properties": {
                    "fw_id": {"type": "string", "description": "Firewall device id, e.g. 'fw-branch1'"}
                },
                "required": ["fw_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_open_ports",
            "description": "Get which ports are currently open (allowed through) on a firewall device.",
            "parameters": {
                "type": "object",
                "properties": {
                    "fw_id": {"type": "string", "description": "Firewall device id, e.g. 'fw-branch1'"}
                },
                "required": ["fw_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "audit_firewall",
            "description": "Audit a firewall for common security issues, e.g. sensitive ports (SSH, Telnet, FTP, RDP) left open to any source.",
            "parameters": {
                "type": "object",
                "properties": {
                    "fw_id": {"type": "string", "description": "Firewall device id, e.g. 'fw-branch1'"}
                },
                "required": ["fw_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "block_port",
            "description": "Block a port on a firewall device, closing it to all traffic.",
            "parameters": {
                "type": "object",
                "properties": {
                    "fw_id": {"type": "string", "description": "Firewall device id, e.g. 'fw-branch1'"},
                    "port": {"type": "integer", "description": "Port number to block, e.g. 22"},
                    "protocol": {"type": "string", "description": "Protocol, defaults to 'tcp'"}
                },
                "required": ["fw_id", "port"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "allow_port",
            "description": "Allow a port on a firewall device, opening it to traffic.",
            "parameters": {
                "type": "object",
                "properties": {
                    "fw_id": {"type": "string", "description": "Firewall device id, e.g. 'fw-branch1'"},
                    "port": {"type": "integer", "description": "Port number to allow, e.g. 22"},
                    "protocol": {"type": "string", "description": "Protocol, defaults to 'tcp'"}
                },
                "required": ["fw_id", "port"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_camera_stream_status",
            "description": "Check whether a camera's video stream service is actually reachable and responding (separate from whether the container itself is powered on).",
            "parameters": {
                "type": "object",
                "properties": {
                    "cam_id": {"type": "string", "description": "Camera device id, e.g. 'cam-khalid'"}
                },
                "required": ["cam_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "start_camera_stream",
            "description": "Start a camera's video stream service, without affecting the container's power state.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cam_id": {"type": "string", "description": "Camera device id, e.g. 'cam-khalid'"}
                },
                "required": ["cam_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "stop_camera_stream",
            "description": "Stop a camera's video stream service, without powering off the container.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cam_id": {"type": "string", "description": "Camera device id, e.g. 'cam-khalid'"}
                },
                "required": ["cam_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_camera_credentials",
            "description": "Check whether a camera is still using its default (weak) password.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cam_id": {"type": "string", "description": "Camera device id, e.g. 'cam-khalid'"}
                },
                "required": ["cam_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "change_camera_credentials",
            "description": "Change a camera's password away from the default.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cam_id": {"type": "string", "description": "Camera device id, e.g. 'cam-khalid'"},
                    "new_password": {"type": "string", "description": "New password to set"}
                },
                "required": ["cam_id", "new_password"],
            },
        },
    },
]

SIMULATED_DISPATCH = {
    "get_status": dc.get_status,
    "get_ip": dc.get_ip,
    "power_on": dc.power_on,
    "power_off": dc.power_off,
    "list_devices": dc.list_devices,
    "list_devices_on_segment": dc.list_devices_on_segment,
    "list_firewall_rules": dc.list_firewall_rules,
    "get_open_ports": dc.get_open_ports,
    "audit_firewall": dc.audit_firewall,
    "block_port": dc.block_port,
    "allow_port": dc.allow_port,
    "get_camera_stream_status": dc.get_camera_stream_status,
    "start_camera_stream": dc.start_camera_stream,
    "stop_camera_stream": dc.stop_camera_stream,
    "check_camera_credentials": dc.check_camera_credentials,
    "change_camera_credentials": dc.change_camera_credentials,
}

SIMULATED_PROMPT = (
    "You are NetMind, a network operations assistant for a SIMULATED lab network "
    "(built with containerlab). Use the provided tools to answer questions about "
    "device status, IPs, firewalls, and cameras, and to power devices on/off. "
    "Be concise. Tool results for power_on/power_off include an already_in_that_state "
    "field — if true, tell the user the device was already in that state and nothing "
    "changed, rather than implying an action just happened."
)

# ---------------------------------------------------------------------------
# REAL network tools — discovery/status only, no power control
# ---------------------------------------------------------------------------
REAL_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "list_devices",
            "description": "Scan the real local network and list every device currently online, with its IP and MAC address.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_status",
            "description": "Check whether a specific real device (by IP or hostname) is currently online or offline.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name_or_owner": {"type": "string", "description": "IP address or hostname of the device"}
                },
                "required": ["name_or_owner"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_ip",
            "description": "Resolve the IP address of a real device by hostname.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name_or_owner": {"type": "string", "description": "Hostname to resolve"}
                },
                "required": ["name_or_owner"],
            },
        },
    },
]

REAL_DISPATCH = {
    "list_devices": lambda: ns.list_devices(),
    "get_status": lambda name_or_owner: ns.get_status(name_or_owner),
    "get_ip": lambda name_or_owner: ns.get_ip(name_or_owner),
}

REAL_PROMPT = (
    "You are NetMind, a network operations assistant for a REAL local network. "
    "You can only discover devices and check whether they are online or offline — "
    "you have NO power control over real devices, because you are a guest on this "
    "network, not its administrator. If asked to turn a device on/off, politely "
    "explain that this isn't possible on a real network and offer to check its "
    "status instead. Be concise. "
    "When reporting a device list, tool results include a 'method' field "
    "('arp' or 'ping') indicating how the scan was performed — always mention "
    "this at the end of your reply as a short standalone line in the exact "
    "format 'Scan method: ARP' or 'Scan method: Ping (ARP unavailable)'. "
    "This matters because ARP results include a real MAC address (more "
    "reliable), while ping-only results don't. "
    "When listing multiple devices, ALWAYS format them as a Markdown table "
    "with columns: IP Address | MAC Address | Hostname | Status. Use '-' for "
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

MODES = {
    "simulated": {
        "tools": SIMULATED_TOOLS,
        "dispatch": SIMULATED_DISPATCH,
        "system_prompt": SIMULATED_PROMPT + COMMON_PROMPT_SUFFIX,
    },
    "real": {
        "tools": REAL_TOOLS,
        "dispatch": REAL_DISPATCH,
        "system_prompt": REAL_PROMPT + COMMON_PROMPT_SUFFIX,
    },
}

# In-memory chat history per (session_id, mode) pair
SESSIONS = {}

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
EVENT_LOG = []       # simulated-mode: power on/off + status changes
REAL_EVENT_LOG = []  # real-network: devices appearing/disappearing
MAX_LOG_ENTRIES = 300

_last_sim_status = {}   # device_id -> last seen status (simulated mode)
_last_real_status = {}  # device_id -> last seen status (real mode)


def _log_event(log, event_type, device_id, device_name, detail):
    log.insert(0, {
        "ts": datetime.now(timezone.utc).timestamp() * 1000,  # ms, matches the frontend's Date.now()-style timestamps
        "type": event_type,  # "power_on" | "power_off" | "status_change" | "device_seen" | "device_lost"
        "device_id": device_id,
        "device_name": device_name,
        "detail": detail,
    })
    del log[MAX_LOG_ENTRIES:]


def _track_sim_status(devices):
    """Diffs the simulated-lab device list against what we last saw and logs
    any status transition. Called on every /api/devices request."""
    for d in devices:
        did = d.get("id")
        name = d.get("name", did)
        new_status = d.get("status")
        old_status = _last_sim_status.get(did)
        if old_status is not None and old_status != new_status:
            if new_status == "online":
                event_type = "power_on"
            elif new_status == "offline":
                event_type = "power_off"
            else:
                event_type = "status_change"
            _log_event(EVENT_LOG, event_type, did, name, f"{name}: {old_status} → {new_status}")
        _last_sim_status[did] = new_status
    return devices


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

def run_query(user_input, history, tools, dispatch, steps=None):
    # `steps` is OPTIONAL and additive: when the caller passes a list, every
    # executed tool call (the "evidence chain") is recorded into it as
    # {"tool": ..., "args": ..., "result": ...}. Nothing about the existing
    # control flow or return value changes — a caller that doesn't pass
    # `steps` sees identical behavior to before.
    history.append({"role": "user", "content": user_input})

    for _ in range(5):
        try:
            response = client.chat.completions.create(
                model=MODEL,
                messages=history,
                tools=tools,
                tool_choice="auto",
            )
        except Exception as e:
            return f"Sorry, I hit an error talking to the model: {e}"
        msg = response.choices[0].message
        history.append(msg)

        if not msg.tool_calls:
            return msg.content

        for call in msg.tool_calls:
            fn_name = call.function.name
            args = json.loads(call.function.arguments) if call.function.arguments else {}
            try:
                result = dispatch[fn_name](**args)
            except Exception as e:
                result = {"error": str(e)}
            history.append({
                "role": "tool",
                "tool_call_id": call.id,
                "content": json.dumps(result),
            })
            if steps is not None:
                steps.append({"tool": fn_name, "args": args, "result": result})

    return "Sorry, I couldn't complete that after several tool calls."

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class ChatRequest(BaseModel):
    session_id: str
    message: str
    mode: str = "simulated"  # "simulated" or "real"

@app.post("/api/chat")
def chat(req: ChatRequest):
    mode = req.mode if req.mode in MODES else "simulated"
    config = MODES[mode]

    key = f"{req.session_id}:{mode}"
    history = SESSIONS.setdefault(key, [{"role": "system", "content": config["system_prompt"]}])

    # ADDED — collects the evidence chain (every tool call + its result) for
    # this turn, so the UI can show the diagnostic steps behind the reply.
    steps = []
    reply = run_query(user_input=req.message, history=history, tools=config["tools"], dispatch=config["dispatch"], steps=steps)
    return {"reply": reply, "mode": mode, "steps": steps}

# ============================================================================
# ADDED — REST endpoints for the live web Dashboard (agent/web/Dashboard.html).
# Reuses the exact same dc./ns. functions the chat tools above already call —
# nothing here duplicates logic, and nothing above this line is touched.
# ============================================================================

class PowerRequest(BaseModel):
    state: str  # "on" or "off"


@app.get("/api/devices")
def api_devices():
    """Live device list for the Dashboard (simulated lab), from registry.json + Docker."""
    devices = dc.list_devices_dashboard()
    _track_sim_status(devices)  # ADDED — feeds the Logs page
    return devices


@app.get("/api/alerts")
def api_alerts():
    """Live alerts for the Dashboard (simulated lab)."""
    return dc.get_alerts()


@app.get("/api/logs")
def api_logs():
    """ADDED — Device power/status history for the Logs page (simulated lab)."""
    return EVENT_LOG


@app.post("/api/devices/{device_id}/power")
def api_power(device_id: str, req: PowerRequest):
    """Powers a simulated-lab device on/off — same functions the chat uses."""
    if req.state == "on":
        result = dc.power_on(device_id)
    elif req.state == "off":
        result = dc.power_off(device_id)
    else:
        return {"error": "state must be 'on' or 'off'"}
    return {"result": result}


@app.get("/api/real-devices")
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
            "cpu": 0,
            "traffic": 0,
        }
        for d in items
    ]
    _track_real_status(shaped)  # ADDED — feeds the Logs page
    return shaped


@app.get("/api/real-alerts")
def api_real_alerts():
    """Real-network mode is read-only monitoring, so no alerts yet."""
    return []


@app.get("/api/real-logs")
def api_real_logs():
    """ADDED — Device appear/disappear history for the Logs page (real network)."""
    return REAL_EVENT_LOG


app.mount("/", StaticFiles(directory=Path(__file__).parent / "web", html=True), name="web")