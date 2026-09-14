#!/usr/bin/env python3
"""FastAPI web server exposing the NetMind agent as a simple browser chat."""
import json
import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from groq import Groq

import device_control as dc

load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / ".env")

client = Groq(api_key=os.environ["GROQ_API_KEY"])
MODEL = "openai/gpt-oss-120b"

TOOLS = [
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

DISPATCH = {
    "get_status": dc.get_status,
    "get_ip": dc.get_ip,
    "power_on": dc.power_on,
    "power_off": dc.power_off,
    "list_devices": dc.list_devices,
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

SYSTEM_PROMPT = {
    "role": "system",
    "content": "You are NetMind, a network operations assistant. Use the provided tools to answer questions about device status, IPs, and to power devices on/off. Be concise. CRITICAL: Always respond in the exact same language as the user's most recent message — if they write in English, respond only in English; if Arabic, respond only in Arabic. Never switch to any other language under any circumstances, even mid-conversation. Tool results for power_on/power_off include an already_in_that_state field — if true, tell the user the device was already in that state and nothing changed, rather than implying an action just happened. You only handle questions about this network and its devices. If asked something unrelated (general knowledge, homework, math, or any topic with no connection to the network), politely decline and redirect the user back to network-related tasks — do not answer the unrelated question."
}

# In-memory chat history per browser session
SESSIONS = {}

def run_query(user_input, history):
    history.append({"role": "user", "content": user_input})

    for _ in range(5):
        try:
            response = client.chat.completions.create(
                model=MODEL,
                messages=history,
                tools=TOOLS,
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
                result = DISPATCH[fn_name](**args)
            except Exception as e:
                result = {"error": str(e)}
            history.append({
                "role": "tool",
                "tool_call_id": call.id,
                "content": json.dumps(result),
            })

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

@app.post("/api/chat")
def chat(req: ChatRequest):
    history = SESSIONS.setdefault(req.session_id, [dict(SYSTEM_PROMPT)])
    reply = run_query(req.message, history)
    return {"reply": reply}

app.mount("/", StaticFiles(directory=Path(__file__).parent / "web", html=True), name="web")
