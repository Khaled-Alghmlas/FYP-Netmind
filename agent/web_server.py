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
]

DISPATCH = {
    "get_status": dc.get_status,
    "get_ip": dc.get_ip,
    "power_on": dc.power_on,
    "power_off": dc.power_off,
    "list_devices": dc.list_devices,
}

SYSTEM_PROMPT = {
    "role": "system",
    "content": "You are NetMind, a network operations assistant. Use the provided tools to answer questions about device status, IPs, and to power devices on/off. Be concise. Reply in the same language the user used."
}

# In-memory chat history per browser session
SESSIONS = {}

def run_query(user_input, history):
    history.append({"role": "user", "content": user_input})

    for _ in range(5):
        response = client.chat.completions.create(
            model=MODEL,
            messages=history,
            tools=TOOLS,
            tool_choice="auto",
        )
        msg = response.choices[0].message
        history.append(msg)

        if not msg.tool_calls:
            return msg.content

        for call in msg.tool_calls:
            fn_name = call.function.name
            args = json.loads(call.function.arguments) if call.function.arguments else {}
            result = DISPATCH[fn_name](**args)
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