#!/usr/bin/env python3
"""NetMind interactive agent — natural language network control via Groq function calling."""
import json
import os
from pathlib import Path

from dotenv import load_dotenv
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

def run_query(user_input, history):
    history.append({"role": "user", "content": user_input})

    for _ in range(5):  # cap rounds to avoid infinite loops
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

def main():
    print("NetMind agent ready. Type a command (or 'exit').")
    history = [{"role": "system", "content": "You are NetMind, a network operations assistant. Use the provided tools to answer questions about device status, IPs, and to power devices on/off. Be concise."}]
    while True:
        user_input = input("\n> ")
        if user_input.strip().lower() in ("exit", "quit"):
            break
        print(run_query(user_input, history))

if __name__ == "__main__":
    main()
