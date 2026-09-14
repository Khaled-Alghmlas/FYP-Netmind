# FYP-Netmind (NetMind)

An LLM-powered network operations assistant. Query and control a simulated
network (routers, switches/hubs, firewalls, hosts, IoT cameras) using natural
language — e.g. "is host-ahmed on or off?", "shut off the network on khalil",
"list all devices".

## Stack

- **Network emulation:** [Containerlab](https://containerlab.dev/) on native
  `docker-ce` inside a WSL2 Ubuntu distro (not Docker Desktop's own engine —
  see Setup notes below)
- **LLM:** Groq API (`openai/gpt-oss-120b`), tool-calling
- **Backend:** FastAPI + Docker SDK
- **Frontend:** Vanilla JS chat UI (English/Arabic)

## Repo layout

topology/
branches.py shared network layout config
generate_topology.py generates netmind-large.clab.yml from branches.py
build_registry.py generates registry.json (gitignored, machine-specific)
netmind-lab.clab.yml small first topology (1 router, 1 fw, 1 switch, 2 hosts, 1 cam)
netmind-large.clab.yml generated large topology (18 nodes / 17 links)
agent/
device_control.py find_devices, get_status, get_ip, power_on, power_off, list_devices
netmind_agent.py terminal REPL agent (Groq tool calling)
web_server.py FastAPI server + chat UI (primary interface)
web/index.html chat UI
collectors/ reserved for future Netmiko/pysnmp deep diagnostics
docker/ reserved for custom node Dockerfiles


## Setup

1. Install a **native `docker-ce`** engine inside your WSL2 Ubuntu distro
   (do *not* rely on Docker Desktop's own WSL integration — its engine
   doesn't reliably expose the network-namespace/bridge access Containerlab
   needs).
2. Install [Containerlab](https://containerlab.dev/) inside that same distro.
3. Create a Python venv and install dependencies:

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

4. Add a `.env` file (gitignored) at the repo root with:

GROQ_API_KEY=your_key_here


### Bridge segments — manual prerequisite

Containerlab's `kind: bridge` nodes (used for every switch/hub segment)
attach to a Linux bridge *interface* that must already exist on the host —
Containerlab does not create it for you. Before deploying, create one bridge
per segment:

sudo ip link add switch-branch1 type bridge && sudo ip link set switch-branch1 up
sudo ip link add hub-branch2 type bridge && sudo ip link set hub-branch2 up
sudo ip link add switch-branch3 type bridge && sudo ip link set switch-branch3 up


`generate_topology.py` prints these exact commands (based on `branches.py`)
after generating the topology YAML, so re-run it if the branch layout
changes. These bridges typically do **not** persist across a host reboot, so
you may need to re-run them after restarting WSL/the machine if `containerlab
deploy` fails to bring up a segment.

## Running the lab

cd topology
python3 generate_topology.py # (re)generates netmind-large.clab.yml

create the bridges printed above, if not already up

sudo containerlab deploy -t netmind-large.clab.yml
python3 build_registry.py # generates registry.json (gitignored)


## Running NetMind

Web UI (primary interface):

cd agent
uvicorn web_server:app --reload


Terminal agent (not actively used going forward):

cd agent
python3 netmind_agent.py


## Notes

- `registry.json` is gitignored — it contains machine-specific container
  IPs and is regenerated locally by each teammate via `build_registry.py`.
- Never commit secrets. GitHub auth uses a Personal Access Token; the Groq
  API key lives only in the local `.env` file.
