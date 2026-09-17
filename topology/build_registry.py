#!/usr/bin/env python3
"""Builds registry.json: maps device names/owners to real runtime IPs and metadata.
Combines branches.py (our network design) with `containerlab inspect` (live IPs).
'ip' is always the management IP (eth0, used by NetMind's own Docker-based
tools). 'network_ip' is the device's address on the actual simulated network
(eth1, from branches.py's compute_addressing()) - not yet used by any
NetMind tool, but recorded for future features (e.g. a real ping-between-hosts
tool) that need to operate on the real topology rather than the management
network."""
import json
import subprocess
from branches import BRANCHES, compute_addressing

TOPOLOGY_FILE = "netmind-large.clab.yml"
LAB_NAME = "netmind-large"

def get_live_containers():
    result = subprocess.run(
        ["containerlab", "inspect", "-t", TOPOLOGY_FILE, "--format", "json"],
        capture_output=True, text=True, check=True
    )
    data = json.loads(result.stdout)
    containers = data[LAB_NAME]
    prefix = f"clab-{LAB_NAME}-"
    return {
        c["name"][len(prefix):]: c
        for c in containers
        if c["name"].startswith(prefix)
    }

def main():
    live = get_live_containers()
    addressing = compute_addressing()
    devices = []
    missing = []

    for idx, b in enumerate(BRANCHES, start=1):
        branch = b["name"]
        segment = f"{b['segment_type']}-{branch}"
        fw_node = f"fw-{branch}"

        if fw_node in live:
            devices.append({
                "id": fw_node,
                "owner": None,
                "type": "firewall",
                "branch": branch,
                "segment": segment,
                "container": live[fw_node]["name"],
                "ip": live[fw_node]["ipv4_address"].split("/")[0],
                "network_ip": addressing["firewalls"][fw_node]["lan_ip"],
            })
        else:
            missing.append(fw_node)

        for owner in b["owners"]:
            node = f"host-{owner}"
            if node in live:
                devices.append({
                    "id": node,
                    "owner": owner,
                    "type": "host",
                    "branch": branch,
                    "segment": segment,
                    "container": live[node]["name"],
                    "ip": live[node]["ipv4_address"].split("/")[0],
                    "network_ip": addressing["devices"].get(node),
                })
            else:
                missing.append(node)

        for owner in b["cameras"]:
            node = f"cam-{owner}"
            if node in live:
                devices.append({
                    "id": node,
                    "owner": owner,
                    "type": "camera",
                    "branch": branch,
                    "segment": segment,
                    "container": live[node]["name"],
                    "ip": live[node]["ipv4_address"].split("/")[0],
                    "network_ip": addressing["devices"].get(node),
                })
            else:
                missing.append(node)

    if "r1" in live:
        devices.append({
            "id": "r1", "owner": None, "type": "router", "branch": None,
            "segment": None, "container": live["r1"]["name"],
            "ip": live["r1"]["ipv4_address"].split("/")[0],
            "network_ip": None,
        })
    else:
        missing.append("r1")

    with open("registry.json", "w") as f:
        json.dump({"devices": devices}, f, indent=2)

    print(f"Wrote {len(devices)} devices to registry.json")

    if missing:
        print(f"\nWARNING: {len(missing)} expected device(s) not found in live "
              f"`containerlab inspect` output — they were skipped and will NOT "
              f"appear in registry.json (NetMind won't be able to control them):")
        for node_id in missing:
            print(f"  - {node_id}")
        print("Check `containerlab deploy` output / `docker ps -a` for these nodes.")

if __name__ == "__main__":
    main()
