#!/usr/bin/env python3
"""Generates a Containerlab topology YAML for the NetMind lab network.
Addressing plan lives in branches.py's compute_addressing() - single source
of truth shared with build_registry.py, so they can never drift apart."""
import argparse
import os
import subprocess
import sys
import yaml
from branches import CORE_ROUTER, ALPINE_IMAGE, FRR_IMAGE, FIREWALL_IMAGE, CAMERA_IMAGE, BRANCHES, compute_addressing

addressing = compute_addressing()

nodes = {CORE_ROUTER: {"kind": "linux", "image": FRR_IMAGE, "exec": ["sysctl -w net.ipv4.ip_forward=1"]}}
links = []
bridges_to_create = []

router_port = 1
for idx, b in enumerate(BRANCHES, start=1):
    fw = f"fw-{b['name']}"
    seg = f"{b['segment_type']}-{b['name']}"
    fw_addr = addressing["firewalls"][fw]
    r1_ip = fw_addr["r1_ip"]
    fw_wan_ip = fw_addr["wan_ip"]
    fw_lan_ip = fw_addr["lan_ip"]
    branch_net_cidr = fw_addr["branch_net"]

    nodes[CORE_ROUTER]["exec"].append(f"ip addr add {r1_ip}/30 dev eth{router_port}")
    nodes[CORE_ROUTER]["exec"].append(f"ip route add {branch_net_cidr} via {fw_wan_ip} dev eth{router_port}")

    nodes[fw] = {
        "kind": "linux",
        "image": FIREWALL_IMAGE,
        "exec": [
            "sysctl -w net.ipv4.ip_forward=1",
            f"ip addr add {fw_wan_ip}/30 dev eth1",
            f"ip addr add {fw_lan_ip}/24 dev eth2",
            f"ip route add 10.0.0.0/8 via {r1_ip} dev eth1",
        ],
    }
    nodes[seg] = {"kind": "bridge"}
    bridges_to_create.append(seg)

    links.append({"endpoints": [f"{CORE_ROUTER}:eth{router_port}", f"{fw}:eth1"]})
    router_port += 1
    links.append({"endpoints": [f"{fw}:eth2", f"{seg}:b{idx}p1"]})

    seg_port = 2
    for owner in b["owners"]:
        host = f"host-{owner}"
        host_ip = addressing["devices"][host]
        nodes[host] = {
            "kind": "linux",
            "image": ALPINE_IMAGE,
            "exec": [
                f"ip addr add {host_ip}/24 dev eth1",
                f"ip route add 10.0.0.0/8 via {fw_lan_ip} dev eth1",
            ],
        }
        links.append({"endpoints": [f"{seg}:b{idx}p{seg_port}", f"{host}:eth1"]})
        seg_port += 1

    for owner in b["cameras"]:
        cam = f"cam-{owner}"
        cam_ip = addressing["devices"][cam]
        nodes[cam] = {
            "kind": "linux",
            "image": CAMERA_IMAGE,
            "exec": [
                f"ip addr add {cam_ip}/24 dev eth1",
                f"ip route add 10.0.0.0/8 via {fw_lan_ip} dev eth1",
            ],
        }
        links.append({"endpoints": [f"{seg}:b{idx}p{seg_port}", f"{cam}:eth1"]})
        seg_port += 1

topology = {"name": "netmind-large", "topology": {"nodes": nodes, "links": links}}

with open("netmind-large.clab.yml", "w") as f:
    yaml.dump(topology, f, sort_keys=False, default_flow_style=False)

print(f"Generated {len(nodes)} nodes, {len(links)} links -> netmind-large.clab.yml")


def _sh(cmd, check=True):
    """Run a host command, using sudo when not root."""
    if os.geteuid() != 0:
        cmd = ["sudo"] + cmd
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def ensure_bridge(name):
    """Create the Linux bridge if it does not exist and bring it up. Idempotent."""
    exists = subprocess.run(["ip", "link", "show", name], capture_output=True).returncode == 0
    if not exists:
        _sh(["ip", "link", "add", name, "type", "bridge"])
        print(f"  created bridge {name}")
    else:
        print(f"  bridge {name} already exists")
    _sh(["ip", "link", "set", name, "up"])


def ensure_forward_rule(flag, bridge):
    """Add `iptables -I FORWARD <flag> <bridge> -j ACCEPT` only if missing. Idempotent."""
    rule = ["FORWARD", flag, bridge, "-j", "ACCEPT"]
    if _sh(["iptables", "-C"] + rule, check=False).returncode != 0:
        _sh(["iptables", "-I"] + rule)


def create_bridges():
    print("\nEnsuring host bridges and FORWARD rules (idempotent):")
    for br in bridges_to_create:
        ensure_bridge(br)
        ensure_forward_rule("-i", br)
        ensure_forward_rule("-o", br)


parser = argparse.ArgumentParser(description="Generate the NetMind containerlab topology.")
parser.add_argument("--create-bridges", action="store_true",
                    help="idempotently create the host bridges and FORWARD rules (needs sudo)")
if __name__ == "__main__":
    args = parser.parse_args()
    if args.create_bridges:
        try:
            create_bridges()
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            sys.exit(f"Failed to create bridges: {e}")
    else:
        print("\nBridges needed on the host (run with --create-bridges to create them):")
        for br in bridges_to_create:
            print(f"  {br}")
