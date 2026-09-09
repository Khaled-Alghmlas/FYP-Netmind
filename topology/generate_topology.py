#!/usr/bin/env python3
"""Generates a Containerlab topology YAML for the NetMind lab network."""
import yaml
from branches import CORE_ROUTER, ALPINE_IMAGE, FRR_IMAGE, BRANCHES

nodes = {CORE_ROUTER: {"kind": "linux", "image": FRR_IMAGE}}
links = []
bridges_to_create = []

router_port = 1
for idx, b in enumerate(BRANCHES, start=1):
    fw = f"fw-{b['name']}"
    seg = f"{b['segment_type']}-{b['name']}"

    nodes[fw] = {"kind": "linux", "image": ALPINE_IMAGE}
    nodes[seg] = {"kind": "bridge"}
    bridges_to_create.append(seg)

    links.append({"endpoints": [f"{CORE_ROUTER}:eth{router_port}", f"{fw}:eth1"]})
    router_port += 1
    links.append({"endpoints": [f"{fw}:eth2", f"{seg}:b{idx}p1"]})

    seg_port = 2
    for owner in b["owners"]:
        host = f"host-{owner}"
        nodes[host] = {"kind": "linux", "image": ALPINE_IMAGE}
        links.append({"endpoints": [f"{seg}:b{idx}p{seg_port}", f"{host}:eth1"]})
        seg_port += 1
    for owner in b["cameras"]:
        cam = f"cam-{owner}"
        nodes[cam] = {"kind": "linux", "image": ALPINE_IMAGE}
        links.append({"endpoints": [f"{seg}:b{idx}p{seg_port}", f"{cam}:eth1"]})
        seg_port += 1

topology = {"name": "netmind-large", "topology": {"nodes": nodes, "links": links}}

with open("netmind-large.clab.yml", "w") as f:
    yaml.dump(topology, f, sort_keys=False, default_flow_style=False)

print(f"Generated {len(nodes)} nodes, {len(links)} links -> netmind-large.clab.yml")
print("\nBridges you must create on the host before deploying:")
for br in bridges_to_create:
    print(f"  sudo ip link add {br} type bridge && sudo ip link set {br} up")
