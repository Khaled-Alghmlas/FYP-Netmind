"""Shared network layout config — used by both the topology generator and the device registry builder."""

CORE_ROUTER = "r1"
ALPINE_IMAGE = "alpine:latest"
FRR_IMAGE = "frrouting/frr:latest"
FIREWALL_IMAGE = "netmind-firewall:latest"
CAMERA_IMAGE = "netmind-camera:latest"

BRANCHES = [
    {"name": "branch1", "segment_type": "switch", "owners": ["khalid", "khalil", "turki"], "cameras": ["khalid"]},
    {"name": "branch2", "segment_type": "hub",    "owners": ["sara", "omar"],               "cameras": []},
    {"name": "branch3", "segment_type": "switch", "owners": ["ahmed", "fahad", "noura"],     "cameras": ["ahmed", "fahad"]},
]

def compute_addressing():
    """Single source of truth for the topology's IP addressing plan (used by
    generate_topology.py to emit exec commands, and build_registry.py to
    record each device's network-layer IP). All under 10.0.0.0/8:
      - r1 <-> fw-branchN point-to-point: 10.10.N.0/30 (r1=.1, fw=.2)
      - branch N LAN: 10.N.0.0/24 (fw's inside leg / gateway = 10.N.0.1)
      - hosts: 10.N.0.10, .11, ... / cameras: 10.N.0.50, .51, ..."""
    firewalls = {}
    devices = {}
    for idx, b in enumerate(BRANCHES, start=1):
        branch_net = f"10.{idx}.0"
        p2p_net = f"10.10.{idx}"
        r1_ip = f"{p2p_net}.1"
        fw_wan_ip = f"{p2p_net}.2"
        fw_lan_ip = f"{branch_net}.1"
        fw = f"fw-{b['name']}"
        firewalls[fw] = {
            "wan_ip": fw_wan_ip, "lan_ip": fw_lan_ip,
            "p2p_net": f"{p2p_net}.0/30", "branch_net": f"{branch_net}.0/24",
            "r1_ip": r1_ip,
        }
        host_octet = 10
        for owner in b["owners"]:
            devices[f"host-{owner}"] = f"{branch_net}.{host_octet}"
            host_octet += 1
        cam_octet = 50
        for owner in b["cameras"]:
            devices[f"cam-{owner}"] = f"{branch_net}.{cam_octet}"
            cam_octet += 1
    return {"firewalls": firewalls, "devices": devices}
