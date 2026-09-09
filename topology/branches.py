"""Shared network layout config — used by both the topology generator and the device registry builder."""

CORE_ROUTER = "r1"
ALPINE_IMAGE = "alpine:latest"
FRR_IMAGE = "frrouting/frr:latest"

BRANCHES = [
    {"name": "branch1", "segment_type": "switch", "owners": ["khalid", "khalil", "turki"], "cameras": ["khalid"]},
    {"name": "branch2", "segment_type": "hub",    "owners": ["sara", "omar"],               "cameras": []},
    {"name": "branch3", "segment_type": "switch", "owners": ["ahmed", "fahad", "noura"],     "cameras": ["ahmed", "fahad"]},
]
