"""Integration test for issue #4: a port blocked on a firewall must be provably
unreachable from ANOTHER branch (i.e. FORWARD chain, not just INPUT).

Needs a running lab:   make up
Run with:              NETMIND_INTEGRATION=1 pytest -m integration -v
"""
import os
import time

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.environ.get("NETMIND_INTEGRATION") != "1",
                       reason="set NETMIND_INTEGRATION=1 with a deployed lab"),
]

PORT = 2222  # unprivileged test port so we don't touch real SSH rules
SERVER = "host-ahmed"        # branch3, behind fw-branch3
CLIENT = "host-khalid"       # branch1
SERVER_FW = "fw-branch3"


@pytest.fixture(scope="module")
def lab():
    import device_control as dc
    reg = {d["id"]: d for d in dc._load_registry()}
    for needed in (SERVER, CLIENT, SERVER_FW):
        if needed not in reg:
            pytest.skip(f"{needed} not in registry.json - is the lab up?")
    server = dc._client.containers.get(reg[SERVER]["container"])
    client = dc._client.containers.get(reg[CLIENT]["container"])
    server.exec_run(["sh", "-c", f"nc -l -p {PORT} >/dev/null 2>&1 &"])
    time.sleep(1)
    dc.allow_port(SERVER_FW, PORT)
    yield dc, client, reg[SERVER]["network_ip"]
    dc.allow_port(SERVER_FW, PORT)
    server.exec_run(["sh", "-c", f"pkill -f 'nc -l -p {PORT}' || true"])


def reachable(client, ip):
    code, _ = client.exec_run(["sh", "-c", f"nc -z -w 2 {ip} {PORT}"])
    return code == 0


def test_blocked_port_is_unreachable_from_another_branch(lab):
    dc, client, server_ip = lab
    assert reachable(client, server_ip), "baseline: port should be reachable before blocking"
    dc.block_port(SERVER_FW, PORT)
    assert not reachable(client, server_ip), "port still reachable after block_port (FORWARD not applied?)"
    dc.allow_port(SERVER_FW, PORT)
    assert reachable(client, server_ip), "port should be reachable again after allow_port"
