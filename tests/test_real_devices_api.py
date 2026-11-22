"""The real-network API and the chat prompt expose what the merged scan found (found_by, ipv6, count)."""
import web_server as ws

SCAN = {
    "method": "arp+ping", "methods": ["arp", "ping"], "count": 2,
    "devices": [
        {"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:01", "hostname": "router.local", "status": "online",
         "found_by": ["arp", "ping"], "ipv6": ["fe80::1"]},
        {"ip": "192.168.1.9", "mac": None, "hostname": None, "status": "online",
         "found_by": ["ping"], "ipv6": []},
    ],
}


def test_real_devices_endpoint_passes_found_by_and_ipv6(monkeypatch):
    monkeypatch.setattr(ws.ns, "list_devices", lambda: SCAN)
    monkeypatch.setattr(ws, "_track_real_status", lambda devices: devices)   # no event-log side effects
    out = ws.api_real_devices()
    assert [d["ip"] for d in out] == ["192.168.1.1", "192.168.1.9"]
    assert out[0]["found_by"] == ["arp", "ping"] and out[0]["ipv6"] == ["fe80::1"]
    assert out[1]["found_by"] == ["ping"] and out[1]["name"] == "192.168.1.9"


def test_real_devices_endpoint_still_accepts_a_plain_list(monkeypatch):
    monkeypatch.setattr(ws.ns, "list_devices", lambda: [{"ip": "10.0.0.2"}])
    monkeypatch.setattr(ws, "_track_real_status", lambda devices: devices)
    out = ws.api_real_devices()
    assert out[0]["found_by"] == [] and out[0]["ipv6"] == []


def test_the_chat_prompt_describes_the_merged_scan():
    for text in ("arp+ping", "count", "found_by", "ipv6", "Found by", "Scan method: ARP + Ping", "no IPv6"):
        assert text in ws.REAL_PROMPT
