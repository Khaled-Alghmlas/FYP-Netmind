"""Real-network scan: ARP, ping, mDNS and IPv6 run together and are merged per device.
Every discovery method is replaced by a fake, so nothing here touches the network."""
import subprocess
import time
from types import SimpleNamespace

import pytest

import network_scanner as ns

SUBNET = "192.168.1.0/24"


@pytest.fixture(autouse=True)
def fakes(monkeypatch):
    """Quiet defaults: nothing found anywhere. Each test overrides what it needs."""
    monkeypatch.setattr(ns, "_cache", {"result": None, "timestamp": 0, "subnet": None})
    monkeypatch.setattr(ns, "_arp_scan", lambda subnet: [])
    monkeypatch.setattr(ns, "_ping_sweep", lambda subnet: [])
    monkeypatch.setattr(ns, "_mdns_scan", lambda: {})
    monkeypatch.setattr(ns, "_ndp_probe", lambda: True)
    monkeypatch.setattr(ns, "_neighbor_table", lambda: [])
    monkeypatch.setattr(ns, "_resolve_hostname", lambda ip, mdns: mdns.get(ip))


def scan():
    return ns.scan_network(SUBNET, use_cache=False)


def by_ip(result):
    return {d["ip"]: d for d in result["devices"]}


def test_a_device_seen_by_both_methods_appears_once_with_both_in_found_by(monkeypatch):
    monkeypatch.setattr(ns, "_arp_scan", lambda s: [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:01"},
                                                    {"ip": "192.168.1.5", "mac": "aa:aa:aa:aa:aa:05"}])
    monkeypatch.setattr(ns, "_ping_sweep", lambda s: ["192.168.1.5", "192.168.1.9"])
    r = scan()
    devs = by_ip(r)
    assert r["method"] == "arp+ping" and r["methods"] == ["arp", "ping"] and r["count"] == 3
    assert devs["192.168.1.1"]["found_by"] == ["arp"]
    assert devs["192.168.1.5"]["found_by"] == ["arp", "ping"]
    assert devs["192.168.1.9"]["found_by"] == ["ping"]
    assert all(d["status"] == "online" for d in devs.values())


def test_devices_are_sorted_by_address_not_as_text(monkeypatch):
    monkeypatch.setattr(ns, "_ping_sweep", lambda s: ["192.168.1.100", "192.168.1.9", "192.168.1.20"])
    assert [d["ip"] for d in scan()["devices"]] == ["192.168.1.9", "192.168.1.20", "192.168.1.100"]


def test_without_raw_socket_permission_ping_still_finds_devices(monkeypatch):
    monkeypatch.setattr(ns, "_arp_scan", lambda s: None)               # ARP could not run
    monkeypatch.setattr(ns, "_ping_sweep", lambda s: ["192.168.1.7"])
    r = scan()
    assert r["method"] == "ping" and r["methods"] == ["ping"]
    assert by_ip(r)["192.168.1.7"]["found_by"] == ["ping"]


def test_a_crashing_method_does_not_hide_the_others(monkeypatch):
    def boom(subnet):
        raise RuntimeError("scapy exploded")
    monkeypatch.setattr(ns, "_arp_scan", boom)
    monkeypatch.setattr(ns, "_ping_sweep", lambda s: ["192.168.1.7"])
    r = scan()
    assert r["methods"] == ["ping"] and r["count"] == 1


def test_when_nothing_can_run_the_method_is_none(monkeypatch):
    monkeypatch.setattr(ns, "_arp_scan", lambda s: None)
    monkeypatch.setattr(ns, "_ping_sweep", lambda s: None)
    r = scan()
    assert r["method"] == "none" and r["devices"] == [] and r["count"] == 0


def test_a_ping_only_host_gets_its_mac_from_the_neighbour_table(monkeypatch):
    monkeypatch.setattr(ns, "_ping_sweep", lambda s: ["192.168.1.7"])
    monkeypatch.setattr(ns, "_neighbor_table", lambda: [{"ip": "192.168.1.7", "mac": "bb:bb:bb:bb:bb:07"}])
    assert by_ip(scan())["192.168.1.7"]["mac"] == "bb:bb:bb:bb:bb:07"


def test_ipv6_addresses_are_attached_by_mac(monkeypatch):
    monkeypatch.setattr(ns, "_arp_scan", lambda s: [{"ip": "192.168.1.5", "mac": "aa:aa:aa:aa:aa:05"}])
    monkeypatch.setattr(ns, "_neighbor_table", lambda: [
        {"ip": "fe80::5", "mac": "aa:aa:aa:aa:aa:05"},
        {"ip": "2001:db8::5", "mac": "aa:aa:aa:aa:aa:05"},
        {"ip": "fe80::99", "mac": "cc:cc:cc:cc:cc:99"},        # someone else's MAC: not ours
    ])
    assert by_ip(scan())["192.168.1.5"]["ipv6"] == ["2001:db8::5", "fe80::5"]


def test_a_device_without_a_mac_has_no_ipv6(monkeypatch):
    monkeypatch.setattr(ns, "_ping_sweep", lambda s: ["192.168.1.7"])
    assert by_ip(scan())["192.168.1.7"]["ipv6"] == []


def test_hostnames_come_from_mdns_first(monkeypatch):
    monkeypatch.setattr(ns, "_arp_scan", lambda s: [{"ip": "192.168.1.5", "mac": "aa:aa:aa:aa:aa:05"}])
    monkeypatch.setattr(ns, "_mdns_scan", lambda: {"192.168.1.5": "printer.local"})
    assert by_ip(scan())["192.168.1.5"]["hostname"] == "printer.local"


def test_the_methods_run_at_the_same_time(monkeypatch):
    def slow_arp(subnet):
        time.sleep(0.4)
        return []

    def slow_ping(subnet):
        time.sleep(0.4)
        return []

    def slow_mdns():
        time.sleep(0.4)
        return {}
    monkeypatch.setattr(ns, "_arp_scan", slow_arp)
    monkeypatch.setattr(ns, "_ping_sweep", slow_ping)
    monkeypatch.setattr(ns, "_mdns_scan", slow_mdns)
    started = time.monotonic()
    scan()
    assert time.monotonic() - started < 0.9          # one after the other would take 1.2s


def test_repeated_scans_use_the_cache_and_a_new_subnet_does_not(monkeypatch):
    calls = []
    monkeypatch.setattr(ns, "_ping_sweep", lambda s: calls.append(s) or [])
    ns.scan_network(SUBNET)
    ns.scan_network(SUBNET)
    assert calls == [SUBNET]
    ns.scan_network("10.0.0.0/24")
    assert calls == [SUBNET, "10.0.0.0/24"]
    ns.scan_network(SUBNET, use_cache=False)
    assert len(calls) == 3


def test_list_devices_returns_the_merged_result(monkeypatch):
    monkeypatch.setattr(ns, "get_local_subnet", lambda: SUBNET)
    monkeypatch.setattr(ns, "_ping_sweep", lambda s: ["192.168.1.7"])
    r = ns.list_devices()
    assert r["count"] == 1 and set(r["devices"][0]) == {"ip", "mac", "hostname", "status", "found_by", "ipv6"}


# --- the real helpers, with the shell commands replaced by canned output -----------------------
def fake_run(stdout):
    return lambda cmd, **kw: SimpleNamespace(stdout=stdout, returncode=0)


def test_neighbor_table_parsing(monkeypatch):
    sample = (
        "192.168.1.1 dev wlan0 lladdr 68:D4:82:89:BF:70 REACHABLE\n"
        "192.168.1.50 dev wlan0  FAILED\n"
        "192.168.1.51 dev wlan0 lladdr 11:22:33:44:55:66 INCOMPLETE\n"
        "fe80::1 dev wlan0 lladdr 68:d4:82:89:bf:70 router STALE\n"
    )
    monkeypatch.undo()                                    # use the real parser, not the autouse fake
    monkeypatch.setattr(subprocess, "run", fake_run(sample))
    assert ns._neighbor_table() == [
        {"ip": "192.168.1.1", "mac": "68:d4:82:89:bf:70"},
        {"ip": "fe80::1", "mac": "68:d4:82:89:bf:70"},
    ]


def test_neighbor_table_survives_a_missing_ip_command(monkeypatch):
    monkeypatch.undo()

    def missing(cmd, **kw):
        raise FileNotFoundError("ip")
    monkeypatch.setattr(subprocess, "run", missing)
    assert ns._neighbor_table() == []


def test_arp_scan_is_none_without_scapy_or_permission(monkeypatch):
    monkeypatch.undo()
    monkeypatch.setattr(ns, "HAS_SCAPY", False)
    assert ns._arp_scan(SUBNET) is None
    monkeypatch.setattr(ns, "HAS_SCAPY", True)

    def denied(*a, **kw):
        raise PermissionError("raw socket")
    monkeypatch.setattr(ns, "srp", denied, raising=False)
    monkeypatch.setattr(ns, "Ether", lambda **kw: 1, raising=False)
    monkeypatch.setattr(ns, "ARP", lambda **kw: 1, raising=False)
    assert ns._arp_scan(SUBNET) is None


def test_ping_sweep_returns_only_the_hosts_that_answer(monkeypatch):
    monkeypatch.undo()
    monkeypatch.setattr(ns, "_ping_once", lambda ip: str(ip) in ("192.168.1.3", "192.168.1.9"))
    assert ns._ping_sweep("192.168.1.0/28") == ["192.168.1.3", "192.168.1.9"]
