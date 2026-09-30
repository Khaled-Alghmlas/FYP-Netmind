#!/usr/bin/env python3
"""Real-network device discovery for NetMind.
Unlike device_control.py (which manages Docker containers in the simulated
containerlab lab), this module only *observes* the real LAN — it discovers
devices via ARP scanning and checks whether they respond (online/offline).
Includes mDNS support for discovering device hostnames (like printers).

Fixes applied per review (#6):
  - IPv6-safe address parsing via info.parsed_addresses() instead of
    socket.inet_ntoa (which only handles 4-byte IPv4 addresses and raised
    a silently-swallowed OSError on any IPv6 record).
  - get_service_info() is no longer called inside the zeroconf callback
    (add_service/update_service) — those callbacks fire on zeroconf's own
    event-loop thread, and a blocking network call there delays processing
    of every other incoming mDNS packet. We now only record (type_, name)
    in the callback and resolve them afterward, from the calling thread.
  - Scan results are cached with a TTL so a repeated list_devices() call
    returns instantly instead of re-running the full 6s mDNS browse + ARP
    sweep every time.
  - get_local_subnet() no longer depends on internet reachability: the
    UDP-connect trick still works offline in most cases (no packet is
    actually sent, it only asks the kernel routing table), but this adds a
    real fallback — parsing `ip -4 addr show` — for cases where there's no
    default route at all.
  - The result now reports which discovery method actually ran ("arp" or
    "ping"), instead of failing over silently.
"""
import subprocess
import socket
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from scapy.all import ARP, Ether, srp
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    from zeroconf import Zeroconf, ServiceBrowser
    HAS_ZEROCONF = True
except ImportError:
    HAS_ZEROCONF = False


# ---------------------------------------------------------------------------
# Result caching — makes repeated calls fast (acceptance criteria)
# ---------------------------------------------------------------------------
_CACHE_TTL_SECONDS = 20
_cache = {"result": None, "timestamp": 0}


def _cache_get():
    if _cache["result"] is not None and (time.time() - _cache["timestamp"]) < _CACHE_TTL_SECONDS:
        return _cache["result"]
    return None


def _cache_set(result):
    _cache["result"] = result
    _cache["timestamp"] = time.time()


# ---------------------------------------------------------------------------
# Subnet detection — works even with no internet route
# ---------------------------------------------------------------------------
def get_local_subnet():
    """Guess the local /24 subnet. Tries the fast UDP-connect trick first
    (works offline too, since no packet is actually sent — it only asks the
    kernel which local interface *would* route to that address), then falls
    back to reading the machine's own interface config directly, which has
    no dependency on any route existing at all."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            return str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
        finally:
            s.close()
    except OSError:
        pass  # no default route (e.g. genuinely offline) — fall through

    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True, text=True, timeout=2
        )
        for line in out.stdout.splitlines():
            parts = line.split()
            if "inet" in parts:
                iface = parts[1]
                if iface == "lo":
                    continue
                cidr = parts[parts.index("inet") + 1]  # e.g. "192.168.1.16/24"
                return str(ipaddress.ip_network(cidr, strict=False))
    except Exception:
        pass

    raise RuntimeError(
        "Could not determine local subnet — no network interface with an "
        "IPv4 address was found (are you connected to any network?)."
    )


# ---------------------------------------------------------------------------
# mDNS hostname resolution — non-blocking, IPv6-safe
# ---------------------------------------------------------------------------
MDNS_SERVICE_TYPES = [
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_printer._tcp.local.",
    "_ipp._tcp.local.",
    "_device-info._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_googlecast._tcp.local.",
    "_workstation._tcp.local.",
    "_smb._tcp.local.",
    "_ssh._tcp.local.",
    "_companion-link._tcp.local.",
]
MDNS_BROWSE_SECONDS = 6


class _MDNSListener:
    """Only records which (type_, name) pairs appeared. Resolution
    (get_service_info, which does blocking network I/O) happens afterward
    from the main thread — never inside these callbacks."""
    def __init__(self):
        self.seen = set()

    def add_service(self, zeroconf, type_, name):
        self.seen.add((type_, name))

    def update_service(self, zeroconf, type_, name):
        self.seen.add((type_, name))

    def remove_service(self, zeroconf, type_, name):
        pass


def _mdns_scan():
    """Browse mDNS for MDNS_BROWSE_SECONDS, then resolve every service found
    afterward (not inside the callback) and return {ip: hostname}."""
    if not HAS_ZEROCONF:
        return {}

    found = {}
    try:
        zc = Zeroconf()
        listener = _MDNSListener()
        ServiceBrowser(zc, MDNS_SERVICE_TYPES, listener)
        time.sleep(MDNS_BROWSE_SECONDS)

        for type_, name in listener.seen:
            try:
                info = zc.get_service_info(type_, name, timeout=1000)
                if info and info.server:
                    hostname = info.server.rstrip(".")
                    # parsed_addresses() returns plain textual IPv4/IPv6
                    # strings — unlike inet_ntoa it doesn't assume a 4-byte
                    # packed address, so it never raises on an IPv6 record.
                    for ip in info.parsed_addresses():
                        found[ip] = hostname
            except Exception:
                continue  # one bad/unreachable service shouldn't kill the scan

        zc.close()
    except Exception:
        pass
    return found


def _resolve_hostname(ip, mdns_results):
    if ip in mdns_results:
        return mdns_results[ip]
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


# ---------------------------------------------------------------------------
# Network scanning — reports which method actually ran
# ---------------------------------------------------------------------------
def scan_network(subnet=None, use_cache=True):
    if use_cache:
        cached = _cache_get()
        if cached is not None:
            return cached

    subnet = subnet or get_local_subnet()
    mdns_results = _mdns_scan()

    if not HAS_SCAPY:
        result = _scan_network_ping_fallback(subnet, mdns_results)
        _cache_set(result)
        return result

    try:
        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        answered = srp(packet, timeout=3, verbose=False)[0]

        devices = []
        for _, received in answered:
            devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc,
                "hostname": _resolve_hostname(received.psrc, mdns_results),
                "status": "online",
            })
        result = {
            "method": "arp",
            "devices": sorted(devices, key=lambda d: tuple(int(x) for x in d["ip"].split("."))),
        }
    except (PermissionError, OSError):
        # No CAP_NET_RAW / not running as root — ARP needs raw sockets
        result = _scan_network_ping_fallback(subnet, mdns_results)

    _cache_set(result)
    return result


def _ping_once(ip):
    try:
        res = subprocess.run(
            ["ping", "-c", "1", "-W", "1", str(ip)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return res.returncode == 0
    except Exception:
        return False


def _scan_network_ping_fallback(subnet, mdns_results=None):
    mdns_results = mdns_results or {}
    network = ipaddress.ip_network(subnet, strict=False)
    devices = []
    with ThreadPoolExecutor(max_workers=64) as pool:
        futures = {pool.submit(_ping_once, ip): ip for ip in network.hosts()}
        for future in as_completed(futures):
            ip = futures[future]
            if future.result():
                devices.append({
                    "ip": str(ip),
                    "mac": None,
                    "hostname": _resolve_hostname(str(ip), mdns_results),
                    "status": "online",
                })
    return {
        "method": "ping",
        "devices": sorted(devices, key=lambda d: tuple(int(x) for x in d["ip"].split("."))),
    }


def get_status(ip_or_hostname):
    ip = ip_or_hostname
    try:
        ip = socket.gethostbyname(ip_or_hostname)
    except socket.gaierror:
        pass

    online = _ping_once(ip)
    return [{
        "id": ip_or_hostname,
        "ip": ip,
        "status": "online" if online else "offline",
    }]


def get_ip(hostname):
    try:
        return [{"id": hostname, "ip": socket.gethostbyname(hostname)}]
    except socket.gaierror:
        return [{"id": hostname, "ip": None, "error": "could not resolve"}]


def list_devices():
    """List every device currently visible on the real LAN.
    Returns {"method": "arp"|"ping", "devices": [...]}."""
    return scan_network()


if __name__ == "__main__":
    import json
    print(f"Scanning {get_local_subnet()} ...")
    print(json.dumps(list_devices(), indent=2))
