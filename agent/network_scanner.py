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

Merged scan (#32): ARP, a ping sweep, mDNS and an IPv6 multicast probe run at the
same time. Each device is reported once, with `found_by` (which methods saw it),
its MAC (also taken from the kernel neighbour table for ping-only hosts) and
the IPv6 addresses that belong to the same MAC. If ARP is not possible (no raw
socket permission) the others still run, so one failing method never hides the
rest.
"""
import subprocess
import socket
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor

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
_cache = {"result": None, "timestamp": 0, "subnet": None}


def _cache_get(subnet):
    if (_cache["result"] is not None and _cache["subnet"] == subnet
            and (time.time() - _cache["timestamp"]) < _CACHE_TTL_SECONDS):
        return _cache["result"]
    return None


def _cache_set(subnet, result):
    _cache["result"] = result
    _cache["subnet"] = subnet
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
# The individual discovery methods. Each one returns None when it cannot run
# at all, so the merge can tell "found nothing" apart from "could not look".
# ---------------------------------------------------------------------------
def _arp_scan(subnet):
    """[{ip, mac}] from an ARP broadcast, or None (no scapy / no raw-socket permission)."""
    if not HAS_SCAPY:
        return None
    try:
        answered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet), timeout=3, verbose=False)[0]
    except (PermissionError, OSError):
        return None
    return [{"ip": received.psrc, "mac": received.hwsrc.lower()} for _, received in answered]


def _ping_once(ip):
    try:
        res = subprocess.run(
            ["ping", "-c", "1", "-W", "1", str(ip)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return res.returncode == 0
    except Exception:
        return False


def _ping_sweep(subnet):
    """IPs that answered a ping."""
    network = ipaddress.ip_network(subnet, strict=False)
    alive = []
    with ThreadPoolExecutor(max_workers=64) as pool:
        for ip, ok in zip(network.hosts(), pool.map(_ping_once, network.hosts())):
            if ok:
                alive.append(str(ip))
    return alive


def _default_interface():
    try:
        out = subprocess.run(["ip", "-4", "route", "show", "default"],
                             capture_output=True, text=True, timeout=2).stdout
        parts = out.split()
        return parts[parts.index("dev") + 1] if "dev" in parts else None
    except Exception:
        return None


def _ndp_probe():
    """Ping the IPv6 all-nodes address so IPv6 neighbours show up in the kernel table."""
    iface = _default_interface()
    if not iface:
        return None
    try:
        subprocess.run(["ping", "-6", "-c", "2", "-W", "1", "-I", iface, "ff02::1"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=6)
    except Exception:
        return None
    return True


def _neighbor_table():
    """[{ip, mac}] (IPv4 and IPv6) from the kernel neighbour table (`ip neigh`)."""
    try:
        out = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True, timeout=3).stdout
    except Exception:
        return []
    rows = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3 or "lladdr" not in parts or parts[-1] in ("FAILED", "INCOMPLETE"):
            continue
        rows.append({"ip": parts[0], "mac": parts[parts.index("lladdr") + 1].lower()})
    return rows


def _outcome(future, default=None):
    """A method that crashes counts as 'could not run', never as a failed scan."""
    try:
        return future.result()
    except Exception:
        return default


# ---------------------------------------------------------------------------
# Network scanning — all methods at once, merged per device
# ---------------------------------------------------------------------------
def scan_network(subnet=None, use_cache=True):
    subnet = subnet or get_local_subnet()
    if use_cache:
        cached = _cache_get(subnet)
        if cached is not None:
            return cached

    with ThreadPoolExecutor(max_workers=4) as pool:
        f_arp = pool.submit(_arp_scan, subnet)
        f_ping = pool.submit(_ping_sweep, subnet)
        f_mdns = pool.submit(_mdns_scan)
        f_ndp = pool.submit(_ndp_probe)
        arp, ping = _outcome(f_arp), _outcome(f_ping)
        mdns_results = _outcome(f_mdns, {}) or {}
        _outcome(f_ndp)

    methods = [name for name, found in (("arp", arp), ("ping", ping)) if found is not None]

    devices = {}

    def add(ip, mac, via):
        d = devices.setdefault(ip, {"ip": ip, "mac": None, "hostname": None, "status": "online",
                                    "found_by": [], "ipv6": []})
        if mac and not d["mac"]:
            d["mac"] = mac
        if via not in d["found_by"]:
            d["found_by"].append(via)

    for row in arp or []:
        add(row["ip"], row["mac"], "arp")
    for ip in ping or []:
        add(ip, None, "ping")

    # Ping-only hosts still have a MAC in the kernel table; IPv6 addresses are matched by MAC.
    neighbors = _neighbor_table()
    v4_mac = {r["ip"]: r["mac"] for r in neighbors if ":" not in r["ip"]}
    v6_by_mac = {}
    for r in neighbors:
        if ":" in r["ip"]:
            v6_by_mac.setdefault(r["mac"], []).append(r["ip"])
    for d in devices.values():
        d["mac"] = d["mac"] or v4_mac.get(d["ip"])
        if d["mac"]:
            d["ipv6"] = sorted(v6_by_mac.get(d["mac"], []))

    ips = list(devices)
    if ips:
        with ThreadPoolExecutor(max_workers=16) as pool:
            for ip, name in zip(ips, pool.map(lambda x: _resolve_hostname(x, mdns_results), ips)):
                devices[ip]["hostname"] = name

    ordered = sorted(devices.values(), key=lambda d: ipaddress.ip_address(d["ip"]))
    result = {
        "method": "+".join(methods) or "none",
        "methods": methods,
        "count": len(ordered),
        "devices": ordered,
    }
    _cache_set(subnet, result)
    return result


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
    Returns {"method": "arp+ping"|"ping", "methods": [...], "count": N, "devices": [...]};
    each device has ip, mac, hostname, status, found_by and ipv6."""
    return scan_network()


if __name__ == "__main__":
    import json
    print(f"Scanning {get_local_subnet()} ...")
    print(json.dumps(list_devices(), indent=2))
