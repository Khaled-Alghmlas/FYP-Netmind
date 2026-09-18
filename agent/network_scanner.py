#!/usr/bin/env python3
"""Real-network device discovery for NetMind.
Unlike device_control.py (which manages Docker containers in the simulated
containerlab lab), this module only *observes* the real LAN — it discovers
devices via ARP scanning and checks whether they respond (online/offline).
Includes mDNS support for discovering device hostnames (like printers).
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
    from zeroconf import Zeroconf, ServiceBrowser, DNSQuestion, const
    HAS_ZEROCONF = True
except ImportError:
    HAS_ZEROCONF = False


def get_local_subnet():
    """Guess the local /24 subnet from this machine's default route IP."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()
    network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    return str(network)


# قاموس مؤقت لتخزين أسماء mDNS المكتشفة
_mdns_cache = {}

if HAS_ZEROCONF:
    class MDNSListener:
        def remove_service(self, zeroconf, type_, name):
            pass

        def add_service(self, zeroconf, type_, name):
            try:
                info = zeroconf.get_service_info(type_, name)
                if info and info.addresses:
                    for addr in info.addresses:
                        ip = socket.inet_to_ntoa(addr)
                        if info.server:
                            _mdns_cache[ip] = info.server.rstrip('.')
            except Exception:
                pass

        def update_service(self, zeroconf, type_, name):
            self.add_service(zeroconf, type_, name)

    def _background_mdns_listener():
        try:
            z = Zeroconf()
            listener = MDNSListener()
            # استماع لخدمات الشبكة الشائعة للبحث عن الأسماء
            browser = ServiceBrowser(z, ["_http._tcp.local.", "_printer._tcp.local.", "_ipp._tcp.local.", "_device-info._tcp.local."], listener)
            time.sleep(2)  # منح وقت قصير لجمع الإعلانات
            z.close()
        except Exception:
            pass

    # تشغيل البحث في الخلفية لتعبئة الكاش
    try:
        import threading
        t = threading.Thread(target=_background_mdns_listener, daemon=True)
        t.start()
    except Exception:
        pass


def _resolve_hostname(ip):
    # 1. التحقق من الكاش الخاص بـ mDNS أولاً
    if ip in _mdns_cache:
        return _mdns_cache[ip]

    # 2. المحاولة عبر Reverse DNS التقليدي
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        pass

    return None


def scan_network(subnet=None):
    """ARP-scan the subnet with mDNS hostname resolution."""
    subnet = subnet or get_local_subnet()

    if not HAS_SCAPY:
        return _scan_network_ping_fallback(subnet)

    try:
        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        result = srp(packet, timeout=3, verbose=False)[0]

        devices = []
        for _, received in result:
            devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc,
                "hostname": _resolve_hostname(received.psrc),
                "status": "online",
            })
        return sorted(devices, key=lambda d: tuple(int(x) for x in d["ip"].split(".")))
    except PermissionError:
        return _scan_network_ping_fallback(subnet)
    except OSError:
        return _scan_network_ping_fallback(subnet)


def _ping_once(ip):
    try:
        res = subprocess.run(
            ["ping", "-c", "1", "-W", "1", str(ip)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return res.returncode == 0
    except Exception:
        return False


def _scan_network_ping_fallback(subnet):
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
                    "hostname": _resolve_hostname(str(ip)),
                    "status": "online",
                })
    return sorted(devices, key=lambda d: tuple(int(x) for x in d["ip"].split(".")))


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
    return scan_network()


if __name__ == "__main__":
    import json
    print(f"Scanning {get_local_subnet()} ...")
    print(json.dumps(list_devices(), indent=2))
