"""Device, firewall and camera services.

All the lab logic lives here, with nothing imported from Docker or HTTP libraries: the
outside world is passed in (a function that returns the Docker-like client, one that loads
the registry, ...). That makes every service importable and testable with plain fakes, with no
Docker daemon and no API key. device_control.py wires the real ones in.
"""
import difflib
import shlex

from iptables import FIREWALL_CHAINS, SENSITIVE_PORTS, effective_port_rules, parse_rules
from models import (
    CameraCredentialCheck, CameraCredentialsChanged, CameraStream, CameraStreamStatus,
    DashboardRow, Device, DeviceIp, DeviceStatus, DeviceSummary, FirewallAudit, FirewallRules,
    OpenPort, OpenPorts, PortChange, PowerResult, SegmentDevice, SegmentListing,
)

CAMERA_PORT = 8080
DEFAULT_CAMERA_PASSWORD = "admin"

_PREFIXES = ("host-", "cam-", "fw-")
FUZZY_MIN_SCORE = 0.8     # how alike two names must be to count as the same name
FUZZY_MIN_MARGIN = 0.08   # and how much better than the runner-up, or we don't guess


def friendly_status(docker_status):
    """Map Docker's raw container status to the online/offline vocabulary real mode uses."""
    return "online" if docker_status == "running" else "offline"


def _bare(name):
    for prefix in _PREFIXES:
        if name.startswith(prefix):
            return name[len(prefix):]
    return name


def _fuzzy_match(devices, needle):
    """Forgiving lookup for typos and spelling variants ('host-khaled' -> host-khalid).
    Returns [] unless one name is clearly the closest, so an ambiguous guess never picks a
    device. Destructive actions still show the resolved device ids on the confirmation prompt."""
    if len(_bare(needle)) < 3:
        return []

    def score(name):
        return max(difflib.SequenceMatcher(None, needle, name).ratio(),
                   difflib.SequenceMatcher(None, _bare(needle), _bare(name)).ratio())

    groups = {}  # a person's devices share one entry; ownerless devices stand alone
    for d in devices:
        key = (d.owner or d.id).lower()
        names = {d.id.lower(), (d.owner or "").lower()} - {""}
        best, members = groups.get(key, (0.0, []))
        groups[key] = (max([best] + [score(n) for n in names]), members + [d])
    ranked = sorted(groups.values(), key=lambda g: -g[0])
    if not ranked or ranked[0][0] < FUZZY_MIN_SCORE:
        return []
    if len(ranked) > 1 and ranked[0][0] - ranked[1][0] < FUZZY_MIN_MARGIN:
        return []
    prefix = next((x for x in _PREFIXES if needle.startswith(x)), None)
    members = ranked[0][1]
    if prefix:  # "host-khaled" means the host, not the same person's camera
        members = [d for d in members if d.id.lower().startswith(prefix)]
    return members


def _exec_ok(container, cmd, failure):
    """Run a command in a container; raise RuntimeError(failure + output) if it fails."""
    exit_code, output = container.exec_run(cmd)
    if exit_code != 0:
        raise RuntimeError(f"{failure}: {output.decode(errors='replace').strip()}")
    return output.decode(errors="replace")


class DeviceService:
    """Names -> devices, status, address, power, and the dashboard rows.

    registry()      -> list of registry dicts
    client()        -> object with .containers.get(name) / .containers.list(all=True)
    resolver(name)  -> list of device dicts; defaults to this service's own find()
    reconnect(id)   -> called after a device is powered on (re-attaches its lab link)
    on_change()     -> called after a power change (e.g. to drop caches)
    not_found / runtime_errors -> exception classes the runtime raises for a missing container
    / an unreachable daemon
    """

    def __init__(self, registry, client, *, resolver=None, reconnect=None, on_change=None,
                 not_found=(), runtime_errors=()):
        self._registry = registry
        self._client = client
        self._resolver = resolver
        self._reconnect = reconnect
        self._on_change = on_change
        self._not_found = tuple(not_found)
        self._runtime_errors = tuple(runtime_errors)

    # -- lookup --------------------------------------------------------------
    def devices(self):
        return [Device(**d) for d in self._registry()]

    def find(self, name_or_owner):
        """Match by exact device id first (e.g. 'host-ahmed'), else by owner name (e.g. 'ahmed'
        -> all their devices). Case-insensitive, since the UI may display names capitalized."""
        devices = self.devices()
        needle = name_or_owner.strip().lower()
        exact = [d for d in devices if d.id.lower() == needle]
        if exact:
            return exact
        by_owner = [d for d in devices if (d.owner or "").lower() == needle]
        if by_owner:
            return by_owner
        return _fuzzy_match(devices, needle)

    def _resolve(self, name_or_owner):
        if self._resolver is None:
            return self.find(name_or_owner)
        return [Device(**d) for d in self._resolver(name_or_owner)]

    def list_on_segment(self, segment_id):
        needle = segment_id.strip().lower()
        matches = [d for d in self.devices() if (d.segment or "").lower() == needle]
        return SegmentListing(segment=segment_id,
                              devices=[SegmentDevice(id=d.id, type=d.type, owner=d.owner) for d in matches])

    # -- state ---------------------------------------------------------------
    def _state(self, device):
        try:
            return friendly_status(self._client().containers.get(device.container).status)
        except self._not_found:
            return "not found"

    def status(self, name_or_owner):
        return [DeviceStatus(id=d.id, type=d.type, status=self._state(d)) for d in self._resolve(name_or_owner)]

    def ip(self, name_or_owner):
        return [DeviceIp(id=d.id, type=d.type, ip=d.ip) for d in self._resolve(name_or_owner)]

    def list_all(self):
        return [DeviceSummary(id=d.id, owner=d.owner, type=d.type, status=self._state(d)) for d in self.devices()]

    def dashboard_rows(self):
        try:
            containers = {c.name: c for c in self._client().containers.list(all=True)}
        except self._runtime_errors:
            containers = {}
        rows = []
        for d in self.devices():
            c = containers.get(d.container)
            rows.append(DashboardRow(id=d.id, name=d.id, type=d.type, ip=d.ip, branch=d.branch,
                                     status="online" if c is not None and c.status == "running" else "offline"))
        return rows

    # -- power ---------------------------------------------------------------
    def power_on(self, name_or_owner):
        results = []
        for d in self._resolve(name_or_owner):
            c = self._client().containers.get(d.container)
            was_running = c.status == "running"
            link = None
            if not was_running:
                c.start()
                if self._on_change:
                    self._on_change()
                if self._reconnect:
                    link = self._reconnect(d.id)
            results.append(PowerResult(id=d.id, already_in_that_state=was_running,
                                       previous_status=friendly_status(c.status),
                                       new_status="online", link=link))
        return results

    def power_off(self, name_or_owner):
        results = []
        for d in self._resolve(name_or_owner):
            c = self._client().containers.get(d.container)
            was_stopped = c.status != "running"
            if not was_stopped:
                # Lab containers run a plain sleep as PID 1 and ignore SIGTERM, so the
                # default 10 s grace period is just dead waiting; 2 s is plenty.
                c.stop(timeout=2)
                if self._on_change:
                    self._on_change()
            results.append(PowerResult(id=d.id, already_in_that_state=was_stopped,
                                       previous_status=friendly_status(c.status), new_status="offline"))
        return results


class FirewallService:
    """Reads and changes the iptables rules of a firewall container.

    resolver(name) -> list of device dicts; client() -> Docker-like client;
    on_change(fw_id) -> called after a rule change (e.g. to drop a cached audit)."""

    def __init__(self, resolver, client, *, on_change=None):
        self._resolver = resolver
        self._client = client
        self._on_change = on_change

    def _device(self, fw_id):
        matches = [Device(**d) for d in self._resolver(fw_id) if d["type"] == "firewall"]
        if not matches:
            raise ValueError(f"'{fw_id}' is not a known firewall.")
        return matches[0]

    def _container(self, fw_id):
        d = self._device(fw_id)
        return d, self._client().containers.get(d.container)

    @staticmethod
    def _iptables(container, args):
        return _exec_ok(container, ["iptables"] + args, "iptables command failed")

    def list_rules(self, fw_id):
        """Rules from both the INPUT and FORWARD chains; each rule carries its chain."""
        d, c = self._container(fw_id)
        rules = []
        for chain in FIREWALL_CHAINS:
            rules.extend(parse_rules(self._iptables(c, ["-L", chain, "-n", "--line-numbers"]), chain))
        return FirewallRules(id=d.id, rules=rules)

    def open_ports(self, fw_id):
        effective = effective_port_rules(self.list_rules(fw_id).rules)
        return OpenPorts(id=fw_id, open_ports=[
            OpenPort(port=port, protocol=proto, chain=chain, source=r.source)
            for (chain, port, proto), r in effective.items() if r.action == "ACCEPT"])

    def audit(self, fw_id):
        effective = effective_port_rules(self.list_rules(fw_id).rules)
        findings = []
        for (chain, port, _proto), r in effective.items():
            if port in SENSITIVE_PORTS and r.action == "ACCEPT" and r.source in ("0.0.0.0/0", "::/0"):
                where = "to the firewall itself" if chain == "INPUT" else "through the firewall to other hosts"
                findings.append(f"Port {port} ({SENSITIVE_PORTS[port]}) is open to any source {where} "
                                f"({chain}) — consider restricting it.")
        return FirewallAudit(id=fw_id, findings=findings, clean=len(findings) == 0)

    def _set_port_rule(self, container, chain, protocol, port, action):
        """Make `action` the single rule for (chain, protocol, port): remove any existing
        ACCEPT/DROP rules for it, then insert the new one at the top. Idempotent."""
        for old in ("ACCEPT", "DROP"):
            while container.exec_run(["iptables", "-C", chain, "-p", protocol, "--dport", str(port), "-j", old])[0] == 0:
                self._iptables(container, ["-D", chain, "-p", protocol, "--dport", str(port), "-j", old])
        self._iptables(container, ["-I", chain, "1", "-p", protocol, "--dport", str(port), "-j", action])

    def _change_port(self, fw_id, port, protocol, action, label):
        d, c = self._container(fw_id)
        for chain in FIREWALL_CHAINS:
            self._set_port_rule(c, chain, protocol, port, action)
        _exec_ok(c, ["sh", "-c", "iptables-save > /etc/netmind-fw-rules"], "Failed to persist firewall rules")
        if self._on_change:
            self._on_change(d.id)
        return PortChange(id=d.id, port=port, protocol=protocol, chains=list(FIREWALL_CHAINS), new_action=label)

    def block_port(self, fw_id, port, protocol="tcp"):
        return self._change_port(fw_id, port, protocol, "DROP", "blocked")

    def allow_port(self, fw_id, port, protocol="tcp"):
        return self._change_port(fw_id, port, protocol, "ACCEPT", "allowed")


class CameraService:
    """Camera stream and credential checks.

    resolver(name) -> list of device dicts; client() -> Docker-like client;
    snapshot_ok(url) -> bool, True if the camera answers an HTTP request (never raises);
    on_change(cam_id) -> called after a credential change."""

    def __init__(self, resolver, client, snapshot_ok, *, on_change=None):
        self._resolver = resolver
        self._client = client
        self._snapshot_ok = snapshot_ok
        self._on_change = on_change

    def _device(self, cam_id):
        matches = [Device(**d) for d in self._resolver(cam_id) if d["type"] == "camera"]
        if not matches:
            raise ValueError(f"'{cam_id}' is not a known camera.")
        return matches[0]

    def _container(self, cam_id):
        d = self._device(cam_id)
        return d, self._client().containers.get(d.container)

    def stream_status(self, cam_id):
        """Makes a real HTTP request to the camera's IP: tests that the camera service is
        genuinely reachable, not just that the container process is alive."""
        d = self._device(cam_id)
        url = f"http://{d.ip}:{CAMERA_PORT}/snapshot"
        return CameraStreamStatus(id=d.id, streaming=bool(self._snapshot_ok(url)), url=url)

    def start_stream(self, cam_id):
        d, c = self._container(cam_id)
        _exec_ok(c, ["/start_camera.sh"], "Failed to start camera stream")
        return CameraStream(id=d.id, streaming=True)

    def stop_stream(self, cam_id):
        d, c = self._container(cam_id)
        _exec_ok(c, ["/stop_camera.sh"], "Failed to stop camera stream")
        return CameraStream(id=d.id, streaming=False)

    def check_credentials(self, cam_id):
        d, c = self._container(cam_id)
        password = _exec_ok(c, ["cat", "/etc/netmind-camera-creds"], "Failed to read camera credentials").strip()
        is_default = password == DEFAULT_CAMERA_PASSWORD
        findings = ["Camera is using the default password (admin) — consider changing it."] if is_default else []
        return CameraCredentialCheck(id=d.id, using_default_credentials=is_default,
                                     findings=findings, clean=not is_default)

    def change_credentials(self, cam_id, new_password):
        d, c = self._container(cam_id)
        _exec_ok(c, ["sh", "-c", f"printf '%s' {shlex.quote(new_password)} > /etc/netmind-camera-creds"],
                 "Failed to update camera credentials")
        if self._on_change:
            self._on_change(d.id)
        return CameraCredentialsChanged(id=d.id, credentials_changed=True)
