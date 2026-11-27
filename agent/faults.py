"""Reversible fault injection for the simulated lab (issue #25).

Each scenario breaks one thing on purpose and knows how to put it back exactly as it was:
    inject(scenario, target) -> a *run*: what was broken, when, and what is needed to undo it
    revert(run_id)            -> undoes that one fault
    revert_all()              -> undoes every fault still active (the "panic button")

Runs are saved to logs/faults.json, so a fault injected before a server restart can still be
reverted after it. The scenarios are a test tool for people (the Scenarios page and
scripts/faults.py): they are deliberately NOT agent tools, so the AI can never break the lab.

Each run also lists the devices it should affect (`watch`). evaluate() compares that list with
the alert history to measure whether the fault was detected, how fast, and which alerts were
raised for other devices while it was active (possible false alarms).
"""
import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import device_control as dc
import lab_network as ln

STATE_PATH = Path(__file__).resolve().parent.parent / "logs" / "faults.json"   # None: memory only
MAX_RUNS = 200
CAMERA_CREDS = "/etc/netmind-camera-creds"
DEFAULT_CAMERA_PASSWORD = "admin"
FAULT_LATENCY_MS = 300
FAULT_LOSS_PERCENT = 40


class FaultError(Exception):
    """A scenario could not be injected or reverted; the message says why, for the user."""


# --- small helpers ---------------------------------------------------------------------------
def _registry():
    return dc._load_registry()


def _device(device_id):
    dev = next((d for d in _registry() if d["id"] == device_id), None)
    if dev is None:
        raise FaultError(f"unknown device '{device_id}'")
    return dev


def _running(dev):
    try:
        c = dc._client.containers.get(dev["container"])
        c.reload()
    except Exception as e:
        raise FaultError(f"{dev['id']} cannot be reached: {e}") from e
    if c.status != "running":
        raise FaultError(f"{dev['id']} is powered off")
    return c


def _sh(dev, command, what, check=True):
    """Runs a shell command inside the device. Raises FaultError if it fails and `check`."""
    code, out = _running(dev).exec_run(["sh", "-c", command])
    text = out.decode(errors="replace") if isinstance(out, (bytes, bytearray)) else str(out or "")
    if check and code != 0:
        raise FaultError(f"{what} failed on {dev['id']}: {text.strip()[-200:] or f'exit code {code}'}")
    return text


def _node_commands(device_id):
    """The addressing/routing commands Containerlab ran for this node at deploy time."""
    try:
        return ln._load_topology().get("nodes", {}).get(device_id, {}).get("exec", [])
    except Exception as e:
        raise FaultError(f"cannot read the topology file: {e}") from e


def _replay(dev):
    """Re-applies a node's deploy-time addresses and routes (bringing a link back up flushes its
    routes). `ip route add` becomes `ip route replace` so a route that survived is not an error."""
    for command in _node_commands(dev["id"]):
        _sh(dev, command.replace("ip route add ", "ip route replace ", 1), "restore", check=False)


def _branch_devices(fw):
    return [d["id"] for d in _registry() if d.get("branch") == fw.get("branch")]


def _branch_net(fw):
    """'10.3.0.1' (the firewall's LAN address) -> '10.3.0.0/24'."""
    lan = fw.get("network_ip") or ""
    parts = lan.split(".")
    if len(parts) != 4:
        raise FaultError(f"{fw['id']} has no lab address in registry.json")
    return ".".join(parts[:3] + ["0"]) + "/24"


def _router():
    return next((d for d in _registry() if d["type"] == "router"), None) or {"id": "r1", "container": "clab-netmind-large-r1"}


def _branch_firewall(dev):
    fw = next((d for d in _registry() if d["type"] == "firewall" and d.get("branch") == dev.get("branch")), None)
    if fw is None:
        raise FaultError(f"no firewall found for {dev['id']}'s branch")
    return fw


# --- the scenarios ---------------------------------------------------------------------------
@dataclass
class Scenario:
    id: str
    title: str
    title_ar: str
    description: str
    target_type: str                   # host | camera | firewall
    expected: str                      # what should notice it
    inject: Callable                   # (dev) -> revert data (dict)
    revert: Callable                   # (dev, data) -> None
    watch: Callable = field(default=lambda dev: [dev["id"]])   # devices that should alert


# Arabic descriptions for the Scenarios page (titles are on each Scenario).
DESCRIPTION_AR = {
    "host-down": "يطفئ حاوية الجهاز.",
    "camera-down": "يطفئ حاوية الكاميرا.",
    "camera-stream-stop": "الكاميرا تبقى شغالة لكن خدمة البث تتوقف.",
    "host-link-down": "يفصل واجهة الجهاز على شبكة اللاب (eth1).",
    "branch-link-down": "يقطع الرابط بين جدار الفرع الناري والراوتر r1.",
    "branch-latency": "يضيف تأخيراً على رابط الفرع مع r1.",
    "branch-packet-loss": "يُسقط جزءاً من الحزم على رابط الفرع مع r1.",
    "route-removed": "يحذف مسار الراوتر r1 إلى شبكة الفرع.",
    "firewall-block-branch": "يضيف قاعدة تحجب كل الحركة الداخلة للفرع.",
    "firewall-block-camera": "يضيف قاعدة تحجب منفذ بث الكاميرا (8080).",
    "firewall-open-telnet": "يضيف قاعدة تفتح Telnet (المنفذ 23) للجميع.",
    "camera-default-password": "يرجع كلمة مرور الكاميرا إلى admin.",
    "host-wrong-gateway": "يوجّه مسار الجهاز إلى عنوان غير موجود.",
    "host-cpu-stress": "يشغّل حلقة تستهلك نواة معالج كاملة (تتوقف وحدها بعد 10 دقائق)."}


def _power_off(dev):
    dc.power_off(dev["id"])
    return {}


def _power_on(dev, _data):
    dc.power_on(dev["id"])   # also re-attaches the device to its switch


def _stream_off(dev):
    _sh(dev, "/stop_camera.sh", "stopping the stream")
    return {}


def _stream_on(dev, _data):
    _sh(dev, "/start_camera.sh", "starting the stream")


def _link_down(dev):
    _sh(dev, "ip link set eth1 down", "taking the link down")
    return {}


def _link_up(dev, _data):
    _sh(dev, "ip link set eth1 up", "bringing the link up")
    _replay(dev)


def _netem(spec):
    def inject(dev):
        _sh(dev, f"tc qdisc replace dev eth1 root netem {spec}",
            "adding the network impairment (needs 'tc': rebuild the lab images with 'make up')")
        return {}
    return inject


def _netem_off(dev, _data):
    _sh(dev, "tc qdisc del dev eth1 root", "removing the network impairment", check=False)


def _route_del(fw):
    net = _branch_net(fw)
    r1 = _router()
    original = next((c for c in _node_commands(r1["id"]) if f"ip route add {net} " in c), None)
    if original is None:
        raise FaultError(f"no route for {net} in r1's deploy commands")
    _sh(r1, f"ip route del {net}", "removing the route")
    return {"restore": original.replace("ip route add ", "ip route replace ", 1)}


def _route_add(fw, data):
    _sh(_router(), data["restore"], "restoring the route")


def _iptables_rule(rule):
    """A firewall rule added at the top of a chain and removed again. Never saved to the
    firewall's rules file, so a firewall restart also clears it."""
    def inject(dev):
        _sh(dev, f"iptables -I {rule}", "adding the firewall rule")
        dc._forget_audit(dev["id"])      # the next security check reads the rules again
        return {"rule": rule}
    return inject


def _iptables_remove(dev, data):
    chain_rule = data["rule"].split(" ", 2)        # "FORWARD 1 -i eth1 -j DROP" -> chain, pos, spec
    spec = f"{chain_rule[0]} {chain_rule[2]}" if chain_rule[1].isdigit() else data["rule"]
    _sh(dev, f"while iptables -C {spec} 2>/dev/null; do iptables -D {spec}; done", "removing the firewall rule")
    dc._forget_audit(dev["id"])


def _block_camera(cam):
    fw = _branch_firewall(cam)
    rule = f"FORWARD 1 -d {cam['network_ip']} -p tcp --dport 8080 -j DROP"
    _sh(fw, f"iptables -I {rule}", "adding the firewall rule")
    return {"firewall": fw["id"], "rule": rule}


def _unblock_camera(cam, data):
    _iptables_remove(_device(data["firewall"]), data)


def _default_password(cam):
    current = _sh(cam, f"cat {CAMERA_CREDS}", "reading the camera password").strip()
    if current == DEFAULT_CAMERA_PASSWORD:
        raise FaultError(f"{cam['id']} already uses the default password; change it first "
                         "(ask the assistant), then run this scenario")
    _sh(cam, f"printf '%s' {DEFAULT_CAMERA_PASSWORD} > {CAMERA_CREDS}", "resetting the password")
    dc._forget_camera(cam["id"])
    return {"previous": current}


def _restore_password(cam, data):
    previous = data["previous"].replace("'", "'\"'\"'")
    _sh(cam, f"printf '%s' '{previous}' > {CAMERA_CREDS}", "restoring the password")
    dc._forget_camera(cam["id"])


def _wrong_gateway(host):
    gw = _gateway(host)
    wrong = ".".join(gw.split(".")[:3] + ["254"])
    _sh(host, f"ip route replace 10.0.0.0/8 via {wrong} dev eth1", "changing the gateway")
    return {"wrong": wrong}


def _gateway(host):
    gw = ln._gateway(_node_commands(host["id"]))
    if not gw:
        raise FaultError(f"no gateway for {host['id']} in the topology file")
    return gw


def _right_gateway(host, _data):
    _replay(host)


def _cpu_stress(host):
    # `timeout` is a safety net: the load stops by itself after 10 minutes even if never reverted
    _sh(host, "timeout 600 yes > /dev/null 2>&1 & echo $! > /tmp/netmind-stress.pid", "starting the CPU load")
    return {}


def _cpu_calm(host, _data):
    _sh(host, "[ -f /tmp/netmind-stress.pid ] && kill $(cat /tmp/netmind-stress.pid); rm -f /tmp/netmind-stress.pid",
        "stopping the CPU load", check=False)


def _whole_branch(fw):
    return _branch_devices(fw)


SCENARIOS = {s.id: s for s in [
    Scenario("host-down", "Host powered off", "إطفاء جهاز مستخدم",
             "Stops the host's container.", "host", "collector: device down", _power_off, _power_on),
    Scenario("camera-down", "Camera powered off", "إطفاء كاميرا",
             "Stops the camera's container.", "camera", "collector: device down", _power_off, _power_on),
    Scenario("camera-stream-stop", "Camera stream stopped", "إيقاف بث الكاميرا",
             "The camera stays on but its video service stops.", "camera", "collector: degraded (stream)",
             _stream_off, _stream_on),
    Scenario("host-link-down", "Host cable unplugged", "فصل كيبل جهاز",
             "Takes the host's lab interface (eth1) down.", "host", "collector: degraded (lab network)",
             _link_down, _link_up),
    Scenario("branch-link-down", "Branch link down", "انقطاع رابط الفرع",
             "Takes down the link between the branch firewall and the router r1.", "firewall",
             "collector: whole branch unreachable", _link_down, _link_up, _whole_branch),
    Scenario("branch-latency", "High latency on a branch", "بطء شديد في الفرع",
             f"Adds {FAULT_LATENCY_MS} ms of delay on the branch's link to r1 (tc netem).", "firewall",
             "collector: degraded (latency)", _netem(f"delay {FAULT_LATENCY_MS}ms"), _netem_off, _whole_branch),
    Scenario("branch-packet-loss", "Packet loss on a branch", "فقد حزم في الفرع",
             f"Drops {FAULT_LOSS_PERCENT}% of the packets on the branch's link to r1 (tc netem).", "firewall",
             "collector: degraded (packet loss)", _netem(f"loss {FAULT_LOSS_PERCENT}%"), _netem_off, _whole_branch),
    Scenario("route-removed", "Route to a branch removed", "حذف مسار الفرع من الراوتر",
             "Deletes r1's route to the branch network.", "firewall", "collector: whole branch unreachable",
             _route_del, _route_add, _whole_branch),
    Scenario("firewall-block-branch", "Firewall blocks the branch", "الجدار الناري يحجب الفرع",
             "Adds a rule that drops all traffic coming into the branch.", "firewall",
             "collector: whole branch unreachable", _iptables_rule("FORWARD 1 -i eth1 -j DROP"), _iptables_remove,
             _whole_branch),
    Scenario("firewall-block-camera", "Firewall blocks a camera", "الجدار الناري يحجب كاميرا",
             "Adds a rule that drops traffic to the camera's video port (8080).", "camera",
             "collector: degraded (stream blocked)", _block_camera, _unblock_camera),
    Scenario("firewall-open-telnet", "Telnet opened on a firewall", "فتح منفذ Telnet",
             "Adds a rule that accepts Telnet (port 23) from anywhere.", "firewall",
             "security finding (open sensitive port)", _iptables_rule("INPUT 1 -p tcp --dport 23 -j ACCEPT"),
             _iptables_remove),
    Scenario("camera-default-password", "Camera password reset to default", "إرجاع كلمة مرور الكاميرا للافتراضية",
             "Sets the camera's password back to 'admin'.", "camera", "security finding (default password)",
             _default_password, _restore_password),
    Scenario("host-wrong-gateway", "Wrong gateway on a host", "بوابة خاطئة في جهاز",
             "Points the host's route at an address that does not exist.", "host",
             "collector: degraded (lab network)", _wrong_gateway, _right_gateway),
    Scenario("host-cpu-stress", "CPU overload on a host", "ضغط عالٍ على المعالج",
             "Runs a busy loop that uses a full CPU core (stops by itself after 10 minutes).", "host",
             "collector: degraded (CPU), within about 40 s", _cpu_stress, _cpu_calm),
]}


# --- runs ------------------------------------------------------------------------------------
_lock = threading.Lock()
_runs = []          # newest first
_loaded = {"done": False}


def _now_ms():
    return int(time.time() * 1000)


def _load():
    if _loaded["done"]:
        return
    _loaded["done"] = True
    if not STATE_PATH:
        return
    try:
        saved = json.loads(Path(STATE_PATH).read_text(encoding="utf-8"))
        if isinstance(saved, list):
            _runs[:] = [r for r in saved if isinstance(r, dict)][:MAX_RUNS]
    except (OSError, ValueError):
        pass


def _save():
    if not STATE_PATH:
        return
    try:
        path = Path(STATE_PATH)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(_runs, default=str), encoding="utf-8")
        tmp.replace(path)
    except OSError:
        pass


def scenarios():
    """Every scenario with the devices it can target, for the Scenarios page."""
    registry = _registry()
    return [{"id": s.id, "title": s.title, "title_ar": s.title_ar, "description": s.description,
             "description_ar": DESCRIPTION_AR.get(s.id, s.description), "target_type": s.target_type, "expected": s.expected,
             "targets": [d["id"] for d in registry if d["type"] == s.target_type]}
            for s in SCENARIOS.values()]


def runs():
    with _lock:
        _load()
        return [dict(r) for r in _runs]


def active():
    return [r for r in runs() if r["status"] == "active"]


def inject(scenario_id, target):
    scenario = SCENARIOS.get(scenario_id)
    if scenario is None:
        raise FaultError(f"unknown scenario '{scenario_id}'")
    dev = _device(target)
    if dev["type"] != scenario.target_type:
        raise FaultError(f"'{scenario_id}' needs a {scenario.target_type}, and {target} is a {dev['type']}")
    with _lock:
        _load()
        if any(r["status"] == "active" and r["scenario"] == scenario_id and r["target"] == target for r in _runs):
            raise FaultError(f"'{scenario.title}' is already active on {target}")
        started = _now_ms()
        data = scenario.inject(dev)          # raises FaultError if it could not be done
        run = {"id": "f" + uuid.uuid4().hex[:8], "scenario": scenario_id, "title": scenario.title,
               "target": target, "status": "active", "injected_at": started, "reverted_at": None,
               "watch": scenario.watch(dev), "revert_data": data, "error": None}
        _runs.insert(0, run)
        del _runs[MAX_RUNS:]
        _save()
        return dict(run)


def revert(run_id):
    with _lock:
        _load()
        run = next((r for r in _runs if r["id"] == run_id), None)
        if run is None:
            raise FaultError(f"no fault run '{run_id}'")
        if run["status"] != "active":
            return dict(run)
        scenario = SCENARIOS[run["scenario"]]
        try:
            scenario.revert(_device(run["target"]), run.get("revert_data") or {})
        except FaultError as e:
            run["error"] = str(e)    # stays active, so it can be retried
            _save()
            raise
        run.update(status="reverted", reverted_at=_now_ms(), error=None)
        _save()
        return dict(run)


def revert_all():
    """Undoes every active fault, newest first; one failure does not stop the others."""
    results = []
    for run in active():
        try:
            results.append(revert(run["id"]))
        except FaultError as e:
            results.append({**run, "error": str(e)})
    return results


# --- measuring detection ---------------------------------------------------------------------
def evaluate(run, alerts):
    """Was the fault detected? Uses alerts raised while it was active (injection until revert,
    or now). Recoveries are not detections. Returns detected, detection_seconds, the matching
    alert ids, and alerts for devices outside the watch list (candidate false alarms)."""
    start, end = run["injected_at"], run.get("reverted_at") or _now_ms()
    watch = set(run.get("watch") or [run["target"]])
    during = [a for a in alerts if start <= a.get("ts", 0) <= end
              and a.get("kind") not in ("device_online", "device_recovered")]
    hits = sorted((a for a in during if a.get("device") in watch), key=lambda a: a["ts"])
    others = [a for a in during if a.get("device") not in watch]
    first = hits[0] if hits else None
    return {"detected": first is not None,
            "detection_seconds": round((first["ts"] - start) / 1000, 1) if first else None,
            "alerts": [a["id"] for a in hits], "other_alerts": [a["id"] for a in others]}
