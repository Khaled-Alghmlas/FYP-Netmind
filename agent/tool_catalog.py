"""Every tool the agent can use, as one registered function each.

To add a tool, write one function here: type hints and an `Args:` docstring give the model its
schema; the decorator says which capability it needs and how risky it is. Nothing else lists tools
(no schema table, no dispatch table). The device code is imported inside each function, so this
module loads without Docker.
"""
from tools import Cap, Risk, ToolRegistry

registry = ToolRegistry()
tool = registry.tool


# --- inventory ---------------------------------------------------------------------------
@tool(Cap.INVENTORY)
def get_status(name_or_owner: str):
    """Check whether a device (or all devices belonging to an owner) is on or off.

    Args:
        name_or_owner: Device id (e.g. 'host-ahmed') or owner name (e.g. 'ahmed')
    """
    import device_control as dc
    return dc.get_status(name_or_owner)


@tool(Cap.INVENTORY)
def get_ip(name_or_owner: str):
    """Get the IP address of a device (or all devices belonging to an owner).

    Args:
        name_or_owner: Device id or owner name
    """
    import device_control as dc
    return dc.get_ip(name_or_owner)


@tool(Cap.INVENTORY)
def list_devices():
    """List every device in the network with its owner, type, and on/off status."""
    import device_control as dc
    return dc.list_devices()


@tool(Cap.SEGMENTS)
def list_devices_on_segment(segment_id: str):
    """List every device connected to a given switch or hub segment (e.g. 'switch-branch1', 'hub-branch2', 'switch-branch3'). Note: switches/hubs are plain network bridges, not controllable devices themselves.

    Args:
        segment_id: Segment name, e.g. 'switch-branch1'
    """
    import device_control as dc
    return dc.list_devices_on_segment(segment_id)


@tool(Cap.DIAGNOSTICS)
def ping_between(src: str, dst: str, count: int = 3):
    """Ping from one lab device to another over the lab (data-plane) network to check whether the link between them works. Read-only. Use it to verify connectivity, for example after a device was powered off and on. src and dst are device ids; each must match exactly one device.

    Args:
        src: Source device id, e.g. 'host-khalid'
        dst: Destination device id, e.g. 'host-khalil'
        count: Number of pings, 1-5 (default 3)
    """
    import lab_network
    return lab_network.ping_between(src, dst, count)


@tool(Cap.DIAGNOSTICS)
def traceroute(src: str, dst: str, max_hops: int = 8):
    """Trace the path packets take from one lab device to another, hop by hop, over the lab (data-plane) network. Read-only. Use it to find where a connection breaks: the last hop that answers is the last working point. src and dst are device ids; each must match exactly one device.

    Args:
        src: Source device id, e.g. 'host-khalid'
        dst: Destination device id, e.g. 'host-sara'
        max_hops: Maximum number of hops to try, 1-15 (default 8)
    """
    import lab_network
    return lab_network.traceroute(src, dst, max_hops)


@tool(Cap.DIAGNOSTICS)
def get_routes():
    """Show the routing table of the core router r1 (read through FRR's vtysh): which networks it reaches and through which next hop and interface. Read-only. Use it to check whether the router knows the way to a branch."""
    import lab_network
    return lab_network.get_routes()


@tool(Cap.DIAGNOSTICS)
def get_interface_stats(device: str, interface: str = ""):
    """Show the network interface counters of a device (packets, errors and drops sent and received) and whether each link is up. Read-only. Use it to find a faulty or congested link.

    Args:
        device: Device id, e.g. 'r1' or 'fw-branch1'
        interface: Optional interface name, e.g. 'eth1'. Leave empty for all interfaces
    """
    import lab_network
    return lab_network.get_interface_stats(device, interface)


# --- root-cause analysis (issue #26) ------------------------------------------------------
@tool(Cap.DIAGNOSTICS)
def diagnose_connectivity(src: str, dst: str):
    """Find out WHY one device cannot reach another (or reaches it slowly or with loss). Read-only. Runs a fixed playbook in code: power of both ends, ping, traceroute, then every device on the path in order (cable and link state, address and gateway compared with the lab design, the router's routes, firewall rules that drop the traffic, delay or loss configured on a link) and, for a camera, whether its video port is reachable. Returns every step with ok true/false and the failed ones under 'problems'. Use it first for any "why can't X reach Y" question.

    Args:
        src: Source device id or owner, e.g. 'host-ahmed'
        dst: Destination device id or owner, e.g. 'cam-fahad'
    """
    import diagnosis
    return diagnosis.diagnose_connectivity(src, dst)


@tool(Cap.DIAGNOSTICS)
def diagnose_device(device: str):
    """Find out WHAT is wrong with one device. Read-only. Runs a fixed playbook in code: the background monitor's view, power (and how it stopped), cable and link state, address and gateway compared with the lab design, its branch firewall and the router's route towards it, delay or loss on links, whether the router can reach it, for a camera whether the video service runs and is reachable, CPU use, and recent changes and alerts. Returns every step with ok true/false and the failed ones under 'problems'. Use it first for "what happened to X" or "why is X down/slow/degraded".

    Args:
        device: Device id or owner, e.g. 'cam-khalid'
    """
    import diagnosis
    return diagnosis.diagnose_device(device)


@tool(Cap.ALERTS)
def get_recent_actions(device: str = "", minutes: int = 60):
    """List the changes made through NetMind recently (power on/off, firewall ports, camera stream and password changes), newest first, with who made them and when. Read-only. Use it to check whether someone changed a device just before a problem started.

    Args:
        device: Device id or part of it. Leave empty for all devices
        minutes: How far back to look, 1-1440 (default 60)
    """
    import diagnosis
    return diagnosis.recent_actions(device, minutes)


# --- history -----------------------------------------------------------------------------
@tool(Cap.ALERTS)
def get_alerts(device: str = "", kind: str = "", active_only: bool = False, hours_back: int = 24,
               start: str = "", end: str = "", limit: int = 20):
    """Look up past alerts (device offline / back online with the downtime, firewall and camera findings), newest first. Read-only. Use it for questions about the past, such as what happened to a camera last night. The result has 'now' (the current time) and 'history_starts' (how far back alerts are recorded): use them to read words like 'last night' or 'yesterday'.

    Args:
        device: Device id or part of it, e.g. 'cam-khalid'. Leave empty for all devices
        kind: Optional alert kind: device_offline, device_online, device_degraded, device_recovered, firewall_finding or camera_finding
        active_only: True to list only alerts that are still open
        hours_back: How many hours back to look, 1-720 (default 24). Ignored when start or end is given
        start: Optional start of the period, ISO date-time in server local time, e.g. '2026-11-24T20:00'
        end: Optional end of the period, ISO date-time in server local time, e.g. '2026-11-25T06:00'
        limit: Maximum number of alerts to return, 1-100 (default 20)
    """
    import alert_history
    return alert_history.get_alerts(device, kind, active_only, hours_back, start, end, limit)


# --- power -------------------------------------------------------------------------------
@tool(Cap.POWER, Risk.ACTION)
def power_on(name_or_owner: str):
    """Turn on a device or all devices belonging to an owner.

    Args:
        name_or_owner: Device id or owner name
    """
    import device_control as dc
    return dc.power_on(name_or_owner)


@tool(Cap.POWER, Risk.DESTRUCTIVE, target="name_or_owner")
def power_off(name_or_owner: str):
    """Turn off / shut down a device or all devices belonging to an owner.

    Args:
        name_or_owner: Device id or owner name
    """
    import device_control as dc
    return dc.power_off(name_or_owner)


# --- firewall ----------------------------------------------------------------------------
@tool(Cap.FIREWALL)
def list_firewall_rules(fw_id: str):
    """List the raw firewall rules configured on a firewall device (e.g. fw-branch1).

    Args:
        fw_id: Firewall device id, e.g. 'fw-branch1'
    """
    import device_control as dc
    return dc.list_firewall_rules(fw_id)


@tool(Cap.FIREWALL)
def get_open_ports(fw_id: str):
    """Get which ports are currently open (allowed through) on a firewall device.

    Args:
        fw_id: Firewall device id, e.g. 'fw-branch1'
    """
    import device_control as dc
    return dc.get_open_ports(fw_id)


@tool(Cap.FIREWALL)
def audit_firewall(fw_id: str):
    """Audit a firewall for common security issues, e.g. sensitive ports (SSH, Telnet, FTP, RDP) left open to any source.

    Args:
        fw_id: Firewall device id, e.g. 'fw-branch1'
    """
    import device_control as dc
    return dc.audit_firewall(fw_id)


@tool(Cap.FIREWALL, Risk.DESTRUCTIVE, target="fw_id")
def block_port(fw_id: str, port: int, protocol: str = "tcp"):
    """Block a port on a firewall device, closing it to all traffic.

    Args:
        fw_id: Firewall device id, e.g. 'fw-branch1'
        port: Port number to block, e.g. 22
        protocol: Protocol, defaults to 'tcp'
    """
    import device_control as dc
    return dc.block_port(fw_id, port, protocol)


@tool(Cap.FIREWALL, Risk.DESTRUCTIVE, target="fw_id")
def allow_port(fw_id: str, port: int, protocol: str = "tcp"):
    """Allow a port on a firewall device, opening it to traffic.

    Args:
        fw_id: Firewall device id, e.g. 'fw-branch1'
        port: Port number to allow, e.g. 22
        protocol: Protocol, defaults to 'tcp'
    """
    import device_control as dc
    return dc.allow_port(fw_id, port, protocol)


# --- cameras -----------------------------------------------------------------------------
@tool(Cap.CAMERA)
def get_camera_stream_status(cam_id: str):
    """Check whether a camera's video stream service is actually reachable and responding (separate from whether the container itself is powered on).

    Args:
        cam_id: Camera device id, e.g. 'cam-khalid'
    """
    import device_control as dc
    return dc.get_camera_stream_status(cam_id)


@tool(Cap.CAMERA, Risk.ACTION)
def start_camera_stream(cam_id: str):
    """Start a camera's video stream service, without affecting the container's power state.

    Args:
        cam_id: Camera device id, e.g. 'cam-khalid'
    """
    import device_control as dc
    return dc.start_camera_stream(cam_id)


@tool(Cap.CAMERA, Risk.ACTION)
def stop_camera_stream(cam_id: str):
    """Stop a camera's video stream service, without powering off the container.

    Args:
        cam_id: Camera device id, e.g. 'cam-khalid'
    """
    import device_control as dc
    return dc.stop_camera_stream(cam_id)


@tool(Cap.CAMERA)
def check_camera_credentials(cam_id: str):
    """Check whether a camera is still using its default (weak) password.

    Args:
        cam_id: Camera device id, e.g. 'cam-khalid'
    """
    import device_control as dc
    return dc.check_camera_credentials(cam_id)


@tool(Cap.CAMERA, Risk.DESTRUCTIVE, target="cam_id")
def change_camera_credentials(cam_id: str, new_password: str):
    """Change a camera's password away from the default.

    Args:
        cam_id: Camera device id, e.g. 'cam-khalid'
        new_password: New password to set
    """
    import device_control as dc
    return dc.change_camera_credentials(cam_id, new_password)