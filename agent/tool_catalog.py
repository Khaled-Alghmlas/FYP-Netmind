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
