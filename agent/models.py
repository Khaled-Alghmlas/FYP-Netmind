"""Typed models for what the services return. Every model dumps to exactly the dict the
agent tools and the dashboard already expect (`model.model_dump()`)."""
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict


class Device(BaseModel):
    """One entry of registry.json. Unknown registry fields are kept."""
    model_config = ConfigDict(extra="allow")

    id: str
    type: str
    container: str
    owner: Optional[str] = None
    ip: str = ""
    branch: Optional[str] = None
    segment: Optional[str] = None
    network_ip: Optional[str] = None


class DeviceStatus(BaseModel):
    id: str
    type: str
    status: str


class DeviceIp(BaseModel):
    id: str
    type: str
    ip: str


class DeviceSummary(BaseModel):
    id: str
    owner: Optional[str] = None
    type: str
    status: str


class SegmentDevice(BaseModel):
    id: str
    type: str
    owner: Optional[str] = None


class SegmentListing(BaseModel):
    segment: str
    devices: list[SegmentDevice]


class PowerResult(BaseModel):
    id: str
    already_in_that_state: bool
    previous_status: str
    new_status: str
    link: Optional[dict[str, Any]] = None   # only present after a power-on that re-attached the link


class DashboardRow(BaseModel):
    id: str
    name: str
    type: str
    ip: str = ""
    branch: Optional[str] = None
    status: str


class FirewallRule(BaseModel):
    chain: str
    rule_num: int
    action: str
    protocol: str
    source: str
    port: Optional[int] = None


class FirewallRules(BaseModel):
    id: str
    rules: list[FirewallRule]


class OpenPort(BaseModel):
    port: int
    protocol: str
    chain: str
    source: str


class OpenPorts(BaseModel):
    id: str
    open_ports: list[OpenPort]


class FirewallAudit(BaseModel):
    id: str
    findings: list[str]
    clean: bool


class PortChange(BaseModel):
    id: str
    port: int
    protocol: str
    chains: list[str]
    new_action: str


class CameraStreamStatus(BaseModel):
    id: str
    streaming: bool
    url: str


class CameraStream(BaseModel):
    id: str
    streaming: bool


class CameraCredentialCheck(BaseModel):
    id: str
    using_default_credentials: bool
    findings: list[str]
    clean: bool


class CameraCredentialsChanged(BaseModel):
    id: str
    credentials_changed: bool
