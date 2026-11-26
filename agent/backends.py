"""Network backends: one interface for "a network NetMind can talk to".

A backend declares which capabilities it has (inventory, power, firewall, ...)
and supplies the functions behind the agent's tools. What a backend may do is
enforced HERE, in code: calling a tool whose capability the backend lacks raises
CapabilityError, whatever the model (or the prompt) says. The real-LAN backend
has no "power" capability, so power_on/power_off can never run against it.

Importable without Docker or an API key (device_control creates its Docker
client lazily).
"""
from abc import ABC, abstractmethod

import device_control as dc
import network_scanner as ns
from tool_catalog import registry
from tools import Cap

# Snapshot of which capability each tool needs. The backends below read the registry live.
TOOL_CAPABILITY = registry.capability_map()


class CapabilityError(Exception):
    """A tool was called on a backend that does not have the capability for it."""


def _refuse(backend_name, tool):
    needed = registry.capability_map().get(tool)
    if needed is None:
        raise CapabilityError(f"'{tool}' is not a known tool.")
    raise CapabilityError(
        f"'{tool}' is not available on the {backend_name} network: it needs the "
        f"'{needed}' capability, which this backend does not have. Nothing was changed.")


class NetworkBackend(ABC):
    name = "base"
    capabilities = frozenset()

    @abstractmethod
    def implementations(self):
        """tool name -> callable, for every tool this backend implements."""

    def tool_overrides(self):
        """tool name -> schema, to replace the shared schema (e.g. different wording)."""
        return {}

    # -- capability checks ---------------------------------------------------
    def supports(self, tool):
        return registry.capability_map().get(tool) in self.capabilities

    def call(self, tool, **args):
        if not self.supports(tool):
            _refuse(self.name, tool)
        return self.implementations()[tool](**args)

    def dispatch(self):
        """tool name -> callable for EVERY known tool. Tools outside this backend's
        capabilities map to a function that raises CapabilityError, so the refusal is
        explicit (and audited) rather than a silent 'unknown tool'."""
        impls = self.implementations()
        table = {}
        for tool in registry.capability_map():
            if self.supports(tool) and tool in impls:
                table[tool] = impls[tool]
            else:
                table[tool] = self._blocked(tool)
        return table

    def _blocked(self, tool):
        def blocked(**_kwargs):
            _refuse(self.name, tool)
        return blocked

    def tools(self, shared_schemas=None):
        """The tool schemas the model is shown: only those this backend supports.
        By default they come from the tool registry."""
        if shared_schemas is None:
            shared_schemas = registry.schemas()
        overrides = self.tool_overrides()
        out = []
        for schema in shared_schemas:
            name = schema["function"]["name"]
            if self.supports(name):
                out.append(overrides.get(name, schema))
        return out

    @abstractmethod
    def resolve(self, name_or_owner):
        """Device dicts matching a name or owner (used by the confirmation guard)."""


class ContainerlabBackend(NetworkBackend):
    """The simulated lab: full control through Docker / Containerlab."""
    name = "simulated"
    capabilities = frozenset({Cap.INVENTORY, Cap.SEGMENTS, Cap.DIAGNOSTICS, Cap.ALERTS,
                              Cap.POWER, Cap.FIREWALL, Cap.CAMERA})

    def implementations(self):
        return registry.implementations()

    def resolve(self, name_or_owner):
        return dc.find_devices(name_or_owner)


_REAL_SCHEMAS = {
    "list_devices": {
        "type": "function",
        "function": {
            "name": "list_devices",
            "description": "Scan the real local network and list every device currently online, with its IP and MAC address.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    "get_status": {
        "type": "function",
        "function": {
            "name": "get_status",
            "description": "Check whether a specific real device (by IP or hostname) is currently online or offline.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name_or_owner": {"type": "string", "description": "IP address or hostname of the device"}
                },
                "required": ["name_or_owner"],
            },
        },
    },
    "get_ip": {
        "type": "function",
        "function": {
            "name": "get_ip",
            "description": "Resolve the IP address of a real device by hostname.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name_or_owner": {"type": "string", "description": "Hostname to resolve"}
                },
                "required": ["name_or_owner"],
            },
        },
    },
}


class RealLanBackend(NetworkBackend):
    """The real LAN this machine is on: discovery and online/offline only. We are
    a guest on that network, so it has NO power, firewall or camera capability."""
    name = "real"
    capabilities = frozenset({Cap.INVENTORY})

    def implementations(self):
        return {
            "list_devices": lambda: ns.list_devices(),
            "get_status": lambda name_or_owner: ns.get_status(name_or_owner),
            "get_ip": lambda name_or_owner: ns.get_ip(name_or_owner),
        }

    def tool_overrides(self):
        return _REAL_SCHEMAS

    def resolve(self, name_or_owner):
        return []  # nothing on a real LAN is controllable, so nothing to confirm