"""Tool registry: a tool is ONE plain function, registered with a decorator.

The model-facing schema is built from the function itself: its name, its type hints and its
docstring (a summary line, then an `Args:` section with one line per parameter). The decorator also
records what the tool needs (a capability) and how risky it is (a risk level), so the safety guard,
the backends and the dashboard all read the same table instead of each keeping its own list.

Pure Python: no Docker, no FastAPI, no model client, so it is importable (and testable) anywhere.
"""
import inspect
import re
import typing
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Callable, Optional


class Cap:
    """What a network backend can do (see backends.py)."""
    INVENTORY = "inventory"      # list devices, status, address lookup
    SEGMENTS = "segments"        # which devices sit behind a switch/hub
    DIAGNOSTICS = "diagnostics"  # ping, traceroute, routes and interface counters (read-only)
    ALERTS = "alerts"            # read the alert history
    POWER = "power"              # power devices on/off
    FIREWALL = "firewall"        # read and change firewall rules
    CAMERA = "camera"            # camera stream and credentials


class Risk:
    READ = "read"                # only looks at things: runs immediately
    ACTION = "action"            # changes state but is easy to undo: runs immediately, and is audited
    DESTRUCTIVE = "destructive"  # needs the user's explicit confirmation before it runs


_JSON_TYPES = {str: "string", int: "integer", float: "number", bool: "boolean"}
_ARG_LINE = re.compile(r"^(\w+):\s+(.*)$")


def _parse_docstring(fn):
    """-> (summary, {param: description}). The summary is everything before 'Args:'."""
    lines = inspect.getdoc(fn).splitlines() if inspect.getdoc(fn) else []
    summary, args, current, in_args = [], {}, None, False
    for raw in lines:
        line = raw.strip()
        if line == "Args:":
            in_args = True
        elif not in_args:
            if line:
                summary.append(line)
        elif line:
            m = _ARG_LINE.match(line)
            if m:
                current = m.group(1)
                args[current] = m.group(2)
            elif current:
                args[current] += " " + line
    return " ".join(summary), args


def build_schema(fn):
    """Build the function-calling schema for `fn` from its signature and docstring."""
    description, arg_docs = _parse_docstring(fn)
    if not description:
        raise ValueError(f"tool '{fn.__name__}' needs a docstring: its first lines become the description")
    hints = typing.get_type_hints(fn)
    properties, required = {}, []
    for name, param in inspect.signature(fn).parameters.items():
        json_type = _JSON_TYPES.get(hints.get(name, str))
        if json_type is None:
            raise TypeError(f"tool '{fn.__name__}': parameter '{name}' must be str, int, float or bool")
        if name not in arg_docs:
            raise ValueError(f"tool '{fn.__name__}': parameter '{name}' is not described in the 'Args:' section")
        properties[name] = {"type": json_type, "description": arg_docs[name]}
        if param.default is inspect.Parameter.empty:
            required.append(name)
        else:   # models often send null for an optional argument: allow it (the default is then used)
            properties[name]["type"] = [json_type, "null"]
    unknown = set(arg_docs) - set(properties)
    if unknown:
        raise ValueError(f"tool '{fn.__name__}': 'Args:' describes unknown parameter(s) {sorted(unknown)}")
    parameters = {"type": "object", "properties": properties}
    if required:
        parameters["required"] = required
    return {"type": "function", "function": {"name": fn.__name__, "description": description,
                                             "parameters": parameters}}


@dataclass(frozen=True)
class ToolSpec:
    name: str
    fn: Callable[..., Any]
    schema: dict
    capability: str
    risk: str
    target: Optional[str]   # the argument that names the device(s) a destructive tool touches

    @property
    def needs_confirmation(self):
        return self.risk == Risk.DESTRUCTIVE


class _ConfirmationTargets(Mapping):
    """Live read-only view: tool name -> target argument, for tools that need confirmation.
    It reads the registry on every access, so a tool registered later is covered too."""

    def __init__(self, registry):
        self._registry = registry

    def __getitem__(self, name):
        spec = self._registry.get(name)
        if spec is None or not spec.needs_confirmation:
            raise KeyError(name)
        return spec.target

    def __iter__(self):
        return (spec.name for spec in self._registry if spec.needs_confirmation)

    def __len__(self):
        return sum(1 for _ in self)


class ToolRegistry:
    def __init__(self):
        self._tools = {}

    def tool(self, capability, risk=Risk.READ, target=None):
        """Register a function as a tool. `target` names the device argument and is required for
        destructive tools (the guard resolves it to show what will be affected)."""
        def register(fn):
            schema = build_schema(fn)
            if fn.__name__ in self._tools:
                raise ValueError(f"tool '{fn.__name__}' is already registered")
            if risk == Risk.DESTRUCTIVE and target not in schema["function"]["parameters"]["properties"]:
                raise ValueError(f"destructive tool '{fn.__name__}' must name its target argument")
            self._tools[fn.__name__] = ToolSpec(fn.__name__, fn, schema, capability, risk, target)
            return fn
        return register

    # -- queries ---------------------------------------------------------------
    def __contains__(self, name):
        return name in self._tools

    def __iter__(self):
        return iter(self._tools.values())

    def get(self, name):
        return self._tools.get(name)

    def schemas(self):
        return [spec.schema for spec in self]

    def capability_map(self):
        return {spec.name: spec.capability for spec in self}

    def implementations(self):
        return {spec.name: spec.fn for spec in self}

    def confirmation_targets(self):
        """tool name -> its target argument, for every tool that needs confirmation (live view)."""
        return _ConfirmationTargets(self)

    def action_names(self):
        """Every tool that changes something (anything not read-only)."""
        return {spec.name for spec in self if spec.risk != Risk.READ}