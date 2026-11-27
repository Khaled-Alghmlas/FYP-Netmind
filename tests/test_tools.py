"""Issue #14: a tool is one registered function; schema, risk and capability come from it."""
import pytest

import agent_core as core
import backends
import tool_catalog
from tools import Cap, Risk, ToolRegistry, build_schema

EXPECTED_TOOLS = {
    "get_status", "get_ip", "list_devices", "list_devices_on_segment", "ping_between",
    "power_on", "power_off", "list_firewall_rules", "get_open_ports", "audit_firewall",
    "block_port", "allow_port", "get_camera_stream_status", "start_camera_stream",
    "stop_camera_stream", "check_camera_credentials", "change_camera_credentials",
    "traceroute", "get_routes", "get_interface_stats", "get_alerts",     # issue #23
    "diagnose_connectivity", "diagnose_device", "get_recent_actions",   # issue #26
}


# --- schema generation -------------------------------------------------------------------
def sample(host: str, count: int = 3, strict: bool = False, ratio: float = 0.5):
    """Do something to a host.
    It can take a second line.

    Args:
        host: The host name
        count: How many times
            (wrapped onto a second line)
        strict: Be strict
        ratio: A fraction
    """


def test_schema_comes_from_hints_and_docstring():
    fn = build_schema(sample)["function"]
    assert fn["name"] == "sample"
    assert fn["description"] == "Do something to a host. It can take a second line."
    assert fn["parameters"]["required"] == ["host"]             # the others have defaults
    props = fn["parameters"]["properties"]
    assert [props[k]["type"] for k in ("host", "count", "strict", "ratio")] == [
        "string", ["integer", "null"], ["boolean", "null"], ["number", "null"]]   # optional ones may be null
    assert props["count"]["description"] == "How many times (wrapped onto a second line)"


def test_a_tool_without_parameters_has_no_required_list():
    def nothing():
        """Do nothing."""
    assert build_schema(nothing)["function"]["parameters"] == {"type": "object", "properties": {}}


@pytest.mark.parametrize("make", [
    lambda: (lambda: None),                                          # no docstring
])
def test_a_missing_docstring_is_refused(make):
    with pytest.raises(ValueError, match="docstring"):
        build_schema(make())


def test_an_undescribed_or_unknown_parameter_is_refused():
    def undescribed(a: str):
        """Summary."""

    def unknown(a: str):
        """Summary.

        Args:
            a: ok
            b: not a parameter
        """

    def bad_type(a: list):
        """Summary.

        Args:
            a: a list
        """
    with pytest.raises(ValueError, match="not described"):
        build_schema(undescribed)
    with pytest.raises(ValueError, match="unknown parameter"):
        build_schema(unknown)
    with pytest.raises(TypeError, match="str, int, float or bool"):
        build_schema(bad_type)


# --- the registry ------------------------------------------------------------------------
def test_registering_records_capability_and_risk():
    reg = ToolRegistry()

    @reg.tool(Cap.POWER, Risk.DESTRUCTIVE, target="host")
    def reboot(host: str):
        """Reboot a host.

        Args:
            host: Device id
        """
        return "ok"

    spec = reg.get("reboot")
    assert spec.capability == Cap.POWER and spec.needs_confirmation and spec.target == "host"
    assert reboot("x") == "ok"                                       # the decorator returns the function unchanged
    assert dict(reg.confirmation_targets()) == {"reboot": "host"}
    assert reg.action_names() == {"reboot"}


def test_duplicate_and_targetless_destructive_tools_are_refused():
    reg = ToolRegistry()

    @reg.tool(Cap.INVENTORY)
    def look():
        """Look."""

    with pytest.raises(ValueError, match="already registered"):
        reg.tool(Cap.INVENTORY)(look)

    def wipe(host: str):
        """Wipe.

        Args:
            host: Device id
        """
    with pytest.raises(ValueError, match="target argument"):
        reg.tool(Cap.POWER, Risk.DESTRUCTIVE)(wipe)
    with pytest.raises(ValueError, match="target argument"):
        reg.tool(Cap.POWER, Risk.DESTRUCTIVE, target="nope")(wipe)


# --- the real catalog --------------------------------------------------------------------
def test_catalog_has_every_tool_with_a_description_for_each_parameter():
    assert {s.name for s in tool_catalog.registry} == EXPECTED_TOOLS
    for spec in tool_catalog.registry:
        fn = spec.schema["function"]
        assert fn["description"]
        assert all(p["description"] for p in fn["parameters"]["properties"].values())


def test_risk_levels_match_the_confirmation_policy():
    reg = tool_catalog.registry
    assert dict(reg.confirmation_targets()) == {
        "power_off": "name_or_owner", "block_port": "fw_id",
        "allow_port": "fw_id", "change_camera_credentials": "cam_id"}
    assert reg.action_names() == set(reg.confirmation_targets()) | {"power_on", "start_camera_stream", "stop_camera_stream"}
    assert core.DESTRUCTIVE_TOOLS == reg.confirmation_targets()      # the guard has no list of its own


def test_catalog_wrappers_call_the_device_functions(monkeypatch):
    import device_control as dc
    calls = []
    monkeypatch.setattr(dc, "block_port", lambda fw, port, proto: calls.append((fw, port, proto)) or "done")
    assert tool_catalog.registry.get("block_port").fn("fw-1", 22) == "done"
    assert calls == [("fw-1", 22, "tcp")]


# --- acceptance: adding a tool is one registered function --------------------------------
def test_a_new_tool_needs_only_one_registered_function(monkeypatch):
    reg = tool_catalog.registry
    monkeypatch.setattr(reg, "_tools", dict(reg._tools))             # undone after the test

    @reg.tool(Cap.FIREWALL, Risk.DESTRUCTIVE, target="fw_id")
    def flush_rules(fw_id: str):
        """Remove every rule from a firewall.

        Args:
            fw_id: Firewall device id
        """
        return {"flushed": fw_id}

    lab = backends.ContainerlabBackend()
    assert "flush_rules" in {t["function"]["name"] for t in lab.tools()}      # the model is shown it
    assert lab.supports("flush_rules") and "flush_rules" in lab.dispatch()    # the backend can run it
    assert not backends.RealLanBackend().supports("flush_rules")              # and the real LAN cannot
    assert "flush_rules" in core.DESTRUCTIVE_TOOLS                            # and it asks for confirmation

    audit = core.AuditLog()
    guard = core.Guard(lab.dispatch(), lambda name: [{"id": name, "type": "firewall"}], audit)
    pending = guard.call("flush_rules", {"fw_id": "fw-1"}, actor="t")
    assert pending["status"] == "pending_confirmation" and pending["protected"] == ["fw-1"]
    assert guard.confirm(pending["pending_id"], True, "user", acknowledge_protected=True)["result"] == {"flushed": "fw-1"}