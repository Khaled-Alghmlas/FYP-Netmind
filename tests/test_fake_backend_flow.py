"""Issue #17: the whole service layer - agent loop, tool registry, guard, backend, audit - runs against
a fake NetworkBackend and a scripted model. No Docker, no network, no API key."""
import json
from types import SimpleNamespace as NS

import pytest

import agent_core as core
import backends
from llm import LLMProvider

DEVICES = {"host-ahmed": "online", "host-sara": "online"}


class FakeLab(backends.NetworkBackend):
    """A tiny in-memory network: it can look at devices and power them, but has no firewall."""
    name = "fake-lab"
    capabilities = frozenset({backends.Cap.INVENTORY, backends.Cap.POWER})

    def __init__(self):
        self.state = dict(DEVICES)

    def implementations(self):
        return {
            "get_status": lambda name_or_owner: [{"id": name_or_owner, "status": self.state[name_or_owner]}],
            "power_off": lambda name_or_owner: self.state.__setitem__(name_or_owner, "offline") or [{"new_status": "offline"}],
        }

    def resolve(self, name_or_owner):
        return [{"id": name_or_owner, "type": "host"}] if name_or_owner in self.state else []


class Script(LLMProvider):
    def __init__(self, *messages):
        self.messages = list(messages)

    def complete(self, messages, tools):
        return self.messages.pop(0)


def say(text):
    return NS(content=text, tool_calls=None)


def call(name, **args):
    return NS(content=None, tool_calls=[NS(id=f"c-{name}", function=NS(name=name, arguments=json.dumps(args)))])


@pytest.fixture
def lab():
    backend = FakeLab()
    audit = core.AuditLog()
    guard = core.Guard(backend.dispatch(), backend.resolve, audit, supports=backend.supports)
    return NS(backend=backend, audit=audit, guard=guard)


def ask(lab, provider, text):
    history = [{"role": "system", "content": "sys"}]
    steps = []
    reply = core.run_query(provider, text, history, lab.backend.tools(), lambda n, a: lab.guard.call(n, a, "chat:t", "k"), steps=steps)
    return reply, steps


def test_the_model_only_sees_the_tools_this_backend_supports(lab):
    names = {t["function"]["name"] for t in lab.backend.tools()}
    assert names == {"get_status", "get_ip", "list_devices", "power_on", "power_off"}   # inventory + power only
    assert "block_port" not in names


def test_a_read_only_question_runs_straight_through(lab):
    reply, steps = ask(lab, Script(call("get_status", name_or_owner="host-ahmed"), say("host-ahmed is online.")), "status of host-ahmed?")
    assert reply == "host-ahmed is online." and steps[0]["result"] == [{"id": "host-ahmed", "status": "online"}]
    assert [e["status"] for e in lab.audit.list()] == ["executed"]


def test_power_off_waits_for_the_user_and_only_then_changes_the_network(lab):
    reply, steps = ask(lab, Script(call("power_off", name_or_owner="host-sara"), say("Please press Confirm.")), "turn off host-sara")
    pending = steps[0]["result"]
    assert pending["status"] == "pending_confirmation" and lab.backend.state["host-sara"] == "online"   # nothing happened yet

    done = lab.guard.confirm(pending["pending_id"], True, actor="user")
    assert done["status"] == "executed" and lab.backend.state["host-sara"] == "offline"
    assert [e["status"] for e in lab.audit.list()] == ["pending", "confirmed"]


def test_cancelling_leaves_the_network_untouched(lab):
    _, steps = ask(lab, Script(call("power_off", name_or_owner="host-sara"), say("Waiting.")), "turn off host-sara")
    assert lab.guard.confirm(steps[0]["result"]["pending_id"], False, actor="user")["status"] == "cancelled"
    assert lab.backend.state["host-sara"] == "online"


def test_a_tool_the_backend_lacks_is_denied_in_code_and_audited(lab):
    reply, steps = ask(lab, Script(call("block_port", fw_id="fw-1", port=22), say("I cannot do that here.")), "block port 22")
    assert "firewall" in steps[0]["result"]["error"] and lab.guard.list_pending() == []
    assert [e["status"] for e in lab.audit.list()] == ["denied"]


def test_an_unknown_device_is_refused_before_anything_is_queued(lab):
    _, steps = ask(lab, Script(call("power_off", name_or_owner="host-ghost"), say("No such device.")), "turn off host-ghost")
    assert "No device matches" in steps[0]["result"]["error"] and lab.guard.list_pending() == []
