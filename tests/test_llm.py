"""Issue #14: the model sits behind LLMProvider, so the agent loop never touches a vendor client."""
from types import SimpleNamespace as NS

import agent_core as core
from llm import ChatCompletionsProvider, GroqProvider, LLMProvider


def message(content=None, calls=()):
    tcs = [NS(id=f"c{i}", function=NS(name=n, arguments=a)) for i, (n, a) in enumerate(calls)] or None
    return NS(content=content, tool_calls=tcs)


class ScriptedProvider(LLMProvider):
    """A model that is not Groq and not OpenAI-shaped: it just returns scripted messages."""

    def __init__(self, *messages):
        self.messages = list(messages)
        self.seen = []

    def complete(self, messages, tools):
        self.seen.append((len(messages), [t["function"]["name"] for t in tools]))
        return self.messages.pop(0)


def run(provider, call_tool=lambda name, args: {"ok": True}, tools=()):
    history = [{"role": "system", "content": "sys"}]
    return core.run_query(provider, "hi", history, list(tools), call_tool), history


def test_chat_completions_provider_sends_the_request_and_returns_the_message():
    seen = {}

    def create(**kwargs):
        seen.update(kwargs)
        return NS(choices=[NS(message="the-message")])

    provider = ChatCompletionsProvider(NS(chat=NS(completions=NS(create=create))), "some-model")
    assert provider.complete([{"role": "user", "content": "x"}], [{"type": "function"}]) == "the-message"
    assert seen == {"model": "some-model", "messages": [{"role": "user", "content": "x"}],
                    "tools": [{"type": "function"}], "tool_choice": "auto"}


def test_groq_provider_builds_the_client_with_its_key_only_when_used():
    built = []

    def factory(api_key):
        built.append(api_key)
        return NS(chat=NS(completions=NS(create=lambda **k: NS(choices=[NS(message=message("hello"))]))))

    provider = GroqProvider("key-123", "m", factory=factory)
    assert built == []                                        # nothing connects at construction
    assert provider.complete([], []).content == "hello"
    assert built == ["key-123"]


def test_groq_provider_without_a_key_fails_clearly_and_the_loop_reports_it():
    reply, _ = run(GroqProvider(None, "m"))
    assert reply.startswith("Sorry, I hit an error talking to the model")
    assert "GROQ_API_KEY" in reply


def test_the_agent_loop_runs_on_any_provider_with_no_vendor_client():
    provider = ScriptedProvider(message(calls=[("get_status", '{"name_or_owner": "host-ahmed"}')]),
                                message("host-ahmed is online."))
    calls = []
    reply, history = run(provider, lambda name, args: calls.append((name, args)) or {"status": "online"},
                         tools=[{"function": {"name": "get_status"}}])
    assert reply == "host-ahmed is online."
    assert calls == [("get_status", {"name_or_owner": "host-ahmed"})]
    assert provider.seen[0] == (2, ["get_status"])           # system + user message, one tool offered
    assert [m["role"] for m in history] == ["system", "user", "assistant", "tool", "assistant"]


def test_a_provider_that_raises_never_crashes_the_loop():
    class Broken(LLMProvider):
        def complete(self, messages, tools):
            raise ConnectionError("network down")

    reply, _ = run(Broken())
    assert "network down" in reply


def test_the_web_server_talks_to_the_model_through_a_provider():
    import web_server as ws
    assert isinstance(ws.provider, LLMProvider)
