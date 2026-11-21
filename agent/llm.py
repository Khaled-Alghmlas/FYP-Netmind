"""The model behind the agent, hidden behind one small interface.

The agent loop (agent_core.run_query) only ever calls `provider.complete(messages, tools)`, so
swapping the model vendor means writing one class here, not touching the loop, the guard or the
server. Importable without the groq package or an API key: the real client is built on first use.
"""
from abc import ABC, abstractmethod

from clients import LazyGroqClient


class LLMProvider(ABC):
    @abstractmethod
    def complete(self, messages, tools):
        """Send the conversation and the tool schemas to the model; return its assistant
        message: `.content` (text or None) and `.tool_calls` (None, or a list of calls each
        with `.id`, `.function.name` and `.function.arguments` as a JSON string)."""


class ChatCompletionsProvider(LLMProvider):
    """Any client that has the OpenAI-style `client.chat.completions.create(...)` API."""

    def __init__(self, client, model):
        self._client = client
        self._model = model

    def complete(self, messages, tools):
        response = self._client.chat.completions.create(
            model=self._model, messages=messages, tools=tools, tool_choice="auto")
        return response.choices[0].message


class GroqProvider(ChatCompletionsProvider):
    """Groq. With no API key it raises a clear error on first use, not at startup."""

    def __init__(self, api_key, model, factory=None):
        super().__init__(LazyGroqClient(api_key, factory), model)
