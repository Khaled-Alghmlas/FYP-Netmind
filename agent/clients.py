"""Clients for outside services, created on first use instead of at import time,
so importing the app (tests, CI, a machine without a key) needs no API key."""


class LazyGroqClient:
    """Looks like a Groq client (`client.chat.completions.create(...)`) but only builds
    the real one when `.chat` is first used. Without an API key, using it raises a clear
    error that the agent loop reports to the user, instead of crashing the server at startup."""

    def __init__(self, api_key, factory=None):
        self._api_key = api_key
        self._factory = factory
        self._real = None

    @property
    def chat(self):
        if self._real is None:
            if not self._api_key:
                raise RuntimeError("GROQ_API_KEY is not set - add it to .env to talk to the model.")
            factory = self._factory
            if factory is None:
                from groq import Groq  # imported lazily as well
                factory = Groq
            self._real = factory(api_key=self._api_key)
        return self._real.chat
