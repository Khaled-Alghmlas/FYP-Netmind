"""Issue #12: settings and clients are built on demand, so nothing needs Docker or an API key at import."""
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from clients import LazyGroqClient
from settings import DEFAULT_MODEL, Settings

AGENT_DIR = Path(__file__).resolve().parent.parent / "agent"


def test_settings_come_from_the_environment_that_is_passed_in():
    s = Settings.from_env({"GROQ_API_KEY": "k", "NETMIND_MODEL": "other-model"})
    assert s.groq_api_key == "k" and s.model == "other-model"


def test_blank_key_counts_as_missing_and_defaults_apply():
    s = Settings.from_env({"GROQ_API_KEY": "   "})
    assert s.groq_api_key is None and s.model == DEFAULT_MODEL
    assert s.registry_path.name == "registry.json"


def test_lazy_client_builds_nothing_until_first_use():
    built = []
    client = LazyGroqClient("key", factory=lambda api_key: built.append(api_key) or NS(chat="the-chat"))
    assert built == []
    assert client.chat == "the-chat" and client.chat == "the-chat"
    assert built == ["key"]                       # created once, then reused


def test_lazy_client_without_a_key_fails_only_when_used():
    client = LazyGroqClient(None)                 # constructing it must not raise
    with pytest.raises(RuntimeError, match="GROQ_API_KEY"):
        client.chat


def test_web_server_imports_without_an_api_key_or_docker():
    code = (f"import sys; sys.path.insert(0, {str(AGENT_DIR)!r}); "
            "import web_server; print('imported', web_server.provider._client._real is None)")
    env = {**os.environ, "GROQ_API_KEY": ""}      # python-dotenv never overrides a variable that is set
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=120)
    assert r.returncode == 0, r.stderr[-600:]
    assert "imported True" in r.stdout
