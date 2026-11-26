import os

# web_server creates a Groq client at import time; tests never call the API.
os.environ.setdefault("GROQ_API_KEY", "test-key")

# Unit tests never talk to a real Docker daemon: point the client at a socket that does not exist, so a
# test that forgets to fake Docker fails loudly instead of passing only on machines that have Docker.
# Integration tests (NETMIND_INTEGRATION=1) need the real lab and keep the real daemon.
if not os.environ.get("NETMIND_INTEGRATION"):
    os.environ["DOCKER_HOST"] = "unix:///nonexistent/netmind-test-docker.sock"
# Tests must never send real Telegram messages, even on a machine whose .env has a bot token.
# load_dotenv() does not override variables that are already set, so these empty values win.
os.environ["TELEGRAM_BOT_TOKEN"] = ""
os.environ["TELEGRAM_CHAT_ID"] = ""