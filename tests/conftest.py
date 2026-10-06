import os

# web_server creates a Groq client at import time; tests never call the API.
os.environ.setdefault("GROQ_API_KEY", "test-key")
