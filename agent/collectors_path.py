"""Makes the background collector in collectors/ importable from the agent (issue #19).

The server runs from agent/ (`cd agent && uvicorn web_server:app`), so collectors/ is not on the
import path by itself. Importing this module adds it once.
"""
import sys
from pathlib import Path

COLLECTORS_DIR = str(Path(__file__).resolve().parent.parent / "collectors")
if COLLECTORS_DIR not in sys.path:
    sys.path.insert(0, COLLECTORS_DIR)
