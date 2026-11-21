"""Application settings, read from the environment when asked - never at import time."""
import os
from pathlib import Path
from typing import Optional

from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MODEL = "openai/gpt-oss-120b"


class Settings(BaseModel):
    groq_api_key: Optional[str] = None
    model: str = DEFAULT_MODEL
    registry_path: Path = ROOT / "topology" / "registry.json"
    logs_dir: Path = ROOT / "logs"

    @classmethod
    def from_env(cls, env=None):
        """Build settings from `env` (default: os.environ). A blank key counts as missing."""
        env = os.environ if env is None else env
        key = (env.get("GROQ_API_KEY") or "").strip() or None
        values = {"groq_api_key": key}
        if env.get("NETMIND_MODEL"):
            values["model"] = env["NETMIND_MODEL"]
        return cls(**values)
