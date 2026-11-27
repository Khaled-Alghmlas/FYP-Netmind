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
    database_path: Path = ROOT / "logs" / "netmind.db"
    # Background collector (issue #19): how often it samples the lab, how many samples in a row
    # must agree before a device changes state, and whether hosts/cameras are pinged.
    collector_enabled: bool = True
    collector_interval: float = 5.0
    collector_confirm: int = 2
    collector_ping: bool = True
    collector_lab_probe: bool = True

    @classmethod
    def from_env(cls, env=None):
        """Build settings from `env` (default: os.environ). A blank key counts as missing."""
        env = os.environ if env is None else env
        key = (env.get("GROQ_API_KEY") or "").strip() or None
        values = {"groq_api_key": key}
        if env.get("NETMIND_MODEL"):
            values["model"] = env["NETMIND_MODEL"]
        if env.get("NETMIND_DB"):
            values["database_path"] = Path(env["NETMIND_DB"])
        if env.get("NETMIND_COLLECTOR"):
            values["collector_enabled"] = env["NETMIND_COLLECTOR"].strip().lower() not in ("0", "false", "no", "off")
        if env.get("NETMIND_COLLECT_LAB"):
            values["collector_lab_probe"] = env["NETMIND_COLLECT_LAB"].strip().lower() not in ("0", "false", "no", "off")
        if env.get("NETMIND_COLLECT_PING"):
            values["collector_ping"] = env["NETMIND_COLLECT_PING"].strip().lower() not in ("0", "false", "no", "off")
        try:
            if env.get("NETMIND_COLLECT_INTERVAL"):
                values["collector_interval"] = max(1.0, float(env["NETMIND_COLLECT_INTERVAL"]))
            if env.get("NETMIND_COLLECT_CONFIRM"):
                values["collector_confirm"] = max(1, int(env["NETMIND_COLLECT_CONFIRM"]))
        except ValueError:
            pass   # a malformed number keeps the default rather than stopping the server
        return cls(**values)
