"""Runtime configuration for Scorpion.ai.

Values come from (in order of precedence):
    1. explicit kwargs to Config(...)
    2. process environment variables
    3. a .env file (KEY=VALUE lines) next to the repo root, if present
    4. built-in defaults

Secrets (the Anthropic key, the Telegram token) are NEVER written to disk by
this module and NEVER hard-coded. They are read from the environment / .env
that the operator sets up on their own server.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

# ----- model defaults -------------------------------------------------------
# These are configurable per deployment; the operator points SCORPION_MODEL at
# whatever model id their Anthropic account exposes. The default is a balanced
# choice for agentic tool use; the heavy model is used for the final report.
DEFAULT_MODEL = "claude-sonnet-5-5"
DEFAULT_HEAVY_MODEL = "claude-opus-5-5"
ANTHROPIC_BASE = "https://api.anthropic.com"
ANTHROPIC_VERSION = "2023-06-01"


def _parse_env_file(path: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key:
                    out[key] = val
    except OSError:
        pass
    return out


def _split_list(value: str) -> List[str]:
    if not value:
        return []
    parts: List[str] = []
    for chunk in value.replace("\n", ",").split(","):
        chunk = chunk.strip()
        if chunk:
            parts.append(chunk)
    return parts


@dataclass
class Config:
    # --- brain ---
    anthropic_api_key: str = ""
    model: str = DEFAULT_MODEL
    heavy_model: str = DEFAULT_HEAVY_MODEL
    anthropic_base: str = ANTHROPIC_BASE
    max_tokens: int = 4096
    no_llm: bool = False            # run the rules-based planner instead of the LLM

    # --- scope (Scope Guard) ---
    scope_allow: List[str] = field(default_factory=list)
    scope_deny: List[str] = field(default_factory=list)

    # --- politeness / safety ---
    rate_per_host: float = 8.0      # max requests/second to any single host
    max_tool_seconds: int = 600     # hard ceiling per tool invocation
    max_steps: int = 40             # agent plan/act iterations per engagement

    # --- notifications ---
    telegram_token: str = ""
    telegram_chat_id: str = ""
    voice_enabled: bool = True

    # --- dashboard ---
    host: str = "127.0.0.1"
    port: int = 8778

    # --- storage ---
    data_dir: str = "outputs/engagements"

    def redacted(self) -> Dict[str, object]:
        """A copy safe to log / show in the UI (secrets masked)."""
        d = asdict(self)
        for k in ("anthropic_api_key", "telegram_token"):
            d[k] = "set" if d.get(k) else ""
        return d

    @property
    def has_brain(self) -> bool:
        return bool(self.anthropic_api_key) and not self.no_llm

    @property
    def has_telegram(self) -> bool:
        return bool(self.telegram_token and self.telegram_chat_id)


def load_config(repo_root: Optional[str] = None, **overrides) -> Config:
    """Build a Config from .env + environment, then apply explicit overrides."""
    if repo_root is None:
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env_file = _parse_env_file(os.path.join(repo_root, ".env"))

    def get(key: str, default: str = "") -> str:
        if key in os.environ and os.environ[key] != "":
            return os.environ[key]
        return env_file.get(key, default)

    def get_bool(key: str, default: bool) -> bool:
        val = get(key, "").lower()
        if val in ("1", "true", "yes", "on"):
            return True
        if val in ("0", "false", "no", "off"):
            return False
        return default

    cfg = Config(
        anthropic_api_key=get("ANTHROPIC_API_KEY") or get("SCORPION_API_KEY"),
        model=get("SCORPION_MODEL", DEFAULT_MODEL),
        heavy_model=get("SCORPION_HEAVY_MODEL", DEFAULT_HEAVY_MODEL),
        anthropic_base=get("ANTHROPIC_BASE_URL", ANTHROPIC_BASE),
        max_tokens=int(get("SCORPION_MAX_TOKENS", "4096") or "4096"),
        no_llm=get_bool("SCORPION_NO_LLM", False),
        scope_allow=_split_list(get("SCORPION_SCOPE") or get("SCORPION_SCOPE_ALLOW")),
        scope_deny=_split_list(get("SCORPION_SCOPE_DENY")),
        rate_per_host=float(get("SCORPION_RATE_PER_HOST", "8") or "8"),
        max_tool_seconds=int(get("SCORPION_MAX_TOOL_SECONDS", "600") or "600"),
        max_steps=int(get("SCORPION_MAX_STEPS", "40") or "40"),
        telegram_token=get("TELEGRAM_BOT_TOKEN"),
        telegram_chat_id=get("TELEGRAM_CHAT_ID"),
        voice_enabled=get_bool("SCORPION_VOICE", True),
        host=get("SCORPION_HOST", "127.0.0.1"),
        port=int(get("SCORPION_PORT", "8778") or "8778"),
        data_dir=get("SCORPION_DATA_DIR", "outputs/engagements"),
    )
    for key, val in overrides.items():
        if hasattr(cfg, key):
            setattr(cfg, key, val)
    return cfg
