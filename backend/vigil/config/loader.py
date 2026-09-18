"""Configuration loader for Vigil AI.

Loads defaults.yaml from the package directory, then overlays any VIGIL_*
environment variables from .env. Returns a validated VigilConfig singleton.
"""

import os
from functools import lru_cache
from pathlib import Path

import yaml
from dotenv import load_dotenv

from vigil.config.schema import (
    AuditConfig,
    DatabaseConfig,
    EmailAgentConfig,
    OllamaConfig,
    ScoringConfig,
    TierConfig,
    ThreatIntelConfig,
    VigilConfig,
)

_DEFAULTS_PATH = Path(__file__).parent / "defaults.yaml"


def _load_yaml() -> dict:
    """Load the defaults.yaml file and return it as a dict."""
    with _DEFAULTS_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _apply_env_overrides(data: dict) -> dict:
    """Apply VIGIL_* environment variable overrides to the config dict.

    Only a curated set of variables are mapped — enough to override the most
    common operational parameters without parsing arbitrary nesting.
    """
    env_map = {
        "VIGIL_DB_URL": ("database", "url"),
        "VIGIL_OLLAMA_URL": ("ollama", "url"),
        "VIGIL_OLLAMA_MODEL": ("ollama", "model"),
        "VIGIL_MOCK_LLM": None,  # handled separately
    }
    for env_key, path in env_map.items():
        val = os.environ.get(env_key)
        if val is not None and path is not None:
            section, key = path
            data.setdefault(section, {})[key] = val

    # Boolean override
    mock_llm_env = os.environ.get("VIGIL_MOCK_LLM", "").lower()
    if mock_llm_env in ("true", "1", "yes"):
        data["mock_llm"] = True
    elif mock_llm_env in ("false", "0", "no"):
        data["mock_llm"] = False

    return data


@lru_cache(maxsize=1)
def load_config() -> VigilConfig:
    """Load and return the validated VigilConfig singleton.

    Loads from defaults.yaml, then applies .env overrides.
    Result is cached — reload only needed after config changes.
    """
    load_dotenv()
    raw = _load_yaml()
    raw = _apply_env_overrides(raw)

    return VigilConfig(
        ollama=OllamaConfig(**raw.get("ollama", {})),
        database=DatabaseConfig(**raw.get("database", {})),
        scoring=ScoringConfig(**raw.get("scoring", {})),
        tiers=TierConfig(**raw.get("tiers", {})),
        threat_intel=ThreatIntelConfig(**raw.get("threat_intel", {})),
        email_agent=EmailAgentConfig(**raw.get("email_agent", {})),
        audit=AuditConfig(**raw.get("audit", {})),
        mock_llm=raw.get("mock_llm", False),
        mock_inbox_path=raw.get("mock_inbox_path", "./tests/fixtures/emails"),
    )


def reload_config() -> VigilConfig:
    """Clear the cache and reload config (used by hot-reload endpoint)."""
    load_config.cache_clear()
    return load_config()
