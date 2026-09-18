"""Configuration Pydantic v2 schema for Vigil AI.

All configuration values are validated here. Environment variables prefixed with
VIGIL_ override values loaded from defaults.yaml.
"""

from pydantic import BaseModel, Field


class OllamaConfig(BaseModel):
    """LLM runtime configuration."""

    url: str = "http://localhost:11434"
    model: str = "qwen2.5:7b"
    fallback_model: str = "llama3.2"
    temperature: float = Field(default=0.1, ge=0.0, le=1.0)
    timeout_seconds: int = Field(default=60, gt=0)


class DatabaseConfig(BaseModel):
    """Database connection configuration."""

    url: str = "sqlite+aiosqlite:///./vigil.db"


class ScoringConfig(BaseModel):
    """Algorithm 1 — Risk Scoring weights and decay factor."""

    decay_lambda: float = Field(default=0.98, ge=0.90, le=0.99)
    weight_anomaly: float = Field(default=12.0, ge=0.0)
    weight_deception: float = Field(default=80.0, ge=0.0)
    weight_heuristic: float = Field(default=20.0, ge=0.0)


class TierConfig(BaseModel):
    """Algorithm 2 — Permission FSM tier boundaries and hysteresis."""

    tier_0_max: int = 19
    tier_1_min: int = 20
    tier_1_max: int = 39
    tier_2_min: int = 40
    tier_2_max: int = 59
    tier_3_min: int = 60
    tier_3_max: int = 79
    tier_4_min: int = 80
    hysteresis_restore_events: int = Field(default=5, ge=1)


class ThreatIntelConfig(BaseModel):
    """Safe Browsing Shield configuration."""

    block_confidence_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    warn_confidence_threshold: float = Field(default=0.4, ge=0.0, le=1.0)
    warn_risk_delta: float = Field(default=15.0, ge=0.0)
    flag_risk_spike_threshold: float = Field(default=20.0, ge=0.0)
    decay_rate_per_7_days: float = Field(default=0.05, ge=0.0, le=1.0)
    archive_below_confidence: float = Field(default=0.2, ge=0.0, le=1.0)


class EmailAgentConfig(BaseModel):
    """Email Intelligence Agent thresholds."""

    suspicious_confidence_threshold: float = Field(default=0.4, ge=0.0, le=1.0)
    malicious_confidence_threshold: float = Field(default=0.7, ge=0.0, le=1.0)


class AuditConfig(BaseModel):
    """Audit logger configuration."""

    hash_algorithm: str = "sha256"
    entries_per_page: int = Field(default=100, ge=1)


class VigilConfig(BaseModel):
    """Top-level Vigil AI configuration model.

    Combines all sub-configurations. Validated on startup.
    """

    ollama: OllamaConfig = OllamaConfig()
    database: DatabaseConfig = DatabaseConfig()
    scoring: ScoringConfig = ScoringConfig()
    tiers: TierConfig = TierConfig()
    threat_intel: ThreatIntelConfig = ThreatIntelConfig()
    email_agent: EmailAgentConfig = EmailAgentConfig()
    audit: AuditConfig = AuditConfig()
    mock_llm: bool = False
    mock_inbox_path: str = "./tests/fixtures/emails"
