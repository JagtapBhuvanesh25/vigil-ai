"""Structured verdict model for the Phishing & Threat Analyzer.

Phase 4: Every analyzer run produces an AnalyzerVerdict — a structured,
Pydantic-validated JSON object that captures all threat intelligence extracted
during analysis. The LLM may suggest parts, but the containment system
(classifier) determines the final verdict and confidence.

Rules.md: LLM output is untrusted — verdict fields are validated and mapped
by the system, not taken verbatim from the model.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class IOCBundle(BaseModel):
    """Indicators of Compromise extracted during analysis.

    Captures all structured threat artifacts found in the email.
    Raw email body content is NOT stored (Rules.md NFR3 / Privacy by Design).

    Attributes:
        urls:               All URLs found in the email body (not raw body text).
        domains:            Extracted root domains from found URLs.
        sender_anomalies:   List of sender/header anomaly descriptions.
        injection_patterns: Human-readable labels of matched injection patterns.
    """

    urls: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    sender_anomalies: list[str] = Field(default_factory=list)
    injection_patterns: list[str] = Field(default_factory=list)


class AnalyzerVerdict(BaseModel):
    """Structured threat analysis verdict for a single email.

    Produced by the Phishing Analyzer Agent after running all analysis tools.
    All fields are system-controlled — the LLM contributes reasoning text
    but cannot set verdict, confidence, or risk scores directly.

    Rules.md §2: LLM is untrusted — only provides text signals.
    """

    verdict: Literal["safe", "suspicious", "malicious"]
    """Final verdict — mapped from containment signals, not LLM output directly."""

    confidence: float = Field(ge=0.0, le=1.0)
    """Confidence in the verdict [0.0, 1.0]. Computed by classifier, not LLM."""

    reasoning: list[str] = Field(default_factory=list)
    """Bulleted reasoning statements. May incorporate LLM-generated text."""

    iocs: IOCBundle = Field(default_factory=IOCBundle)
    """Structured indicators of compromise extracted during analysis."""

    threat_type: str = "unknown"
    """Threat type: prompt_injection | phishing | social_engineering | composite | benign."""

    header_anomalies: list[str] = Field(default_factory=list)
    """Header-level anomalies found (From/Reply-To mismatch, Received chain, etc.)."""

    urls_found: list[str] = Field(default_factory=list)
    """All URLs extracted from the email body."""

    urls_blocked: list[str] = Field(default_factory=list)
    """URLs blocked during pre-check (confidence ≥ 0.7 in threat_intel)."""

    auto_flagged_domains: list[str] = Field(default_factory=list)
    """Domains automatically written to threat_intel (malicious + confidence ≥ 0.7)."""

    heuristic_hit: bool = False
    """True if the heuristic injection detector fired before any LLM call."""

    risk_score_at_verdict: float = Field(default=0.0, ge=0.0, le=100.0)
    """Session risk score at the time the verdict was produced."""

    def to_dict(self) -> dict:
        """Serialize to a response-safe dict (no raw email body).

        Returns:
            Dict representation of the verdict for API responses and DB storage.
        """
        return self.model_dump()

    @classmethod
    def fail_safe(cls, reason: str, risk_score: float = 0.0) -> "AnalyzerVerdict":
        """Create a fail-safe suspicious verdict for use on exceptions.

        Rules.md: Any detector failure → fail restrictive (not safe, not pass).

        Args:
            reason:     Human-readable reason for the fail-safe activation.
            risk_score: Risk score to record at verdict time.

        Returns:
            An AnalyzerVerdict with verdict='suspicious', confidence=0.5.
        """
        return cls(
            verdict="suspicious",
            confidence=0.5,
            reasoning=[f"[FAIL-SAFE] {reason}"],
            iocs=IOCBundle(),
            threat_type="unknown",
            heuristic_hit=False,
            risk_score_at_verdict=risk_score,
        )


__all__ = ["AnalyzerVerdict", "IOCBundle"]
