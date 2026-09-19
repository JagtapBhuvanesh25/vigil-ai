"""Email classifier — deterministic multi-signal email threat classification.

Architecture.md §2: LLM output is an untrusted signal. The classifier:
  1. Runs HeuristicDetector FIRST (before any LLM call).
  2. Checks honeytoken email address FIRST (before heuristic).
  3. Uses LLM only if no heuristic injection detected.
  4. Maps LLM output to a fixed confidence value (LLM does NOT set risk scores).

Rules.md §3: All security decisions originate from the containment system.
The classifier returns a ClassificationResult; the containment engine computes
actual risk updates via Algorithm 1 (this module does NOT update session risk).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# ── Verdict constants ─────────────────────────────────────────────────────────

VERDICT_SAFE = "safe"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_MALICIOUS = "malicious"
VERDICT_HONEYTOKEN = "honeytoken"
VERDICT_PENDING = "pending"


@dataclass
class ClassificationResult:
    """Result of classifying a single email.

    Attributes:
        verdict:    One of: safe | suspicious | malicious | honeytoken | pending
        confidence: Float in [0.0, 1.0] — classifier confidence in the verdict.
        reasoning:  Human-readable explanation (shown in dashboard).
        heuristic_hit: True if the heuristic detector triggered (injection pattern).
        risk_delta: Suggested risk score change (informational; containment engine
                    computes actual risk via Algorithm 1 on the tool call).
    """

    verdict: str
    confidence: float
    reasoning: str
    heuristic_hit: bool = False
    risk_delta: float = 0.0


class EmailClassifier:
    """Multi-signal email threat classifier.

    Signal priority (highest first):
      1. Honeytoken sender match → HONEYTOKEN_TRIGGERED (immediate Tier 4)
      2. Heuristic injection detection → MALICIOUS (no LLM call)
      3. LLM classification → SAFE / SUSPICIOUS / MALICIOUS

    Rules.md: LLM verdict is mapped to a fixed confidence value.
    The LLM does NOT set the risk score — that is Algorithm 1's job.
    """

    def __init__(self) -> None:
        """Initialise the classifier with the shared LLM client."""
        from vigil.agents.llm import get_llm_client
        from vigil.core.scoring.detectors.heuristic import HeuristicDetector

        self._llm = get_llm_client()
        self._heuristic = HeuristicDetector()

    def classify(
        self,
        subject: str,
        body: str,
        sender_addr: str,
        email_honeytoken: str | None = None,
    ) -> ClassificationResult:
        """Classify an email by verdict.

        Args:
            subject:          Email subject line.
            body:             Plain-text body content.
            sender_addr:      Parsed From address (lowercase).
            email_honeytoken: The session's planted fake email address, if any.
                              If sender_addr matches this, return HONEYTOKEN.

        Returns:
            ClassificationResult with verdict, confidence, reasoning.
        """
        combined_text = f"Subject: {subject}\n\n{body}"

        # ── Signal 1: Honeytoken sender check ─────────────────────────────────
        if email_honeytoken and sender_addr:
            if sender_addr.lower() == email_honeytoken.lower():
                logger.warning(
                    "classifier: honeytoken email address triggered — sender=%s",
                    sender_addr,
                )
                return ClassificationResult(
                    verdict=VERDICT_HONEYTOKEN,
                    confidence=1.0,
                    reasoning=(
                        f"Sender address '{sender_addr}' matches the session honeytoken "
                        "email address. This indicates adversarial forging of an internal "
                        "Vigil sender. Immediate Tier 4 escalation triggered."
                    ),
                    heuristic_hit=False,
                    risk_delta=80.0,
                )

        # ── Signal 2: Heuristic injection pre-screen ──────────────────────────
        try:
            heuristic_score = self._heuristic.detect(
                tool_name="read_email",
                raw_args={"subject": subject, "body": body[:2000]},
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("classifier: heuristic detector error: %s — fail-safe MALICIOUS", exc)
            return ClassificationResult(
                verdict=VERDICT_MALICIOUS,
                confidence=0.95,
                reasoning=f"Heuristic detector failed ({exc}). Fail-safe: treating as Malicious.",
                heuristic_hit=True,
                risk_delta=20.0,
            )

        if heuristic_score >= 1.0:
            logger.info(
                "classifier: injection pattern detected — verdict=MALICIOUS (heuristic)"
            )
            return ClassificationResult(
                verdict=VERDICT_MALICIOUS,
                confidence=0.95,
                reasoning=(
                    "Injection pattern detected in email content by heuristic detector. "
                    "Email contains text that attempts to override AI instructions or "
                    "manipulate agent behavior. No LLM call made."
                ),
                heuristic_hit=True,
                risk_delta=20.0,
            )

        # ── Signal 3: LLM classification ──────────────────────────────────────
        try:
            llm_verdict = self._llm.classify(combined_text[:3000])
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "classifier: LLM classify failed: %s — fail-safe SUSPICIOUS", exc
            )
            return ClassificationResult(
                verdict=VERDICT_SUSPICIOUS,
                confidence=0.5,
                reasoning=f"LLM classifier unavailable ({exc}). Treating as Suspicious (fail-safe).",
                heuristic_hit=False,
                risk_delta=5.0,
            )

        return self._map_llm_verdict(llm_verdict)

    @staticmethod
    def _map_llm_verdict(llm_output: str) -> ClassificationResult:
        """Map raw LLM output string to a ClassificationResult with fixed confidence.

        Rules.md §3: LLM output is untrusted.  Confidence values are determined by
        the containment system (this mapping), NOT by the LLM itself.

        Args:
            llm_output: Raw LLM response (first word extracted, uppercased).

        Returns:
            ClassificationResult with deterministic confidence mapping.
        """
        verdict_upper = llm_output.strip().upper()

        if verdict_upper == "MALICIOUS":
            return ClassificationResult(
                verdict=VERDICT_MALICIOUS,
                confidence=0.85,
                reasoning=(
                    "LLM classifier identified this email as malicious. "
                    "Possible indicators: phishing, credential theft, or impersonation."
                ),
                heuristic_hit=False,
                risk_delta=15.0,
            )
        elif verdict_upper == "SUSPICIOUS":
            return ClassificationResult(
                verdict=VERDICT_SUSPICIOUS,
                confidence=0.65,
                reasoning=(
                    "LLM classifier identified suspicious indicators. "
                    "Possible: unusual urgency, unverified identity, mild phishing signals."
                ),
                heuristic_hit=False,
                risk_delta=5.0,
            )
        elif verdict_upper == "SAFE":
            return ClassificationResult(
                verdict=VERDICT_SAFE,
                confidence=0.90,
                reasoning="LLM classifier identified this as a normal business email.",
                heuristic_hit=False,
                risk_delta=0.0,
            )
        else:
            # Unexpected LLM output — fail-safe to SUSPICIOUS
            logger.warning(
                "classifier: unexpected LLM verdict %r — defaulting to SUSPICIOUS", llm_output
            )
            return ClassificationResult(
                verdict=VERDICT_SUSPICIOUS,
                confidence=0.4,
                reasoning=f"Unexpected classifier output '{llm_output}'. Treating as Suspicious (fail-safe).",
                heuristic_hit=False,
                risk_delta=5.0,
            )
