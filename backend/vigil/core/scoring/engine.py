"""Algorithm 1 — Risk Scoring Engine (Layer 2).

Implements the canonical multi-detector composite risk scoring formula:

    Rt = clamp(λ · Rt-1 + wa·sa + wb·sb + wc·sc, 0, 100)

Where:
    λ   = decay_lambda       (configured in defaults.yaml, default 0.98)
    wa  = weight_anomaly     (n-gram behavioral anomaly signal)
    wb  = weight_deception   (honeytoken hit signal)
    wc  = weight_heuristic   (injection pattern signal)
    sa  = AnomalyDetector.detect() ∈ [0.0, 1.0]
    sb  = DeceptionDetector.detect() ∈ [0.0, 1.0]
    sc  = HeuristicDetector.detect() ∈ [0.0, 1.0]

Rules.md invariants:
  - Any detector exception → treat as max risk (1.0) — fail-safe.
  - Score is always clamped to [0, 100].
  - Score never goes below 0 (no negative rewards).
"""

from __future__ import annotations

import logging
from typing import Any

from vigil.config.loader import load_config
from vigil.core.scoring.detectors.anomaly import AnomalyDetector
from vigil.core.scoring.detectors.deception import DeceptionDetector
from vigil.core.scoring.detectors.heuristic import HeuristicDetector

logger = logging.getLogger(__name__)

# Module-level singleton detectors (stateful AnomalyDetector is shared).
_anomaly_detector = AnomalyDetector()
_deception_detector = DeceptionDetector()
_heuristic_detector = HeuristicDetector()


class RiskScoringEngine:
    """Algorithm 1 implementation — multi-detector composite risk scorer.

    The engine is stateless itself; it delegates to the three detectors and
    applies the weighted exponential decay formula.

    Attributes:
        _cfg: Loaded VigilConfig (scoring weights and decay lambda).
    """

    def __init__(self) -> None:
        """Load configuration at construction time."""
        self._cfg = load_config()

    def score(
        self,
        tool_name: str,
        args_hash: str,
        risk_before: float,
        deception_registry: dict[str, str],
        raw_args: Any = None,
        session_id: str = "",
    ) -> float:
        """Compute the new risk score Rt using Algorithm 1.

        Args:
            tool_name:          Tool being called.
            args_hash:          Pre-computed salted hash of arguments (not used
                                by detectors directly — raw_args is used).
            risk_before:        Previous risk score Rt-1.
            deception_registry: Session honeytoken registry {value: type}.
            raw_args:           Raw unserialized arguments for pattern scanning.
            session_id:         Session identifier for anomaly detector state.

        Returns:
            New risk score Rt clamped to [0.0, 100.0].
        """
        cfg = self._cfg.scoring
        lam = cfg.decay_lambda
        wa = cfg.weight_anomaly
        wb = cfg.weight_deception
        wc = cfg.weight_heuristic

        # Run detectors (each returns signal ∈ [0.0, 1.0]).
        try:
            sa = _anomaly_detector.detect(
                session_id=session_id or tool_name, tool_name=tool_name
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("scoring: anomaly detector raised %s — max risk (fail-safe)", exc)
            sa = 1.0

        try:
            sb = _deception_detector.detect(
                tool_name=tool_name,
                raw_args=raw_args,
                deception_registry=deception_registry,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("scoring: deception detector raised %s — max risk (fail-safe)", exc)
            sb = 1.0

        try:
            sc = _heuristic_detector.detect(
                tool_name=tool_name,
                raw_args=raw_args,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("scoring: heuristic detector raised %s — max risk (fail-safe)", exc)
            sc = 1.0

        # Algorithm 1: Rt = clamp(λ·Rt-1 + wa·sa + wb·sb + wc·sc, 0, 100)
        raw_score = lam * risk_before + wa * sa + wb * sb + wc * sc
        rt = max(0.0, min(100.0, raw_score))

        logger.debug(
            "scoring: tool=%s Rt-1=%.1f sa=%.2f sb=%.2f sc=%.2f Rt=%.1f",
            tool_name,
            risk_before,
            sa,
            sb,
            sc,
            rt,
        )
        return rt
