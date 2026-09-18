"""Tier boundary lookup table — Layer 3 Permission FSM helper.

Provides deterministic mapping of risk scores to permission tiers and
supports the hysteresis logic in the Permission FSM controller.

Tier definitions (Architecture.md § 4.3):
    Tier 0 — GREEN:  Risk  0–19  — all tools allowed
    Tier 1 — YELLOW: Risk 20–39  — no network egress
    Tier 2 — ORANGE: Risk 40–59  — read-only
    Tier 3 — RED:    Risk 60–79  — read-only introspection only
    Tier 4 — BLACK:  Risk 80–100 — full block + human escalation

Rules.md: unknown/unrecognised risk values → most restrictive tier (4).
"""

from __future__ import annotations

import logging

from vigil.config.loader import load_config

logger = logging.getLogger(__name__)

_TIER_LABELS = {0: "GREEN", 1: "YELLOW", 2: "ORANGE", 3: "RED", 4: "BLACK"}


def risk_to_tier(risk: float) -> int:
    """Map a risk score to the corresponding permission tier.

    This mapping is deterministic and does NOT apply hysteresis — it is a
    pure function of the risk value against configured thresholds.

    The Permission FSM controller applies hysteresis on top of this.

    Args:
        risk: Current risk score in [0.0, 100.0].

    Returns:
        Integer tier in {0, 1, 2, 3, 4}.
        Returns 4 (most restrictive) for any out-of-range or NaN value.
    """
    try:
        cfg = load_config().tiers
        if risk < 0 or risk != risk:  # NaN check: NaN != NaN
            logger.warning("bands: invalid risk score %.1f → tier 4 (fail-safe)", risk)
            return 4

        if risk <= cfg.tier_0_max:
            return 0
        elif risk <= cfg.tier_1_max:
            return 1
        elif risk <= cfg.tier_2_max:
            return 2
        elif risk <= cfg.tier_3_max:
            return 3
        else:
            return 4

    except Exception as exc:  # noqa: BLE001
        logger.error("bands: exception in risk_to_tier: %s → tier 4 (fail-safe)", exc)
        return 4


def tier_label(tier: int) -> str:
    """Return the human-readable label for a tier.

    Args:
        tier: Integer tier in {0, 1, 2, 3, 4}.

    Returns:
        Colour label string (e.g. 'GREEN', 'BLACK').
    """
    return _TIER_LABELS.get(tier, "UNKNOWN")
