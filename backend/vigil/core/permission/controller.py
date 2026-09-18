"""Algorithm 2 — Permission FSM with asymmetric hysteresis (Layer 3).

Implements the 5-tier state machine with the following properties:

  FAST RESTRICT:  If the new risk maps to a HIGHER tier, transition immediately.
  SLOW RESTORE:   If the new risk maps to a LOWER tier, the transition is
                  deferred until `hysteresis_restore_events` consecutive
                  below-threshold events have been observed.

This asymmetry means the system is quick to restrict and slow to restore,
implementing the fail-safe posture required by Rules.md.

Special case — Tier 4 (BLACK):
  Once Tier 4 is reached, the FSM does NOT restore automatically.
  A human operator must explicitly approve the session via the escalations
  workflow (API POST /escalations/{id}/approve).

Algorithm 2 state per session:
    current_tier          — integer {0, 1, 2, 3, 4}
    consecutive_below     — counter for hysteresis (resets on any upward move)

Rules.md:
  - FSM exception → fail restrictive to tier 4.
  - Tier 4 → block all tools and require escalation.
"""

from __future__ import annotations

import logging
from collections import defaultdict

from vigil.config.loader import load_config
from vigil.core.permission.bands import risk_to_tier

logger = logging.getLogger(__name__)


class PermissionController:
    """Algorithm 2: 5-tier FSM with asymmetric hysteresis.

    Maintains per-session state so that hysteresis counters survive across
    consecutive tool calls within the same session.

    Attributes:
        _hysteresis: Mapping from session_id to consecutive below-threshold
                     event count.
        _cfg:        Loaded VigilConfig for hysteresis threshold.
    """

    def __init__(self) -> None:
        """Initialise controller with empty per-session hysteresis counters."""
        self._hysteresis: dict[str, int] = defaultdict(int)
        self._cfg = load_config()

    def evaluate(
        self,
        risk: float,
        current_tier: int,
        session_id: str,
    ) -> int:
        """Evaluate the new tier given the updated risk score.

        Algorithm 2 logic:
            target_tier = risk_to_tier(risk)

            if target_tier > current_tier:
                # FAST RESTRICT — immediate transition.
                reset consecutive_below counter.
                return target_tier

            elif target_tier < current_tier and current_tier < 4:
                # Potential restoration — hysteresis applies.
                increment consecutive_below.
                if consecutive_below >= hysteresis_restore_events:
                    reset counter.
                    return target_tier
                else:
                    return current_tier  # Stay in current tier.

            else:
                # Same tier or Tier 4 lock — no change.
                return current_tier

        Args:
            risk:         Updated risk score Rt from Algorithm 1.
            current_tier: Active permission tier before this event.
            session_id:   Session identifier for hysteresis state.

        Returns:
            New permission tier (may be same as current_tier).
        """
        try:
            restore_threshold = self._cfg.tiers.hysteresis_restore_events
            target_tier = risk_to_tier(risk)

            # Tier 4 lock — only human operator can release.
            if current_tier == 4:
                logger.debug(
                    "fsm: session=%s tier=4 locked — operator approval required", session_id
                )
                return 4

            if target_tier > current_tier:
                # FAST RESTRICT: immediate escalation.
                logger.warning(
                    "fsm: RESTRICT session=%s tier %d→%d risk=%.1f",
                    session_id,
                    current_tier,
                    target_tier,
                    risk,
                )
                self._hysteresis[session_id] = 0
                return target_tier

            elif target_tier < current_tier:
                # SLOW RESTORE: hysteresis.
                self._hysteresis[session_id] += 1
                count = self._hysteresis[session_id]
                logger.debug(
                    "fsm: below-threshold event session=%s count=%d/%d",
                    session_id,
                    count,
                    restore_threshold,
                )
                if count >= restore_threshold:
                    logger.info(
                        "fsm: RESTORE session=%s tier %d→%d after %d events",
                        session_id,
                        current_tier,
                        target_tier,
                        count,
                    )
                    self._hysteresis[session_id] = 0
                    return target_tier
                else:
                    return current_tier

            else:
                # Same tier — maintain.
                return current_tier

        except Exception as exc:  # noqa: BLE001
            logger.error(
                "fsm: exception for session=%s: %s — failing restrictive to tier 4",
                session_id,
                exc,
            )
            return 4

    def reset_session(self, session_id: str) -> None:
        """Clear hysteresis state for a completed/terminated session.

        Args:
            session_id: Session to clear.
        """
        self._hysteresis.pop(session_id, None)
