"""URL Pre-check integration for Layer 1 Interceptor.

Phase 5: Safe Browsing Shield — integrates precheck_url() into the
containment pipeline so that every http_get / web_search tool call is
checked against the Threat Intelligence DB BEFORE execution.

Integration points:
  - Called inside @contained_tool wrapper for egress tools (http_get, web_search).
  - BLOCK result → raise ToolDenied immediately (fail-safe, Rules.md).
  - WARN result → pre-elevate session risk by +15 before execution continues.

Rules.md invariants enforced here:
  - Invariant 9: ALL outbound URL calls MUST pass precheck first.
  - DB fault → BLOCK (fail restrictive).
  - Latency target: < 50ms (pure DB lookup, no network).

Usage (called from @contained_tool wrapper or inline in egress tools)::

    from vigil.core.interceptor.url_precheck import run_url_precheck
    await run_url_precheck(url=url, session_id=session_id, db_session=db)
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

# Module-level import so the symbol is patchable in tests
from vigil.threat_intel.precheck import precheck_url, PreCheckAction, WARN_RISK_DELTA  # noqa: E402

logger = logging.getLogger(__name__)

# Egress tool names that require URL pre-check before execution
EGRESS_TOOL_NAMES: frozenset[str] = frozenset({"http_get", "web_search"})

# Pre-check latency warning threshold (milliseconds)
LATENCY_WARN_MS: float = 50.0


async def run_url_precheck(
    url: str,
    session_id: str,
    db_session: AsyncSession,
) -> None:
    """Run URL pre-check against the Threat Intelligence DB.

    Must be called before executing any egress tool (http_get, web_search).
    Raises ToolDenied on BLOCK. Pre-elevates session risk on WARN.
    Passes through silently on PASS (clean URL).

    Rules.md Invariant 9: This function is the enforcement gate for all
    outbound network calls. It MUST be called before the tool executes.

    Args:
        url:        The target URL from the tool call arguments.
        session_id: Active session UUID (for risk elevation and audit).
        db_session: An active async SQLAlchemy session.

    Raises:
        ToolDenied: If the URL is in the threat DB with confidence ≥ 0.70,
                    or if the DB is unavailable (fail-safe BLOCK).
    """
    from vigil.core.interceptor.wrapper import ToolDenied

    t_start = time.perf_counter()

    try:
        result = await precheck_url(url=url, db_session=db_session)
    except Exception as exc:  # noqa: BLE001
        # Unexpected error → fail restrictive
        logger.error(
            "url_precheck: unexpected error for url=%s session=%s: %s — BLOCKING",
            url,
            session_id,
            exc,
        )
        raise ToolDenied(
            tool_name="url_precheck",
            session_id=session_id,
            reason=f"URL pre-check failed (fail-safe BLOCK): {exc}",
            tier=0,
            risk=100.0,
        ) from exc

    elapsed_ms = (time.perf_counter() - t_start) * 1000.0
    if elapsed_ms > LATENCY_WARN_MS:
        logger.warning(
            "url_precheck: latency=%.1fms exceeds %.0fms target for url=%s",
            elapsed_ms,
            LATENCY_WARN_MS,
            url,
        )

    if result.action == PreCheckAction.BLOCK:
        logger.warning(
            "url_precheck: BLOCKED url=%s session=%s confidence=%.2f reason=%s",
            url,
            session_id,
            result.confidence,
            result.reason,
        )
        raise ToolDenied(
            tool_name="url_precheck",
            session_id=session_id,
            reason=f"URL blocked by Safe Browsing Shield: {result.reason}",
            tier=0,
            risk=result.confidence * 100.0,
        )

    if result.action == PreCheckAction.WARN:
        logger.warning(
            "url_precheck: WARN url=%s session=%s confidence=%.2f — pre-elevating risk +%.0f",
            url,
            session_id,
            result.confidence,
            WARN_RISK_DELTA,
        )
        await _elevate_session_risk(session_id=session_id, delta=WARN_RISK_DELTA)

    # PASS — no action
    logger.debug(
        "url_precheck: PASS url=%s session=%s latency=%.1fms",
        url,
        session_id,
        elapsed_ms,
    )


async def _elevate_session_risk(session_id: str, delta: float) -> None:
    """Pre-elevate session risk by delta points for a WARN pre-check result.

    This updates the in-memory session state (SessionManager) so that the
    Permission FSM sees the elevated risk on the next evaluation.

    Args:
        session_id: Session to update.
        delta:      Risk delta to add (e.g. 15.0 for WARN).
    """
    try:
        from vigil.core.session.manager import SessionManager

        mgr = SessionManager()
        state = await mgr.get_state(session_id)
        current_risk = float(state.get("current_risk", 0.0))
        new_risk = min(current_risk + delta, 100.0)
        await mgr.update_risk_and_tier(
            session_id=session_id,
            risk=new_risk,
            tier=state.get("current_tier", 0),
        )
        logger.debug(
            "url_precheck: risk elevated %s: %.1f → %.1f (+%.1f)",
            session_id,
            current_risk,
            new_risk,
            delta,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "url_precheck: failed to elevate risk for session %s: %s",
            session_id,
            exc,
        )


def is_egress_tool(tool_name: str) -> bool:
    """Return True if the tool is an egress tool requiring URL pre-check.

    Args:
        tool_name: Tool name string from @contained_tool.

    Returns:
        True if the tool should be intercepted by the URL pre-check gate.
    """
    return tool_name in EGRESS_TOOL_NAMES


__all__ = [
    "EGRESS_TOOL_NAMES",
    "LATENCY_WARN_MS",
    "run_url_precheck",
    "is_egress_tool",
]
