"""@contained_tool decorator — Layer 1 Interceptor wrapper.

Rules.md invariants enforced here:
  1. Every tool call passes through containment (this decorator).
  2. Audit entry is written BEFORE the action executes.
  3. Honeytokens must already be planted (enforced by session manager).
  4. Unknown tool calls fail restrictive.
  5. Tier 4 blocks all tool execution.

Usage::

    @contained_tool
    async def send_email(session_id: str, to: str, subject: str, body: str) -> dict:
        ...

The decorated function's first positional argument *must* be ``session_id``.
The decorator injects the containment pipeline transparently.
"""

from __future__ import annotations

import asyncio
import functools
import logging
from typing import Any, Callable

logger = logging.getLogger(__name__)


class ToolDenied(Exception):
    """Raised when containment blocks a tool call.

    Attributes:
        tool_name:     Name of the blocked tool.
        session_id:    Owning session.
        reason:        Human-readable denial reason.
        tier:          Current permission tier at time of denial.
        risk:          Current risk score at time of denial.
    """

    def __init__(
        self,
        tool_name: str,
        session_id: str,
        reason: str,
        tier: int,
        risk: float,
    ) -> None:
        """Initialise ToolDenied."""
        super().__init__(
            f"[ToolDenied] tool={tool_name} session={session_id} "
            f"tier={tier} risk={risk:.1f} reason={reason}"
        )
        self.tool_name = tool_name
        self.session_id = session_id
        self.reason = reason
        self.tier = tier
        self.risk = risk


def contained_tool(func: Callable) -> Callable:
    """Decorator that wraps a tool function with the full containment pipeline.

    The pipeline for each call:
      1. Extract session_id and args.
      2. Hash args with per-session salt (never store plaintext).
      3. Load current session state (risk, tier, honeytokens).
      4. Run Layer 2 (Risk Scorer) on the TraceEvent.
      5. Run Layer 3 (Permission FSM) — may upgrade tier.
      6. Write audit entry to DB (BEFORE execution).
      7. Run Layer 4 (Enforcement Adapter) — deny or allow.
      8. If allowed, execute the real function.

    Args:
        func: An async callable whose first argument is ``session_id: str``.

    Returns:
        Wrapped async callable.

    Raises:
        ToolDenied: If the containment pipeline denies the tool call.
        ValueError: If session_id cannot be resolved from arguments.
    """

    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        # ── 1. Resolve session_id ─────────────────────────────────────────────
        session_id: str | None = None

        # Accept session_id as first positional or keyword argument.
        if args:
            session_id = args[0]
        if not session_id:
            session_id = kwargs.get("session_id")
        if not session_id:
            raise ValueError(
                f"contained_tool: {func.__name__} must receive 'session_id' "
                "as its first argument."
            )

        tool_name = func.__name__

        # ── 2. Import lazily to avoid circular imports ────────────────────────
        from vigil.core.interceptor.hashing import hash_args
        from vigil.core.interceptor.trace import TraceEvent
        from vigil.core.scoring.engine import RiskScoringEngine
        from vigil.core.permission.controller import PermissionController
        from vigil.core.enforcement.adapter import EnforcementAdapter
        from vigil.core.audit.writer import AuditWriter
        from vigil.core.session.manager import SessionManager

        manager = SessionManager()
        scorer = RiskScoringEngine()
        controller = PermissionController()
        enforcer = EnforcementAdapter()
        auditor = AuditWriter()

        # ── 3. Load session state ─────────────────────────────────────────────
        try:
            state = await manager.get_state(session_id)
        except Exception as exc:  # noqa: BLE001
            # Rules.md: fail restrictive on any state load error.
            logger.error(
                "contained_tool: failed to load session state for %s: %s",
                session_id,
                exc,
            )
            raise ToolDenied(
                tool_name=tool_name,
                session_id=session_id,
                reason="session state unavailable — fail restrictive",
                tier=4,
                risk=100.0,
            ) from exc

        risk_before = state["current_risk"]
        tier_before = state["current_tier"]
        salt = state["session_salt"]

        # ── 4. Hash arguments ─────────────────────────────────────────────────
        all_args: dict[str, Any] = {}
        if len(args) > 1:
            all_args["positional"] = list(args[1:])
        all_args.update(kwargs)
        args_hash = hash_args(all_args, salt)

        # ── 5. Run Risk Scorer (Algorithm 1) ──────────────────────────────────
        try:
            deception_registry = state.get("deception_registry", {})
            risk_after = scorer.score(
                tool_name=tool_name,
                args_hash=args_hash,
                risk_before=risk_before,
                deception_registry=deception_registry,
                raw_args=all_args,
            )
        except Exception as exc:  # noqa: BLE001
            # Rules.md: detector exception → max risk signal.
            logger.error(
                "contained_tool: risk scorer raised %s for session %s — "
                "treating as max risk (fail-safe)",
                exc,
                session_id,
            )
            risk_after = 100.0

        # ── 6. Run Permission FSM (Algorithm 2) ───────────────────────────────
        try:
            tier_after = controller.evaluate(
                risk=risk_after,
                current_tier=tier_before,
                session_id=session_id,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "contained_tool: FSM raised %s for session %s — "
                "failing restrictive to tier 4",
                exc,
                session_id,
            )
            tier_after = 4

        # ── 7. Build TraceEvent ───────────────────────────────────────────────
        allowed = enforcer.is_allowed(tool_name=tool_name, tier=tier_after)
        denial_reason = None if allowed else f"tool not permitted at tier {tier_after}"

        trace = TraceEvent(
            session_id=session_id,
            tool_name=tool_name,
            args_hash=args_hash,
            allowed=allowed,
            denial_reason=denial_reason,
            risk_before=risk_before,
            risk_after=risk_after,
            tier_before=tier_before,
            tier_after=tier_after,
        )

        # ── 8. Write audit entry BEFORE execution ─────────────────────────────
        # Rules.md invariant 4: audit committed before the action executes.
        try:
            await auditor.append(session_id=session_id, trace=trace)
        except Exception as exc:  # noqa: BLE001
            # Rules.md: audit failure → deny and fail restrictive.
            logger.error(
                "contained_tool: audit write failed for session %s: %s — "
                "denying tool call (fail-safe)",
                session_id,
                exc,
            )
            raise ToolDenied(
                tool_name=tool_name,
                session_id=session_id,
                reason="audit write failed — fail restrictive",
                tier=tier_after,
                risk=risk_after,
            ) from exc

        # ── 9. Update session state ───────────────────────────────────────────
        await manager.update_risk_and_tier(
            session_id=session_id,
            risk=risk_after,
            tier=tier_after,
        )

        # ── 10. Enforce ───────────────────────────────────────────────────────
        if not allowed:
            logger.warning(
                "contained_tool: DENIED tool=%s session=%s tier=%d risk=%.1f",
                tool_name,
                session_id,
                tier_after,
                risk_after,
            )
            raise ToolDenied(
                tool_name=tool_name,
                session_id=session_id,
                reason=denial_reason or "denied by enforcement adapter",
                tier=tier_after,
                risk=risk_after,
            )

        # ── 11. Execute tool ──────────────────────────────────────────────────
        logger.debug(
            "contained_tool: ALLOWED tool=%s session=%s tier=%d risk=%.1f",
            tool_name,
            session_id,
            tier_after,
            risk_after,
        )
        return await func(*args, **kwargs)

    return wrapper
