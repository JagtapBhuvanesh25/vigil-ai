"""TraceEvent — the canonical record of a single tool call interception.

Every tool call processed by the @contained_tool decorator produces one
TraceEvent.  The event is the input to Layer 2 (Risk Scorer) and is also
embedded in the audit log payload.

Rules.md invariant 1: every tool call passes through containment; the
TraceEvent is the artefact that proves it did.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class TraceEvent(BaseModel):
    """Immutable record of a single intercepted tool call.

    Attributes:
        trace_id:     Unique identifier for this interception event.
        session_id:   Session that owns this tool call.
        tool_name:    The name of the tool being called (e.g. 'send_email').
        args_hash:    Per-session salted SHA-256 of the serialised arguments.
                      Never stores raw argument values.
        timestamp:    UTC timestamp when the interception occurred.
        allowed:      Whether the tool call was ultimately permitted.
        denial_reason: Populated if allowed=False.
        risk_before:  Risk score (Rt-1) before this event was processed.
        risk_after:   Risk score (Rt) after Algorithm 1 ran on this event.
        tier_before:  Permission tier before this event.
        tier_after:   Permission tier after Algorithm 2 ran.
    """

    trace_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    tool_name: str
    args_hash: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    allowed: bool = False
    denial_reason: str | None = None
    risk_before: float = 0.0
    risk_after: float = 0.0
    tier_before: int = 0
    tier_after: int = 0

    model_config = {"frozen": True}
