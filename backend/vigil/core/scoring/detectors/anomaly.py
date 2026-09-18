"""Behavioral n-gram anomaly detector — Layer 2 sub-detector.

Detects unusual sequences of tool calls by comparing against an expected
n-gram transition model.  Each session maintains a running call history;
the detector flags when the current tool is unexpected given recent context.

The model is intentionally simple (bigram transitions) to be fully testable
without an external LLM.  More sophisticated models can be plugged in later
as a replacement for the score() method without changing the interface.

Rules.md:
  - Detector exception → treat as max risk (1.0) — fail-safe rule.
  - No external network calls, no LLM dependency.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

logger = logging.getLogger(__name__)

# Expected tool-call bigram transitions.
# Outer key: tool that was just called.
# Inner set: tools that are expected to follow.
# A tool NOT in the expected set triggers anomaly.
# Deliberately conservative: an empty expected set means any follower is normal.
_EXPECTED_TRANSITIONS: dict[str, set[str]] = {
    "read_email": {"draft_reply", "flag_email", "send_email", "schedule_meeting",
                   "read_email", "http_get"},
    "draft_reply": {"send_email", "draft_reply"},
    "send_email": {"read_email"},
    "flag_email": {"read_email"},
    "schedule_meeting": {"read_email"},
    "http_get": {"read_email", "flag_email"},
    # Any unknown tool can follow anything (unknown → unknown is not flagged
    # by *this* detector; the wrapper handles unknown tools separately).
}

# Tools that should NEVER appear in a normal session.
_ALWAYS_ANOMALOUS: frozenset[str] = frozenset({
    "exec_shell", "delete_all", "exfiltrate", "write_arbitrary_file",
})


class AnomalyDetector:
    """Behavioral n-gram anomaly detector.

    Maintains a call history per session and detects unusual transitions.

    Attributes:
        _history: Mapping from session_id to the last N tool names called.
        _max_history: Maximum history length to retain per session.
    """

    def __init__(self, max_history: int = 10) -> None:
        """Initialise the anomaly detector.

        Args:
            max_history: Number of past tool names to track per session.
        """
        self._history: dict[str, list[str]] = defaultdict(list)
        self._max_history = max_history

    def detect(self, session_id: str, tool_name: str) -> float:
        """Compute anomaly signal for the current tool call.

        Args:
            session_id: Owning session identifier.
            tool_name:  Name of the tool being called.

        Returns:
            Float signal in [0.0, 1.0]:
            - 1.0 if the call is always-anomalous or the bigram is unexpected.
            - 0.5 if the previous tool has no model entry (partial uncertainty).
            - 0.0 if the transition is expected.
            - 1.0 if an exception occurred (fail-safe).
        """
        try:
            # Always-anomalous tools → immediate max signal.
            if tool_name in _ALWAYS_ANOMALOUS:
                logger.warning(
                    "anomaly: always-anomalous tool=%s session=%s", tool_name, session_id
                )
                return 1.0

            history = self._history[session_id]
            signal = 0.0

            if history:
                prev = history[-1]
                expected = _EXPECTED_TRANSITIONS.get(prev)
                if expected is None:
                    # Previous tool not modelled — slight elevation (partial unknown).
                    signal = 0.5
                elif tool_name not in expected:
                    logger.warning(
                        "anomaly: unexpected transition %s→%s session=%s",
                        prev,
                        tool_name,
                        session_id,
                    )
                    signal = 1.0

            # Update history (sliding window).
            history.append(tool_name)
            if len(history) > self._max_history:
                history.pop(0)

            return signal

        except Exception as exc:  # noqa: BLE001
            logger.error(
                "anomaly: exception for tool=%s session=%s: %s — returning 1.0 (fail-safe)",
                tool_name,
                session_id,
                exc,
            )
            return 1.0

    def reset_session(self, session_id: str) -> None:
        """Clear history for a session (called on session teardown).

        Args:
            session_id: Session to clear.
        """
        self._history.pop(session_id, None)
