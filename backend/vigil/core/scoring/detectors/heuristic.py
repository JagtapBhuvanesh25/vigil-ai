"""Heuristic injection-pattern detector — Layer 2 sub-detector.

Scans tool call arguments for known prompt-injection patterns loaded from
``injection_patterns.yaml``.  Each match contributes a score of 1.0 (full
signal); partial matches are treated as 0.0 (no half-measures).

Rules.md:
  - Detector exception → treat as max risk (1.0) — fail-safe rule.
  - Never fail open.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_PATTERNS_PATH = Path(__file__).parent / "injection_patterns.yaml"

# Compiled pattern cache — loaded once at import time.
_compiled: list[tuple[re.Pattern, str]] = []


def _load_patterns() -> list[tuple[re.Pattern, str]]:
    """Load and compile injection patterns from YAML.

    Returns:
        List of (compiled_regex, label) tuples.
        Skips entries that fail to compile (logged, never fail-open).
    """
    try:
        data = yaml.safe_load(_PATTERNS_PATH.read_text(encoding="utf-8"))
        compiled = []
        for entry in data.get("patterns", []):
            try:
                compiled.append(
                    (re.compile(entry["pattern"], re.IGNORECASE), entry["label"])
                )
            except re.error as exc:
                logger.warning("heuristic: failed to compile pattern %r: %s", entry, exc)
        return compiled
    except Exception as exc:  # noqa: BLE001
        logger.error("heuristic: failed to load injection_patterns.yaml: %s", exc)
        return []


_compiled = _load_patterns()


class HeuristicDetector:
    """Prompt-injection heuristic detector.

    Scans the serialised representation of tool arguments against the known
    injection pattern list.  Returns a normalised signal score in [0.0, 1.0].

    Signal:
        1.0  — at least one pattern matched (injection detected).
        0.0  — no patterns matched.

    Attributes:
        patterns: Loaded (compiled_regex, label) list.
    """

    def __init__(self) -> None:
        """Initialise with the globally compiled pattern list."""
        self.patterns = _compiled

    def detect(self, tool_name: str, raw_args: Any) -> float:
        """Run heuristic detection on tool call arguments.

        Args:
            tool_name: Name of the tool being called (included in scan text).
            raw_args:  Raw argument dict or string passed to the tool.

        Returns:
            Float signal in [0.0, 1.0]:
            - 1.0 if any injection pattern matched.
            - 0.0 if no patterns matched.
            - 1.0 if an exception occurred (fail-safe).
        """
        try:
            # Flatten args to a single scannable string.
            if isinstance(raw_args, dict):
                text = " ".join(str(v) for v in raw_args.values())
            elif isinstance(raw_args, (list, tuple)):
                text = " ".join(str(v) for v in raw_args)
            else:
                text = str(raw_args)

            scan_text = f"{tool_name} {text}"

            for pattern, label in self.patterns:
                if pattern.search(scan_text):
                    logger.warning(
                        "heuristic: injection pattern matched label=%s tool=%s",
                        label,
                        tool_name,
                    )
                    return 1.0

            return 0.0

        except Exception as exc:  # noqa: BLE001
            # Rules.md: detector exception → treat as max risk (fail-safe).
            logger.error(
                "heuristic: exception during detection for tool=%s: %s — "
                "returning 1.0 (fail-safe)",
                tool_name,
                exc,
            )
            return 1.0
