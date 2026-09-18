"""Honeytoken hit detector — Layer 2 sub-detector.

Checks whether a tool call's arguments reference any session-scoped decoy
artefacts (honeytokens).  A single honeytoken hit produces a maximum-strength
signal (1.0), triggering an immediate risk spike that pushes the session into
Tier 4 (Blackout) per Algorithm 1 with weight_deception=80.

Rules.md invariants:
  - Honeytokens exist BEFORE the first tool call (planted by session manager).
  - Honeytoken hit → immediate Tier 4 (via Algorithm 1 spike).
  - Detector exception → max risk (fail-safe).
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class DeceptionDetector:
    """Honeytoken hit detector.

    Checks whether any value in the tool call arguments matches a registered
    decoy identifier from the session's honeytoken registry.

    Attributes:
        None (stateless; the registry is passed per call).
    """

    def detect(
        self,
        tool_name: str,
        raw_args: Any,
        deception_registry: dict[str, str],
    ) -> float:
        """Detect honeytoken interaction in tool call arguments.

        Args:
            tool_name:          Name of the tool being called.
            raw_args:           Raw arguments (dict, list, or scalar).
            deception_registry: Mapping of {token_value: token_type} for this
                                session.  Populated by deception/registry.py
                                before the first tool call.

        Returns:
            Float signal in [0.0, 1.0]:
            - 1.0 if any honeytoken value appears in the arguments.
            - 0.0 if no honeytoken is touched.
            - 1.0 if an exception occurred (fail-safe).
        """
        try:
            if not deception_registry:
                return 0.0

            # Flatten args to a single scannable string.
            if isinstance(raw_args, dict):
                text = " ".join(str(v) for v in raw_args.values())
            elif isinstance(raw_args, (list, tuple)):
                text = " ".join(str(v) for v in raw_args)
            else:
                text = str(raw_args)

            # Also include the tool name itself (a tool-name honeytoken is valid).
            scan_text = f"{tool_name} {text}"

            for token_value, token_type in deception_registry.items():
                if token_value and token_value in scan_text:
                    logger.warning(
                        "deception: HONEYTOKEN HIT token_type=%s tool=%s",
                        token_type,
                        tool_name,
                    )
                    return 1.0

            return 0.0

        except Exception as exc:  # noqa: BLE001
            logger.error(
                "deception: exception during detection tool=%s: %s — "
                "returning 1.0 (fail-safe)",
                tool_name,
                exc,
            )
            return 1.0
