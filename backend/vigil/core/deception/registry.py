"""Session-scoped honeytoken registry — Layer 5 Deception Engine.

Materializes honeytokens for a session from the catalog + randomizer and
maintains the in-session registry that the DeceptionDetector queries on
every tool call.

Rules.md invariant 5:
    Honeytokens must exist BEFORE the first tool call.
    The SessionManager calls `plant()` immediately after session creation.

Architecture.md:
    4 honeytoken types planted per session.
    Types: credential, tool, endpoint, file.
"""

from __future__ import annotations

import logging

from vigil.core.deception.catalog import HONEYTOKEN_CATALOG, HoneytokenType
from vigil.core.deception.randomizer import make_honeytoken_value

logger = logging.getLogger(__name__)


class HoneytokenRegistry:
    """Per-session honeytoken registry.

    Generates and stores the 4 session-scoped honeytoken values.
    The registry is a dict mapping {token_value: token_type_str} which is
    directly consumable by the DeceptionDetector.

    Attributes:
        session_id:  Owning session.
        _registry:   Mapping of {token_value: type_string} for fast lookup.
    """

    def __init__(self, session_id: str) -> None:
        """Initialise an empty registry for a session.

        Args:
            session_id: The owning session identifier.
        """
        self.session_id = session_id
        self._registry: dict[str, str] = {}

    def plant(self) -> dict[str, str]:
        """Generate and register one honeytoken per catalog type.

        Called by SessionManager immediately after session creation.
        Generates 4 unique random tokens (one per HoneytokenType).

        Returns:
            The populated registry dict {token_value: type_string}.
            Also stores the registry internally for future queries.

        Raises:
            RuntimeError: If already planted (re-planting is forbidden to
                          prevent enumeration via repeated calls).
        """
        if self._registry:
            raise RuntimeError(
                f"HoneytokenRegistry: session {self.session_id} already planted. "
                "Re-planting is not permitted."
            )

        for template in HONEYTOKEN_CATALOG:
            value = make_honeytoken_value(prefix=template.prefix)
            self._registry[value] = template.token_type.value
            logger.debug(
                "deception: planted %s token for session=%s",
                template.token_type.value,
                self.session_id,
            )

        logger.info(
            "deception: %d honeytokens planted for session=%s",
            len(self._registry),
            self.session_id,
        )
        return dict(self._registry)

    def get_registry(self) -> dict[str, str]:
        """Return the current honeytoken registry.

        Returns:
            Shallow copy of {token_value: type_string}.
            Returns empty dict if plant() has not been called.
        """
        return dict(self._registry)

    def is_planted(self) -> bool:
        """Return whether honeytokens have been planted for this session.

        Returns:
            True if plant() has been called and registry is non-empty.
        """
        return bool(self._registry)
