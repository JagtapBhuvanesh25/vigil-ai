"""Enforcement Adapter — Layer 4, dispatcher for application vs Docker enforcement.

Routes tool execution through the appropriate enforcement adapter based on:
  1. The current permission tier (from the Permission FSM).
  2. Whether Docker is available.

Application Adapter (always available):
  - Checks tool name against the tools_map for the current tier.
  - Denies any tool not in the allowed set.
  - Runs entirely in-process, no Docker dependency.

Docker/OS Adapter (optional, Linux+Docker only):
  - Additionally enforces container-level syscall restrictions (seccomp JSON).
  - Uses pre-warmed ContainerPool.
  - Degrades gracefully to application adapter if Docker is unavailable.

Rules.md:
  - Docker unavailable → application adapter enforces, fail restrictive for
    container-isolated operations.
  - Unknown tools → always denied (fail-safe).
  - Tier 4 → always denied regardless of tool.
"""

from __future__ import annotations

import logging
from pathlib import Path

from vigil.core.permission.tools_map import is_tool_allowed

logger = logging.getLogger(__name__)

_PROFILES_DIR = Path(__file__).parent / "profiles"


class EnforcementAdapter:
    """Layer 4 Enforcement Adapter — dual-mode tool execution gate.

    Implements both application-level and Docker-level enforcement.
    All enforcement decisions are based on the Permission FSM tier output.

    Attributes:
        _docker_available: Whether Docker enforcement is available.
    """

    def __init__(self) -> None:
        """Initialise adapter (Docker availability checked lazily)."""
        self._docker_available: bool | None = None

    def _check_docker(self) -> bool:
        """Check Docker availability (cached after first call).

        Returns:
            True if Docker daemon is reachable.
        """
        if self._docker_available is None:
            try:
                import docker  # type: ignore[import]
                client = docker.from_env()
                client.ping()
                self._docker_available = True
                logger.debug("enforcement: Docker adapter available")
            except Exception:  # noqa: BLE001
                self._docker_available = False
                logger.debug(
                    "enforcement: Docker not available — application adapter active"
                )
        return self._docker_available

    def is_allowed(self, tool_name: str, tier: int) -> bool:
        """Application-level permission check (always runs first).

        This is the primary gate.  Docker/OS enforcement is additional.

        Args:
            tool_name: Name of the tool being called.
            tier:      Current permission tier from the FSM.

        Returns:
            True if the tool is permitted at this tier.
            False for Tier 4, unknown tools, or non-permitted tools.
        """
        # Tier 4 — full block, no exceptions.
        if tier == 4:
            logger.warning(
                "enforcement: DENIED tool=%s tier=4 (Blackout — escalation required)",
                tool_name,
            )
            return False

        allowed = is_tool_allowed(tool_name=tool_name, tier=tier)
        if not allowed:
            logger.warning(
                "enforcement: DENIED tool=%s tier=%d (not in allowed set)",
                tool_name,
                tier,
            )
        return allowed

    def get_seccomp_profile_path(self, tier: int) -> Path | None:
        """Return the path to the seccomp JSON profile for a tier.

        Only meaningful when Docker adapter is available.

        Args:
            tier: Tier number (0–4).

        Returns:
            Absolute path to the seccomp profile JSON file, or None.
        """
        profile = _PROFILES_DIR / f"tier{tier}_seccomp.json"
        if profile.exists():
            return profile
        logger.warning("enforcement: seccomp profile not found for tier %d", tier)
        return None

    def get_apparmor_profile_name(self, tier: int) -> str:
        """Return the AppArmor profile name for a tier.

        Args:
            tier: Tier number (0–4).

        Returns:
            AppArmor profile name string.
        """
        return f"vigil_tier{tier}"
