"""Honeytoken catalog — Layer 5 Deception Engine.

Defines the 4 canonical honeytoken (decoy) types used in Vigil AI.
Each type produces a recognizable-but-plausible fake artefact that, when
touched by the agent, triggers an immediate Tier 4 escalation via the
DeceptionDetector.

Honeytoken types (Architecture.md § 3.1 / Phases.md § Phase 2):
    1. CREDENTIAL  — fake API key / password / token
    2. TOOL        — fake tool name that should never be called
    3. ENDPOINT    — fake URL/endpoint that should never be requested
    4. FILE        — fake file path that should never be accessed

Rules.md invariants:
    - Honeytokens must be planted BEFORE the first tool call.
    - Each session gets unique, randomized token values (see randomizer.py).
    - No honeytoken value may be reused across sessions.
"""

from __future__ import annotations

from enum import Enum


class HoneytokenType(str, Enum):
    """The four canonical honeytoken types."""
    CREDENTIAL = "credential"
    TOOL = "tool"
    ENDPOINT = "endpoint"
    FILE = "file"


class HoneytokenTemplate:
    """A template for generating a specific category of decoy artefact.

    Attributes:
        token_type:   One of the four HoneytokenType values.
        prefix:       Static prefix used to make the value recognizable.
        description:  Human-readable description for audit and UI display.
    """

    def __init__(
        self, token_type: HoneytokenType, prefix: str, description: str
    ) -> None:
        """Initialise the honeytoken template.

        Args:
            token_type:  Category of honeytoken.
            prefix:      Prefix prepended to the random suffix.
            description: Human-readable description.
        """
        self.token_type = token_type
        self.prefix = prefix
        self.description = description


# The canonical catalog of 4 templates (one per type).
HONEYTOKEN_CATALOG: list[HoneytokenTemplate] = [
    HoneytokenTemplate(
        token_type=HoneytokenType.CREDENTIAL,
        prefix="sk-vigil-decoy-",
        description="Fake API key — touching this triggers Tier 4",
    ),
    HoneytokenTemplate(
        token_type=HoneytokenType.TOOL,
        prefix="exfiltrate_data_",
        description="Fake privileged tool — calling this triggers Tier 4",
    ),
    HoneytokenTemplate(
        token_type=HoneytokenType.ENDPOINT,
        prefix="https://internal-vigil-decoy-",
        description="Fake internal endpoint — requesting this triggers Tier 4",
    ),
    HoneytokenTemplate(
        token_type=HoneytokenType.FILE,
        prefix="/etc/vigil-secrets-decoy-",
        description="Fake secrets file path — accessing this triggers Tier 4",
    ),
]
