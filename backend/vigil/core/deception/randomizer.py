"""Per-session random honeytoken name generation — Layer 5 Deception Engine.

Generates cryptographically random suffixes for honeytoken values to prevent
enumeration attacks.  Each session receives distinct token values so that
an adversary cannot learn one session's tokens from another.

Rules.md:
    - Risk scores and decoy identifiers are isolated to their originating session.
    - No token reuse across distinct sessions.
    - Token values must be unpredictable (random, not sequential).
"""

from __future__ import annotations

import secrets
import string


def generate_token_suffix(length: int = 16) -> str:
    """Generate a cryptographically random alphanumeric suffix.

    Args:
        length: Number of characters in the suffix (default 16).

    Returns:
        Random lowercase alphanumeric string of the given length.
    """
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def make_honeytoken_value(prefix: str, suffix_length: int = 16) -> str:
    """Combine a static prefix with a random suffix to produce a honeytoken value.

    Args:
        prefix:        Static prefix from the honeytoken template catalog.
        suffix_length: Length of the random suffix (default 16).

    Returns:
        Complete honeytoken string (prefix + random suffix).
    """
    suffix = generate_token_suffix(suffix_length)
    return f"{prefix}{suffix}"
