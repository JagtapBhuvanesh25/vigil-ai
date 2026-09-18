"""Per-session salted SHA-256 argument hashing.

Rules.md: Every session must generate a unique random salt stored in the
session record.  This salt is used to hash tool arguments so that argument
content is never stored in plaintext in the audit log.

The same tool called with the same arguments in *different* sessions produces
*different* hashes, preventing correlation across sessions.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from typing import Any


def generate_session_salt() -> str:
    """Generate a cryptographically random 32-byte hex salt.

    Returns:
        64-character lowercase hex string.
    """
    return secrets.token_hex(32)


def hash_args(args: Any, salt: str) -> str:
    """Produce a per-session salted SHA-256 hash of tool arguments.

    The hash is computed over the JSON-serialised arguments prefixed with the
    session salt.  This prevents:
    - Plaintext argument leakage in audit entries.
    - Cross-session argument correlation.

    Args:
        args:  Arbitrary Python object representing the tool arguments.
               Must be JSON-serialisable; if not, a safe fallback is used.
        salt:  Per-session hex salt from the session record.

    Returns:
        64-character lowercase hex SHA-256 digest.
    """
    try:
        payload = json.dumps(args, sort_keys=True, default=str)
    except (TypeError, ValueError):
        # Fail-safe: if args cannot be serialised, hash a sentinel so the
        # audit entry is still created (Rules.md: fail restrictive).
        payload = "<unserializable>"

    raw = f"{salt}:{payload}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
