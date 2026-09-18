"""JWT authentication utilities for Vigil AI.

Rules.md: On API startup, assert VIGIL_API_KEY and VIGIL_JWT_SECRET are not
          set to their placeholder values. Refuse to start if they are.
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

_PLACEHOLDER_API_KEY = "CHANGE_ME_VIGIL_API_KEY"
_PLACEHOLDER_JWT_SECRET = "CHANGE_ME_JWT_SECRET_AT_LEAST_32_CHARS"

_bearer = HTTPBearer(auto_error=False)
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def validate_secrets_on_startup() -> None:
    """Assert secrets are not at placeholder values.

    Called during FastAPI startup. Raises RuntimeError and prevents the server
    from starting if placeholder values are detected.
    """
    api_key = os.environ.get("VIGIL_API_KEY", _PLACEHOLDER_API_KEY)
    jwt_secret = os.environ.get("VIGIL_JWT_SECRET", _PLACEHOLDER_JWT_SECRET)

    if api_key == _PLACEHOLDER_API_KEY:
        raise RuntimeError(
            "VIGIL_API_KEY is still set to its placeholder value. "
            "Copy .env.example to .env and set a real key before starting."
        )
    if jwt_secret == _PLACEHOLDER_JWT_SECRET:
        raise RuntimeError(
            "VIGIL_JWT_SECRET is still set to its placeholder value. "
            "Copy .env.example to .env and set a real secret before starting."
        )


def _get_api_key() -> str:
    """Return the configured API key from env."""
    return os.environ.get("VIGIL_API_KEY", "")


def _get_jwt_secret() -> str:
    """Return the configured JWT secret from env."""
    return os.environ.get("VIGIL_JWT_SECRET", "")


def create_access_token(subject: str, expires_minutes: int = 480) -> str:
    """Create a signed JWT access token for dashboard authentication.

    Args:
        subject: The token subject (e.g. 'operator').
        expires_minutes: Token lifetime in minutes (default 8 hours).

    Returns:
        Signed JWT string.
    """
    try:
        from jose import jwt
    except ImportError as exc:
        raise RuntimeError("python-jose not installed") from exc

    expire = datetime.now(tz=timezone.utc) + timedelta(minutes=expires_minutes)
    payload: dict[str, Any] = {"sub": subject, "exp": expire}
    return jwt.encode(payload, _get_jwt_secret(), algorithm="HS256")


def verify_api_key(api_key: str = Security(_api_key_header)) -> str:
    """FastAPI dependency: verify X-API-Key header.

    Raises 401 if the key is missing or does not match VIGIL_API_KEY.
    """
    if not api_key or api_key != _get_api_key():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )
    return api_key
