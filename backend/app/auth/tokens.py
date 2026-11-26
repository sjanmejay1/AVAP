"""Access tokens (short-lived HS256 JWTs) and opaque refresh tokens."""

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import jwt

_ALGORITHM = "HS256"
_ACCESS_TOKEN_TYPE = "access"  # noqa: S105 # nosec B105 -- token type label
_REFRESH_TOKEN_BYTES = 32


class InvalidAccessTokenError(Exception):
    """The access token is malformed, expired, or has a bad signature."""


def create_access_token(user_id: uuid.UUID, secret: str, ttl_minutes: int) -> str:
    """Sign a JWT whose subject is the user's id."""
    now = datetime.now(UTC)
    claims = {
        "sub": str(user_id),
        "type": _ACCESS_TOKEN_TYPE,
        "iat": now,
        "exp": now + timedelta(minutes=ttl_minutes),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(claims, secret, algorithm=_ALGORITHM)


def decode_access_token(token: str, secret: str) -> uuid.UUID:
    """Verify the token and return the user id it was issued for.

    Only HS256 is accepted, which rules out "alg: none" and key-confusion
    attacks. exp, iat and sub are required.

    Raises:
        InvalidAccessTokenError: for any verification failure.
    """
    try:
        claims = jwt.decode(
            token,
            secret,
            algorithms=[_ALGORITHM],
            options={"require": ["exp", "iat", "sub"]},
        )
        if claims.get("type") != _ACCESS_TOKEN_TYPE:
            raise InvalidAccessTokenError("Wrong token type.")
        return uuid.UUID(claims["sub"])
    except (jwt.PyJWTError, ValueError) as exc:
        raise InvalidAccessTokenError("Invalid access token.") from exc


def generate_refresh_token() -> str:
    """Return a new random, URL-safe refresh token (256 bits)."""
    return secrets.token_urlsafe(_REFRESH_TOKEN_BYTES)


def hash_refresh_token(token: str) -> str:
    """Return the SHA-256 hex digest stored in place of the token.

    A fast hash is appropriate here: the token is 256 random bits, so it
    cannot be brute-forced the way a password can.
    """
    return hashlib.sha256(token.encode()).hexdigest()
