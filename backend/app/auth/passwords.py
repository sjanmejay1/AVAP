"""Argon2id password hashing (argon2-cffi defaults follow RFC 9106)."""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

_hasher = PasswordHasher()

# A real hash verified when the email is unknown, so a login for a
# non-existent account costs the same time as one with a wrong password.
_DUMMY_HASH = _hasher.hash("timing-equalizer-not-a-real-password")


def hash_password(password: str) -> str:
    """Return an Argon2id hash of the password."""
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Return True if the password matches the stored hash."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def burn_verification_time(password: str) -> None:
    """Spend one verification's worth of time without a real account."""
    verify_password(_DUMMY_HASH, password)


def needs_rehash(password_hash: str) -> bool:
    """Return True if the hash uses outdated parameters."""
    return _hasher.check_needs_rehash(password_hash)
