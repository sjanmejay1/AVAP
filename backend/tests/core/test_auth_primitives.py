"""Pure auth primitives: hashing, tokens, encryption, throttling, and the
startup secret checks."""

import base64
import uuid

import pytest

from app.auth.key_cipher import KeyCipher, KeyDecryptionError
from app.auth.passwords import hash_password, verify_password
from app.auth.throttle import SlidingWindowThrottle
from app.auth.tokens import (
    InvalidAccessTokenError,
    create_access_token,
    decode_access_token,
    generate_refresh_token,
    hash_refresh_token,
)
from app.core.config import Settings

SECRET = "s" * 64
FERNET_KEY = base64.urlsafe_b64encode(b"k" * 32).decode()


def test_password_hash_is_argon2id_and_verifies():
    hashed = hash_password("a long passphrase")
    assert hashed.startswith("$argon2id$")
    assert verify_password(hashed, "a long passphrase")
    assert not verify_password(hashed, "a wrong passphrase")


def test_verify_password_handles_garbage_hash():
    assert not verify_password("not-a-hash", "anything")


def test_access_token_round_trip():
    user_id = uuid.uuid4()
    token = create_access_token(user_id, SECRET, ttl_minutes=5)
    assert decode_access_token(token, SECRET) == user_id


def test_access_token_with_other_secret_is_rejected():
    token = create_access_token(uuid.uuid4(), SECRET, ttl_minutes=5)
    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(token, "x" * 64)


def test_refresh_tokens_are_random_and_hashed():
    first, second = generate_refresh_token(), generate_refresh_token()
    assert first != second
    assert len(hash_refresh_token(first)) == 64
    assert hash_refresh_token(first) == hash_refresh_token(first)


def test_key_cipher_round_trip_and_wrong_key():
    cipher = KeyCipher(FERNET_KEY)
    ciphertext = cipher.encrypt("hf_secret")
    assert "hf_secret" not in ciphertext
    assert cipher.decrypt(ciphertext) == "hf_secret"

    other = KeyCipher(base64.urlsafe_b64encode(b"o" * 32).decode())
    with pytest.raises(KeyDecryptionError):
        other.decrypt(ciphertext)


def test_throttle_blocks_after_limit_and_resets():
    throttle = SlidingWindowThrottle(max_events=2, window_seconds=60)
    throttle.record("k")
    assert not throttle.is_blocked("k")
    throttle.record("k")
    assert throttle.is_blocked("k")
    assert not throttle.is_blocked("other")
    throttle.reset("k")
    assert not throttle.is_blocked("k")


def test_throttle_forgets_events_outside_the_window():
    throttle = SlidingWindowThrottle(max_events=1, window_seconds=0)
    throttle.record("k")
    assert not throttle.is_blocked("k")


@pytest.mark.parametrize(
    ("jwt_secret", "fernet_key", "message"),
    [
        ("", FERNET_KEY, "JWT_SECRET_KEY"),
        ("short", FERNET_KEY, "JWT_SECRET_KEY"),
        (SECRET, "", "APP_ENCRYPTION_KEY"),
        (SECRET, "not-a-fernet-key", "APP_ENCRYPTION_KEY"),
    ],
)
def test_startup_rejects_missing_or_weak_secrets(jwt_secret, fernet_key, message):
    settings = Settings(
        _env_file=None, jwt_secret_key=jwt_secret, app_encryption_key=fernet_key
    )
    with pytest.raises(ValueError, match=message) as exc:
        settings.validate_security_settings()
    assert jwt_secret not in str(exc.value) or not jwt_secret


def test_startup_accepts_strong_secrets():
    Settings(
        _env_file=None, jwt_secret_key=SECRET, app_encryption_key=FERNET_KEY
    ).validate_security_settings()
