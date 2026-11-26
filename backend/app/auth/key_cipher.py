"""Fernet (AES-128-CBC + HMAC-SHA256) encryption for stored provider keys."""

from cryptography.fernet import Fernet, InvalidToken


class KeyDecryptionError(Exception):
    """Stored ciphertext could not be decrypted (wrong or rotated key)."""


class KeyCipher:
    """Encrypts and decrypts secrets with the app's Fernet key."""

    def __init__(self, fernet_key: str):
        self._fernet = Fernet(fernet_key.encode())

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        try:
            return self._fernet.decrypt(ciphertext.encode()).decode()
        except InvalidToken as exc:
            raise KeyDecryptionError("Stored key could not be decrypted.") from exc
