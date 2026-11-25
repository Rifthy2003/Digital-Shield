"""
Provider-independent token encryption abstraction (Phase 18 — Task 18.2).

Uses Fernet / MultiFernet authenticated encryption (AES-128-CBC + HMAC-SHA256)
for MVP, behind a `TokenCipher` interface designed so a future KMS-backed
envelope-encryption implementation (AWS KMS, GCP Cloud KMS, HashiCorp Vault)
can replace `MultiFernetTokenCipher` without changing OAuth business logic.

Security guarantees:
- Keys are loaded from external configuration (`TOKEN_ENCRYPTION_KEY`), never
  hardcoded or stored in PostgreSQL.
- MultiFernet supports zero-downtime key rotation: the first comma-separated
  key is the primary encryption key; older keys remain valid for decryption
  and `rotate()` re-encrypts ciphertext under the primary key.
- Plaintext tokens, raw key material, and raw ciphertext are never included in
  logs or exception messages.
"""
from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from collections.abc import Sequence

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from app.config import get_settings


class TokenCryptoError(Exception):
    """Base exception for token encryption/decryption errors."""


class TokenEncryptionConfigError(TokenCryptoError, ValueError):
    """Raised when token encryption key configuration is missing or invalid."""


class TokenDecryptionError(TokenCryptoError, ValueError):
    """Raised when encrypted token payload cannot be authenticated or decrypted."""


class TokenCipher(ABC):
    """
    Provider-independent interface for encrypting and decrypting OAuth tokens at rest.
    Future KMS implementations (e.g., AWS KMS / GCP Cloud KMS envelope encryption)
    should implement this exact interface.
    """

    @property
    @abstractmethod
    def key_id(self) -> str:
        """Non-secret identifier/version of the active primary encryption key."""

    @abstractmethod
    def encrypt(self, plaintext: str) -> str:
        """Encrypt a non-empty plaintext token and return an authenticated ciphertext string."""

    @abstractmethod
    def decrypt(self, ciphertext: str) -> str:
        """Decrypt and authenticate a ciphertext string, returning the plaintext token."""

    @abstractmethod
    def rotate(self, ciphertext: str) -> str:
        """Re-encrypt an existing ciphertext under the current primary key."""


def parse_fernet_keys(raw_keys: str | Sequence[str] | None) -> list[str]:
    """
    Parse and validate one or more urlsafe base64-encoded 32-byte Fernet keys.
    Accepts a comma-separated string or a sequence of key strings.
    Raises `TokenEncryptionConfigError` without leaking key material if missing or invalid.
    """
    if raw_keys is None:
        raise TokenEncryptionConfigError(
            "TOKEN_ENCRYPTION_KEY is not configured."
        )

    if isinstance(raw_keys, str):
        candidates = [part.strip() for part in raw_keys.split(",") if part.strip()]
    else:
        candidates = [str(part).strip() for part in raw_keys if str(part).strip()]

    if not candidates:
        raise TokenEncryptionConfigError(
            "TOKEN_ENCRYPTION_KEY cannot be empty or whitespace-only."
        )

    for key in candidates:
        try:
            Fernet(key.encode("utf-8"))
        except Exception as exc:
            raise TokenEncryptionConfigError(
                "Invalid TOKEN_ENCRYPTION_KEY format; expected urlsafe base64-encoded 32-byte Fernet key(s)."
            ) from exc

    return candidates


def _derive_key_fingerprint(key: str) -> str:
    """Derive a short, non-reversible fingerprint to identify the active primary key."""
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    return f"fernet:{digest}"


class MultiFernetTokenCipher(TokenCipher):
    """
    Fernet / MultiFernet implementation of `TokenCipher`.

    The first key in `keys` is the active primary key used for all `encrypt()` and
    `rotate()` operations. Any subsequent keys are retained for decrypting tokens
    encrypted prior to key rotation.
    """

    def __init__(self, keys: str | Sequence[str]) -> None:
        validated = parse_fernet_keys(keys)
        self._key_count = len(validated)
        self._key_id = _derive_key_fingerprint(validated[0])
        self._fernets = [Fernet(k.encode("utf-8")) for k in validated]
        self._primary = self._fernets[0]
        self._multi = MultiFernet(self._fernets)

    def __repr__(self) -> str:
        return f"MultiFernetTokenCipher(key_id={self._key_id!r}, key_count={self._key_count})"

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def key_count(self) -> int:
        return self._key_count

    def encrypt(self, plaintext: str) -> str:
        if not isinstance(plaintext, str) or not plaintext:
            raise ValueError("Plaintext token must be a non-empty string.")
        try:
            return self._multi.encrypt(plaintext.encode("utf-8")).decode("utf-8")
        except Exception as exc:
            raise TokenCryptoError("Failed to encrypt token.") from exc

    def decrypt(self, ciphertext: str) -> str:
        if not isinstance(ciphertext, str) or not ciphertext.strip():
            raise TokenDecryptionError("Encrypted token payload is empty or invalid.")
        try:
            return self._multi.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
        except (InvalidToken, ValueError, TypeError) as exc:
            raise TokenDecryptionError(
                "Failed to decrypt token: invalid or tampered ciphertext."
            ) from exc

    def rotate(self, ciphertext: str) -> str:
        if not isinstance(ciphertext, str) or not ciphertext.strip():
            raise TokenDecryptionError("Encrypted token payload is empty or invalid.")
        try:
            return self._multi.rotate(ciphertext.encode("utf-8")).decode("utf-8")
        except (InvalidToken, ValueError, TypeError) as exc:
            raise TokenDecryptionError(
                "Failed to rotate token: invalid or tampered ciphertext."
            ) from exc

    def is_encrypted_with_primary(self, ciphertext: str) -> bool:
        """Return True if `ciphertext` decrypts directly under the current primary key."""
        if not isinstance(ciphertext, str) or not ciphertext.strip():
            return False
        try:
            self._primary.decrypt(ciphertext.encode("utf-8"))
            return True
        except Exception:
            return False


def get_token_cipher() -> TokenCipher:
    """
    Construct the active `TokenCipher` from application settings.
    Raises `TokenEncryptionConfigError` if `TOKEN_ENCRYPTION_KEY` is missing or invalid.
    """
    settings = get_settings()
    return MultiFernetTokenCipher(settings.TOKEN_ENCRYPTION_KEY)
