"""
Credential and token security utilities.

- Passwords are hashed with Argon2id only (via passlib). Plaintext passwords
  are never stored, logged, or returned in any response.
- Access tokens are short-lived JWTs. Refresh tokens are random opaque
  strings; only their SHA-256 hash is persisted (see models/user.py), so a
  database read alone never yields a usable session token.
"""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from passlib.context import CryptContext

from app.config import get_settings

settings = get_settings()

# Argon2id only — no legacy scheme, no fallback to a weaker hash.
_pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

# Pre-computed dummy Argon2id hash used to mitigate timing side-channel attacks on login
# when a user does not exist. Uses standard passlib Argon2id parameters (m=65536, t=3, p=4).
DUMMY_PASSWORD_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$s7a2di4FwPj/H2MspVRqjQ$eX30MPTIC0PGk2fGembD/T9bNL80BiTAoEFtTKaW5/k"
)


def hash_password(plain_password: str) -> str:
    return _pwd_context.hash(plain_password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    return _pwd_context.verify(plain_password, password_hash)


def dummy_verify_password(plain_password: str) -> bool:
    """
    Executes password verification against a pre-computed dummy Argon2id hash to consume
    time equivalent to a real password verification. Always returns False.
    """
    return verify_password(plain_password, DUMMY_PASSWORD_HASH)


def create_access_token(
    subject: str,
    role: str,
    extra_claims: dict[str, Any] | None = None,
    session_id: str | None = None,
) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "role": role,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    if session_id:
        payload["sid"] = session_id
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """Raises jwt.PyJWTError on an invalid/expired/tampered token."""
    return jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])


def generate_refresh_token() -> tuple[str, str, datetime]:
    """Returns (raw_token_for_client, sha256_hash_to_store, expires_at)."""
    raw = secrets.token_urlsafe(64)
    token_hash = hash_token(raw)
    expires_at = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    return raw, token_hash, expires_at


def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def hash_identifier(value: str) -> str:
    """Used for email/url/content hashes stored for lookups — never store the raw value where a hash will do."""
    return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()


def hash_ip(ip_address: str | None) -> str | None:
    if not ip_address:
        return None
    return hashlib.sha256(ip_address.encode("utf-8")).hexdigest()
