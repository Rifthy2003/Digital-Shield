"""
Time-Based One-Time Password (TOTP) and Recovery Code service for Infora accounts.

Security properties:
- TOTP secrets are generated with 160 bits of entropy (32-char Base32).
- Secrets are encrypted at rest using TokenCipher (Fernet/MultiFernet) and
  never stored or logged in plaintext.
- TOTP verification enforces a configurable clock-skew window and prevents
  replay attacks by tracking the last accepted 30-second time step per user.
- Recovery codes use an unambiguous 32-character alphabet (50 bits of entropy),
  are stored strictly as SHA-256 hashes, and are consumed atomically once.
- MFA login challenges are short-lived, single-use, purpose-bound tokens.
"""

import hashlib
import hmac
import re
import secrets
import time
from datetime import datetime, timedelta

import pyotp
from sqlalchemy import delete, update
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.crypto import get_token_cipher
from app.core.security import hash_token
from app.models.mfa import MfaChallenge, MfaRecoveryCode

_RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_TOTP_STEP_SECONDS = 30


def generate_totp_secret() -> str:
    """Generate a 160-bit Base32 TOTP secret."""
    return pyotp.random_base32(length=32)


def build_provisioning_uri(secret: str, email: str) -> str:
    """Build an otpauth:// provisioning URI for authenticator apps."""
    settings = get_settings()
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=settings.MFA_ISSUER_NAME)


def encrypt_totp_secret(secret: str) -> str:
    """Encrypt a plaintext TOTP secret using the configured TokenCipher."""
    return get_token_cipher().encrypt(secret)


def decrypt_totp_secret(encrypted_secret: str) -> str:
    """Decrypt an encrypted TOTP secret using the configured TokenCipher."""
    return get_token_cipher().decrypt(encrypted_secret)


def verify_totp_code(
    secret: str,
    code: str,
    *,
    last_totp_step: int | None = None,
    window: int | None = None,
    now: float | None = None,
) -> int | None:
    """
    Verify a 6-digit TOTP code against `secret` with replay prevention.

    Returns the matched 30-second time step if valid and not replayed, or None.
    """
    cleaned = code.strip()
    if not re.fullmatch(r"\d{6}", cleaned):
        return None

    settings = get_settings()
    valid_window = settings.MFA_TOTP_WINDOW if window is None else max(0, window)
    current_ts = time.time() if now is None else now
    current_step = int(current_ts // _TOTP_STEP_SECONDS)

    totp = pyotp.TOTP(secret)
    offsets = [0]
    for delta in range(1, valid_window + 1):
        offsets.extend([-delta, delta])

    for offset in offsets:
        step = current_step + offset
        if last_totp_step is not None and step <= last_totp_step:
            continue
        expected = totp.at(step * _TOTP_STEP_SECONDS)
        if hmac.compare_digest(cleaned, expected):
            return step

    return None


def generate_recovery_codes(count: int | None = None) -> list[str]:
    """Generate high-entropy one-time recovery codes formatted as XXXXX-XXXXX."""
    settings = get_settings()
    total = settings.MFA_RECOVERY_CODE_COUNT if count is None else count
    codes: list[str] = []
    for _ in range(total):
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def hash_recovery_code(raw_code: str) -> str:
    """Normalize and SHA-256 hash a recovery code for storage/lookup."""
    normalized = re.sub(r"[\s-]+", "", raw_code).upper()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def replace_recovery_codes(db: Session, user_id: str, count: int | None = None) -> list[str]:
    """
    Revoke any existing recovery codes for `user_id` and store a fresh set.

    Returns the plaintext codes once; only SHA-256 hashes are saved in the DB.
    """
    db.execute(delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user_id))
    plaintext_codes = generate_recovery_codes(count=count)
    for code in plaintext_codes:
        db.add(MfaRecoveryCode(user_id=user_id, code_hash=hash_recovery_code(code)))
    return plaintext_codes


def consume_recovery_code(db: Session, user_id: str, raw_code: str) -> bool:
    """
    Atomically verify and consume a one-time recovery code for `user_id`.
    """
    cleaned = re.sub(r"[\s-]+", "", raw_code).upper()
    if len(cleaned) < 8:
        return False
    code_hash = hashlib.sha256(cleaned.encode("utf-8")).hexdigest()
    result = db.execute(
        update(MfaRecoveryCode)
        .where(
            MfaRecoveryCode.user_id == user_id,
            MfaRecoveryCode.code_hash == code_hash,
            MfaRecoveryCode.used_at.is_(None),
        )
        .values(used_at=datetime.utcnow())
    )
    return (result.rowcount or 0) == 1


def count_remaining_recovery_codes(db: Session, user_id: str) -> int:
    """Return the number of unused recovery codes for `user_id`."""
    return (
        db.query(MfaRecoveryCode)
        .filter(MfaRecoveryCode.user_id == user_id, MfaRecoveryCode.used_at.is_(None))
        .count()
    )


def create_mfa_challenge(db: Session, user_id: str) -> str:
    """Create a short-lived, single-use MFA challenge token for login."""
    settings = get_settings()
    raw_token = secrets.token_urlsafe(32)
    challenge = MfaChallenge(
        user_id=user_id,
        challenge_hash=hash_token(raw_token),
        expires_at=datetime.utcnow() + timedelta(minutes=settings.MFA_CHALLENGE_EXPIRE_MINUTES),
        used=False,
    )
    db.add(challenge)
    return raw_token


def consume_mfa_challenge(db: Session, raw_token: str) -> MfaChallenge | None:
    """
    Atomically consume a valid, unexpired, unused MFA challenge token.
    """
    if not raw_token or not raw_token.strip():
        return None
    token_hash = hash_token(raw_token.strip())
    now = datetime.utcnow()
    challenge = db.query(MfaChallenge).filter(MfaChallenge.challenge_hash == token_hash).first()
    if not challenge:
        return None
    result = db.execute(
        update(MfaChallenge)
        .where(
            MfaChallenge.id == challenge.id,
            MfaChallenge.used.is_(False),
            MfaChallenge.expires_at > now,
        )
        .values(used=True)
    )
    if (result.rowcount or 0) != 1:
        return None
    return challenge
