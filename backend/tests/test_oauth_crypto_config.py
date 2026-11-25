"""
Unit tests for Phase 18 — Task 18.2: OAuth Crypto & Configuration Foundation.

Covers:
1. Successful encryption and decryption.
2. Different plaintext values (and repeated encryptions) produce distinct ciphertext.
3. Invalid key rejection.
4. Invalid / tampered / empty ciphertext rejection.
5. Missing key handling.
6. MultiFernet decryption using an old key.
7. Encryption using the current primary key.
8. Key rotation behavior (`rotate()`).
9. Secret redaction and safe error handling (no plaintext, key, or secret in errors/repr).
10. Existing application startup and health check when OAuth is disabled.
"""
import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError

from app.config import Settings, get_settings
from app.core.crypto import (
    MultiFernetTokenCipher,
    TokenCipher,
    TokenDecryptionError,
    TokenEncryptionConfigError,
    get_token_cipher,
)


def _gen_key() -> str:
    return Fernet.generate_key().decode("utf-8")


def test_encrypt_and_decrypt_roundtrip():
    key = _gen_key()
    cipher: TokenCipher = MultiFernetTokenCipher(key)
    plaintext = "ya29.test-access-token-value-12345"

    ciphertext = cipher.encrypt(plaintext)
    assert isinstance(ciphertext, str)
    assert ciphertext != plaintext
    assert plaintext not in ciphertext
    assert cipher.decrypt(ciphertext) == plaintext
    assert cipher.key_id.startswith("fernet:")


def test_different_plaintexts_and_non_deterministic_ciphertext():
    cipher = MultiFernetTokenCipher(_gen_key())
    ct_a = cipher.encrypt("token-alpha")
    ct_b = cipher.encrypt("token-beta")
    ct_a2 = cipher.encrypt("token-alpha")

    assert ct_a != ct_b
    assert ct_a != ct_a2
    assert cipher.decrypt(ct_a) == "token-alpha"
    assert cipher.decrypt(ct_b) == "token-beta"
    assert cipher.decrypt(ct_a2) == "token-alpha"


@pytest.mark.parametrize("bad_key", [
    "not-a-valid-fernet-key",
    "short-key",
    "a" * 32,  # not base64-encoded 32 bytes
    f"{_gen_key()},invalid-second-key",
])
def test_invalid_key_rejected(bad_key):
    with pytest.raises(TokenEncryptionConfigError) as exc_info:
        MultiFernetTokenCipher(bad_key)
    assert bad_key not in str(exc_info.value)

    with pytest.raises(ValidationError) as cfg_exc:
        Settings(ENVIRONMENT="development", TOKEN_ENCRYPTION_KEY=bad_key, _env_file=None)
    assert all(bad_key not in err["msg"] for err in cfg_exc.value.errors())


def test_invalid_and_tampered_ciphertext_rejected():
    cipher = MultiFernetTokenCipher(_gen_key())
    valid_ct = cipher.encrypt("sensitive-refresh-token")
    tampered_ct = valid_ct[:-4] + ("AAAA" if not valid_ct.endswith("AAAA") else "BBBB")

    for bad_ct in ("", "   ", "not-fernet-ciphertext", tampered_ct):
        with pytest.raises(TokenDecryptionError):
            cipher.decrypt(bad_ct)
        with pytest.raises(TokenDecryptionError):
            cipher.rotate(bad_ct)


def test_missing_key_handling(monkeypatch):
    for missing in (None, "", "   "):
        with pytest.raises(TokenEncryptionConfigError):
            MultiFernetTokenCipher(missing)  # type: ignore[arg-type]

    monkeypatch.delenv("TOKEN_ENCRYPTION_KEY", raising=False)
    get_settings.cache_clear()
    try:
        with pytest.raises(TokenEncryptionConfigError):
            get_token_cipher()
    finally:
        get_settings.cache_clear()


def test_multifernet_decrypts_with_old_key_and_encrypts_with_primary():
    old_key = _gen_key()
    new_key = _gen_key()

    old_cipher = MultiFernetTokenCipher(old_key)
    legacy_ciphertext = old_cipher.encrypt("legacy-provider-token")

    # New primary key first, old key second
    rotated_cipher = MultiFernetTokenCipher(f"{new_key},{old_key}")

    # Can decrypt legacy ciphertext encrypted with old_key
    assert rotated_cipher.decrypt(legacy_ciphertext) == "legacy-provider-token"
    assert not rotated_cipher.is_encrypted_with_primary(legacy_ciphertext)

    # New encryptions use the current primary key (old_cipher alone cannot decrypt)
    fresh_ciphertext = rotated_cipher.encrypt("fresh-provider-token")
    assert rotated_cipher.is_encrypted_with_primary(fresh_ciphertext)
    with pytest.raises(TokenDecryptionError):
        old_cipher.decrypt(fresh_ciphertext)


def test_key_rotation_reencrypts_under_primary_key():
    old_key = _gen_key()
    new_key = _gen_key()

    old_cipher = MultiFernetTokenCipher(old_key)
    legacy_ct = old_cipher.encrypt("token-to-rotate")

    keyring_cipher = MultiFernetTokenCipher(f"{new_key},{old_key}")
    rotated_ct = keyring_cipher.rotate(legacy_ct)

    assert rotated_ct != legacy_ct
    assert keyring_cipher.is_encrypted_with_primary(rotated_ct)

    # After retiring old_key, only new_key can decrypt the rotated ciphertext
    new_only_cipher = MultiFernetTokenCipher(new_key)
    assert new_only_cipher.decrypt(rotated_ct) == "token-to-rotate"
    with pytest.raises(TokenDecryptionError):
        old_cipher.decrypt(rotated_ct)


def test_secret_redaction_and_safe_error_handling():
    key = _gen_key()
    cipher = MultiFernetTokenCipher(key)
    secret_token = "super-secret-oauth-token-xyz"
    ct = cipher.encrypt(secret_token)

    # __repr__ must not leak key material
    assert key not in repr(cipher)
    assert cipher.key_id in repr(cipher)

    # Decryption failure with wrong key must not leak plaintext or keys
    wrong_cipher = MultiFernetTokenCipher(_gen_key())
    with pytest.raises(TokenDecryptionError) as exc_info:
        wrong_cipher.decrypt(ct)
    err_msg = str(exc_info.value)
    assert secret_token not in err_msg
    assert key not in err_msg
    assert ct not in err_msg


def test_app_startup_and_settings_succeed_when_oauth_disabled(client, monkeypatch):
    monkeypatch.delenv("TOKEN_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_CLIENT_ID", raising=False)
    monkeypatch.delenv("GOOGLE_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("GOOGLE_REDIRECT_URI", raising=False)

    dev_settings = Settings(ENVIRONMENT="development", _env_file=None)
    assert not dev_settings.google_oauth_enabled

    prod_settings = Settings(
        ENVIRONMENT="production",
        JWT_SECRET_KEY="p" * 40,
        _env_file=None,
    )
    assert not prod_settings.google_oauth_enabled

    health_resp = client.get("/api/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["status"] == "ok"


def test_google_oauth_settings_validation():
    valid_key = _gen_key()

    # Partial config fails
    with pytest.raises(ValidationError):
        Settings(
            ENVIRONMENT="development",
            GOOGLE_CLIENT_ID="dummy-client-id",
            TOKEN_ENCRYPTION_KEY=valid_key,
            _env_file=None,
        )

    # OAuth enabled without TOKEN_ENCRYPTION_KEY fails
    with pytest.raises(ValidationError):
        Settings(
            ENVIRONMENT="development",
            GOOGLE_CLIENT_ID="dummy-client-id",
            GOOGLE_CLIENT_SECRET="dummy-client-secret",
            GOOGLE_REDIRECT_URI="http://localhost:5174/oauth/google/callback",
            TOKEN_ENCRYPTION_KEY="",
            _env_file=None,
        )

    # Production requires HTTPS redirect URI
    with pytest.raises(ValidationError):
        Settings(
            ENVIRONMENT="production",
            JWT_SECRET_KEY="p" * 40,
            GOOGLE_CLIENT_ID="dummy-client-id",
            GOOGLE_CLIENT_SECRET="dummy-client-secret",
            GOOGLE_REDIRECT_URI="http://localhost:5174/oauth/google/callback",
            TOKEN_ENCRYPTION_KEY=valid_key,
            _env_file=None,
        )

    # Full valid production OAuth config succeeds
    prod_oauth = Settings(
        ENVIRONMENT="production",
        JWT_SECRET_KEY="p" * 40,
        GOOGLE_CLIENT_ID="dummy-client-id",
        GOOGLE_CLIENT_SECRET="dummy-client-secret",
        GOOGLE_REDIRECT_URI="https://app.infora.example/oauth/google/callback",
        TOKEN_ENCRYPTION_KEY=valid_key,
        _env_file=None,
    )
    assert prod_oauth.google_oauth_enabled
