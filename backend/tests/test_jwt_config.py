import logging
import pytest
from pydantic import ValidationError

from app.config import (
    DISALLOWED_JWT_SECRETS,
    INSECURE_DEV_JWT_SECRET,
    Settings,
)


def test_production_valid_strong_secret_succeeds(monkeypatch):
    # Production with a valid, strong secret (>= 32 chars) must succeed.
    strong_secret = "c" * 32
    monkeypatch.setenv("JWT_SECRET_KEY", strong_secret)
    settings = Settings(ENVIRONMENT="production", JWT_SECRET_KEY=strong_secret, _env_file=None)
    assert settings.ENVIRONMENT == "production"
    assert settings.JWT_SECRET_KEY == strong_secret


def test_production_missing_secret_fails(monkeypatch):
    # When JWT_SECRET_KEY is omitted in production, it falls back to the insecure default, which must be rejected.
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    with pytest.raises(ValidationError) as exc_info:
        Settings(ENVIRONMENT="production", _env_file=None)
    assert "default fallback is not permitted" in str(exc_info.value)


def test_production_empty_secret_fails(monkeypatch):
    # Empty string must be rejected in production.
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    with pytest.raises(ValidationError) as exc_info:
        Settings(ENVIRONMENT="production", JWT_SECRET_KEY="", _env_file=None)
    assert "cannot be empty or whitespace-only" in str(exc_info.value)


def test_production_whitespace_secret_fails(monkeypatch):
    # Whitespace-only string must be rejected in production.
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    with pytest.raises(ValidationError) as exc_info:
        Settings(ENVIRONMENT="production", JWT_SECRET_KEY="    ", _env_file=None)
    assert "cannot be empty or whitespace-only" in str(exc_info.value)


def test_production_insecure_fallback_fails(monkeypatch):
    # Explicitly passing the insecure fallback value in production must be rejected.
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    with pytest.raises(ValidationError) as exc_info:
        Settings(ENVIRONMENT="production", JWT_SECRET_KEY=INSECURE_DEV_JWT_SECRET, _env_file=None)
    assert "default fallback is not permitted" in str(exc_info.value)


@pytest.mark.parametrize("placeholder", [
    "replace_with_a_long_random_value",
    "secret",
    "password",
    "Replace_With_A_Long_Random_Value",
    "PASSWORD",
])
def test_production_known_placeholders_fail(monkeypatch, placeholder):
    # Known placeholder values must be rejected in production.
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    with pytest.raises(ValidationError) as exc_info:
        Settings(ENVIRONMENT="production", JWT_SECRET_KEY=placeholder, _env_file=None)
    assert (
        "known insecure placeholder" in str(exc_info.value)
        or "at least 32 characters long" in str(exc_info.value)
    )


def test_production_short_secret_fails(monkeypatch):
    # Secrets shorter than 32 characters must be rejected in production.
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    short_secret = "a" * 31
    with pytest.raises(ValidationError) as exc_info:
        Settings(ENVIRONMENT="production", JWT_SECRET_KEY=short_secret, _env_file=None)
    assert "at least 32 characters long in production" in str(exc_info.value)


def test_development_valid_secret_succeeds(caplog, monkeypatch):
    # In development, a valid custom secret succeeds without warning.
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    with caplog.at_level(logging.WARNING):
        settings = Settings(ENVIRONMENT="development", JWT_SECRET_KEY="dev-custom-secret-key-1234567890", _env_file=None)
        assert settings.ENVIRONMENT == "development"
    assert "INSECURE CONFIGURATION" not in caplog.text


def test_development_empty_secret_fails(monkeypatch):
    # In development, empty or whitespace-only secrets must also be rejected.
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    with pytest.raises(ValidationError) as exc_info:
        Settings(ENVIRONMENT="development", JWT_SECRET_KEY="", _env_file=None)
    assert "cannot be empty or whitespace-only" in str(exc_info.value)

    with pytest.raises(ValidationError) as exc_info:
        Settings(ENVIRONMENT="development", JWT_SECRET_KEY="   ", _env_file=None)
    assert "cannot be empty or whitespace-only" in str(exc_info.value)


def test_development_fallback_produces_warning(caplog, monkeypatch):
    # In development, using the default fallback secret succeeds but emits a clear security warning.
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    with caplog.at_level(logging.WARNING):
        settings = Settings(ENVIRONMENT="development", JWT_SECRET_KEY=INSECURE_DEV_JWT_SECRET, _env_file=None)
        assert settings.JWT_SECRET_KEY == INSECURE_DEV_JWT_SECRET
    assert "INSECURE CONFIGURATION" in caplog.text
    # Ensure the secret itself is never exposed in the log message
    assert INSECURE_DEV_JWT_SECRET not in caplog.text


def test_jwt_functionality_with_valid_secret():
    # Valid token creation and decoding operates normally with a strong secret.
    strong_secret = "x" * 48
    payload_subject = "usr-test-123"
    payload_role = "citizen"

    # Isolate Settings with the strong secret
    test_settings = Settings(ENVIRONMENT="production", JWT_SECRET_KEY=strong_secret, _env_file=None)

    import jwt
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {"sub": payload_subject, "role": payload_role, "type": "access", "iat": now, "exp": now + timedelta(minutes=15)},
        test_settings.JWT_SECRET_KEY,
        algorithm=test_settings.JWT_ALGORITHM,
    )
    decoded = jwt.decode(token, test_settings.JWT_SECRET_KEY, algorithms=[test_settings.JWT_ALGORITHM])
    assert decoded["sub"] == payload_subject
    assert decoded["role"] == payload_role
    assert decoded["type"] == "access"
