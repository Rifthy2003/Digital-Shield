"""
Unit tests for Phase 18 — Task 18.4: Google OIDC Provider Service.

Uses ephemeral RSA keys and `httpx.MockTransport` — never real Google credentials,
and never weakens RS256 signature / claims verification.
"""
import json
import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from app.config import Settings
from app.core.crypto import MultiFernetTokenCipher
from app.services.oauth_google import (
    GOOGLE_AUTH_URL,
    GOOGLE_JWKS_URL,
    GOOGLE_REVOKE_URL,
    GOOGLE_TOKEN_URL,
    GoogleIdTokenValidationError,
    GoogleOAuthNotConfiguredError,
    GoogleOAuthProviderError,
    GoogleOAuthService,
    GoogleTokenRefreshError,
    GoogleTokenRevocationError,
    generate_pkce_pair,
    hash_oauth_value,
    verify_pkce_challenge,
)


def _gen_rsa_jwk(kid: str):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk_dict = RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    jwk_dict["kid"] = kid
    jwk_dict["use"] = "sig"
    jwk_dict["alg"] = "RS256"
    return private_key, jwk_dict


def _make_settings(enc_key: str) -> Settings:
    return Settings(
        ENVIRONMENT="development",
        GOOGLE_CLIENT_ID="test-google-client-id",
        GOOGLE_CLIENT_SECRET="test-google-client-secret",
        GOOGLE_REDIRECT_URI="http://localhost:5174/oauth/google/callback",
        TOKEN_ENCRYPTION_KEY=enc_key,
        _env_file=None,
    )


def _sign_id_token(
    private_key,
    kid: str,
    *,
    sub: str = "google-sub-12345",
    email: str = "citizen@gmail.com",
    email_verified: bool = True,
    name: str = "Test Citizen",
    picture: str = "https://lh3.googleusercontent.com/a/avatar",
    iss: str = "https://accounts.google.com",
    aud: str = "test-google-client-id",
    nonce: str = "raw-nonce-abc",
    exp_delta: timedelta = timedelta(minutes=10),
) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "iss": iss,
        "aud": aud,
        "sub": sub,
        "email": email,
        "email_verified": email_verified,
        "name": name,
        "picture": picture,
        "nonce": nonce,
        "iat": int(now.timestamp()),
        "exp": int((now + exp_delta).timestamp()),
    }
    return jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})


def _make_service(handler, settings: Settings, cipher: MultiFernetTokenCipher) -> GoogleOAuthService:
    transport = httpx.MockTransport(handler)
    return GoogleOAuthService(
        settings=settings,
        cipher=cipher,
        http_client_factory=lambda: httpx.AsyncClient(transport=transport, timeout=5.0),
    )


def test_authorization_url_scopes_pkce_state_and_nonce():
    enc_key = Fernet.generate_key().decode()
    settings = _make_settings(enc_key)
    cipher = MultiFernetTokenCipher(enc_key)
    svc = GoogleOAuthService(settings=settings, cipher=cipher)

    a1 = svc.build_authorization_request()
    a2 = svc.build_authorization_request()

    parsed = urlparse(a1.authorization_url)
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == GOOGLE_AUTH_URL
    qs = parse_qs(parsed.query)

    assert qs["client_id"] == ["test-google-client-id"]
    assert qs["redirect_uri"] == ["http://localhost:5174/oauth/google/callback"]
    assert qs["response_type"] == ["code"]
    assert qs["scope"] == ["openid email profile"]
    assert "gmail" not in a1.authorization_url.lower()
    assert qs["code_challenge_method"] == ["S256"]
    assert qs["access_type"] == ["offline"]

    # State & nonce stored only as SHA-256 hashes; PKCE verifier encrypted
    raw_state = qs["state"][0]
    raw_nonce = qs["nonce"][0]
    assert a1.state_hash == hash_oauth_value(raw_state)
    assert a1.nonce_hash == hash_oauth_value(raw_nonce)
    assert raw_state != a1.state_hash
    assert raw_nonce != a1.nonce_hash

    decrypted_verifier = cipher.decrypt(a1.code_verifier_encrypted)
    assert verify_pkce_challenge(decrypted_verifier, qs["code_challenge"][0])
    assert not verify_pkce_challenge("wrong-verifier", qs["code_challenge"][0])

    # Unpredictable across calls
    assert a1.state_hash != a2.state_hash
    assert a1.nonce_hash != a2.nonce_hash


def test_pkce_s256_generation_and_validation():
    verifier, challenge = generate_pkce_pair()
    assert verifier != challenge
    assert verify_pkce_challenge(verifier, challenge)
    assert not verify_pkce_challenge(verifier + "x", challenge)


def test_unconfigured_google_oauth_raises():
    s = Settings(ENVIRONMENT="development", _env_file=None)
    svc = GoogleOAuthService(settings=s)
    with pytest.raises(GoogleOAuthNotConfiguredError):
        svc.build_authorization_request()


@pytest.mark.asyncio
async def test_successful_code_exchange_and_token_encryption():
    enc_key = Fernet.generate_key().decode()
    settings = _make_settings(enc_key)
    cipher = MultiFernetTokenCipher(enc_key)
    priv_key, jwk_dict = _gen_rsa_jwk("kid-1")

    raw_nonce = "nonce-value-1"
    id_token = _sign_id_token(priv_key, "kid-1", nonce=raw_nonce)

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == GOOGLE_TOKEN_URL:
            form = parse_qs(request.content.decode())
            assert form["redirect_uri"] == ["http://localhost:5174/oauth/google/callback"]
            assert form["grant_type"] == ["authorization_code"]
            return httpx.Response(
                200,
                json={
                    "access_token": "ya29.real-access",
                    "refresh_token": "1//real-refresh",
                    "id_token": id_token,
                    "expires_in": 3600,
                    "token_type": "Bearer",
                    "scope": "openid email profile",
                },
            )
        if str(request.url) == GOOGLE_JWKS_URL:
            return httpx.Response(200, json={"keys": [jwk_dict]})
        return httpx.Response(404)

    svc = _make_service(handler, settings, cipher)
    encrypted_verifier = cipher.encrypt("pkce-verifier-1")
    result = await svc.exchange_code_for_tokens(
        code="auth-code-123",
        code_verifier_encrypted=encrypted_verifier,
        expected_nonce_hash=hash_oauth_value(raw_nonce),
    )

    assert result.identity.provider_user_id == "google-sub-12345"
    assert result.identity.email == "citizen@gmail.com"
    assert result.identity.email_verified is True
    assert result.identity.display_name == "Test Citizen"
    assert result.tokens.encryption_key_id == cipher.key_id
    assert cipher.decrypt(result.tokens.access_token_encrypted) == "ya29.real-access"
    assert cipher.decrypt(result.tokens.refresh_token_encrypted) == "1//real-refresh"


@pytest.mark.asyncio
async def test_refresh_token_preserved_when_google_omits_it():
    enc_key = Fernet.generate_key().decode()
    settings = _make_settings(enc_key)
    cipher = MultiFernetTokenCipher(enc_key)
    priv_key, jwk_dict = _gen_rsa_jwk("kid-1")
    raw_nonce = "nonce-preserve"
    id_token = _sign_id_token(priv_key, "kid-1", nonce=raw_nonce)

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == GOOGLE_TOKEN_URL:
            return httpx.Response(
                200,
                json={
                    "access_token": "ya29.new-access",
                    # refresh_token intentionally omitted by Google
                    "id_token": id_token,
                    "expires_in": 3600,
                },
            )
        if str(request.url) == GOOGLE_JWKS_URL:
            return httpx.Response(200, json={"keys": [jwk_dict]})
        return httpx.Response(404)

    svc = _make_service(handler, settings, cipher)
    existing_rt_enc = cipher.encrypt("1//existing-refresh-token")

    res = await svc.exchange_code_for_tokens(
        code="code-456",
        code_verifier_encrypted=cipher.encrypt("verifier"),
        expected_nonce_hash=hash_oauth_value(raw_nonce),
        existing_refresh_token_encrypted=existing_rt_enc,
    )
    assert res.tokens.refresh_token_encrypted == existing_rt_enc
    assert cipher.decrypt(res.tokens.refresh_token_encrypted) == "1//existing-refresh-token"

    # Also verify refresh_access_token preserves existing refresh token when omitted
    refreshed = await svc.refresh_access_token(existing_rt_enc)
    assert cipher.decrypt(refreshed.access_token_encrypted) == "ya29.new-access"
    assert cipher.decrypt(refreshed.refresh_token_encrypted) == "1//existing-refresh-token"


@pytest.mark.asyncio
async def test_id_token_validation_failures():
    enc_key = Fernet.generate_key().decode()
    settings = _make_settings(enc_key)
    cipher = MultiFernetTokenCipher(enc_key)
    priv_key, jwk_dict = _gen_rsa_jwk("kid-1")
    other_priv_key, _ = _gen_rsa_jwk("kid-1")

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == GOOGLE_JWKS_URL:
            return httpx.Response(200, json={"keys": [jwk_dict]})
        return httpx.Response(404)

    svc = _make_service(handler, settings, cipher)
    nonce_hash = hash_oauth_value("expected-nonce")

    # Wrong signature
    bad_sig = _sign_id_token(other_priv_key, "kid-1", nonce="expected-nonce")
    with pytest.raises(GoogleIdTokenValidationError):
        await svc.verify_id_token(bad_sig, expected_nonce_hash=nonce_hash)

    # Wrong issuer
    bad_iss = _sign_id_token(priv_key, "kid-1", iss="https://evil.example.com", nonce="expected-nonce")
    with pytest.raises(GoogleIdTokenValidationError, match="issuer"):
        await svc.verify_id_token(bad_iss, expected_nonce_hash=nonce_hash)

    # Wrong audience
    bad_aud = _sign_id_token(priv_key, "kid-1", aud="other-client-id", nonce="expected-nonce")
    with pytest.raises(GoogleIdTokenValidationError, match="audience"):
        await svc.verify_id_token(bad_aud, expected_nonce_hash=nonce_hash)

    # Expired token
    expired = _sign_id_token(priv_key, "kid-1", exp_delta=timedelta(minutes=-5), nonce="expected-nonce")
    with pytest.raises(GoogleIdTokenValidationError, match="expired"):
        await svc.verify_id_token(expired, expected_nonce_hash=nonce_hash)

    # Invalid nonce
    bad_nonce = _sign_id_token(priv_key, "kid-1", nonce="wrong-nonce")
    with pytest.raises(GoogleIdTokenValidationError, match="nonce"):
        await svc.verify_id_token(bad_nonce, expected_nonce_hash=nonce_hash)

    # Missing expected nonce hash
    valid_tok = _sign_id_token(priv_key, "kid-1", nonce="expected-nonce")
    with pytest.raises(GoogleIdTokenValidationError):
        await svc.verify_id_token(valid_tok, expected_nonce_hash="")


@pytest.mark.asyncio
async def test_jwks_key_rotation_handling():
    enc_key = Fernet.generate_key().decode()
    settings = _make_settings(enc_key)
    cipher = MultiFernetTokenCipher(enc_key)
    priv_1, jwk_1 = _gen_rsa_jwk("kid-1")
    priv_2, jwk_2 = _gen_rsa_jwk("kid-2")

    jwks_calls = 0
    current_keys = [jwk_1]

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal jwks_calls
        if str(request.url) == GOOGLE_JWKS_URL:
            jwks_calls += 1
            return httpx.Response(200, json={"keys": current_keys})
        return httpx.Response(404)

    svc = _make_service(handler, settings, cipher)

    # First token uses kid-1 (populates cache)
    tok1 = _sign_id_token(priv_1, "kid-1", nonce="n1")
    id1 = await svc.verify_id_token(tok1, expected_nonce_hash=hash_oauth_value("n1"))
    assert id1.provider_user_id == "google-sub-12345"
    assert jwks_calls == 1

    # Rotate keys upstream to kid-2; cache miss on kid-2 must automatically refresh JWKS
    current_keys = [jwk_2]
    tok2 = _sign_id_token(priv_2, "kid-2", nonce="n2")
    id2 = await svc.verify_id_token(tok2, expected_nonce_hash=hash_oauth_value("n2"))
    assert id2.provider_user_id == "google-sub-12345"
    assert jwks_calls == 2


@pytest.mark.asyncio
async def test_revocation_success_and_failure():
    enc_key = Fernet.generate_key().decode()
    settings = _make_settings(enc_key)
    cipher = MultiFernetTokenCipher(enc_key)
    rt_enc = cipher.encrypt("1//secret-refresh-token")

    status_to_return = 200

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == GOOGLE_REVOKE_URL:
            if status_to_return == 200:
                return httpx.Response(200)
            return httpx.Response(400, json={"error": "invalid_token"})
        return httpx.Response(404)

    svc = _make_service(handler, settings, cipher)
    await svc.revoke_token(rt_enc)

    status_to_return = 400
    with pytest.raises(GoogleTokenRevocationError):
        await svc.revoke_token(rt_enc)


@pytest.mark.asyncio
async def test_timeout_invalid_provider_response_and_log_redaction(caplog):
    enc_key = Fernet.generate_key().decode()
    settings = _make_settings(enc_key)
    cipher = MultiFernetTokenCipher(enc_key)

    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    svc_timeout = _make_service(timeout_handler, settings, cipher)
    secret_code = "4/secret-auth-code-999"
    with caplog.at_level(logging.WARNING):
        with pytest.raises(GoogleOAuthProviderError, match="timed out"):
            await svc_timeout.exchange_code_for_tokens(
                code=secret_code,
                code_verifier_encrypted=cipher.encrypt("secret-verifier-999"),
                expected_nonce_hash=hash_oauth_value("n"),
            )

    # Refresh failure & invalid provider JSON
    def invalid_json_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not-json")

    svc_bad_json = _make_service(invalid_json_handler, settings, cipher)
    secret_rt = "1//very-secret-refresh-token"
    with caplog.at_level(logging.WARNING):
        with pytest.raises(GoogleTokenRefreshError):
            await svc_bad_json.refresh_access_token(cipher.encrypt(secret_rt))

    # Ensure no secrets or tokens appear in any log records
    assert secret_code not in caplog.text
    assert secret_rt not in caplog.text
    assert "secret-verifier-999" not in caplog.text
    assert "test-google-client-secret" not in caplog.text
