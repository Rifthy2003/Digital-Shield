"""
Security & Token Lifecycle Integration Tests for Phase 18 — Task 18.7.

Covers:
1. Access token expiration tracking and refresh token rotation (when Google issues a new refresh token).
2. Invalid/revoked refresh token (`invalid_grant`) handling with secret redaction.
3. End-to-end MultiFernet key rotation compatibility on persisted OAuthToken records.
4. POST /google/callback rate limiting (10/minute -> HTTP 429).
5. Disconnected account cannot be queried or disconnected again (404 + OAuthToken removed).
6. Authorization-code / state replay rejected after failed provider exchange.
"""
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from app.api.routes.oauth import get_google_oauth_service
from app.config import Settings
from app.core.crypto import MultiFernetTokenCipher
from app.main import app
from app.models.oauth import ConnectedAccount, OAuthToken
from app.services.oauth_google import (
    GOOGLE_JWKS_URL,
    GOOGLE_REVOKE_URL,
    GOOGLE_TOKEN_URL,
    GoogleOAuthService,
    GoogleTokenRefreshError,
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
        GOOGLE_CLIENT_ID="test-client-id",
        GOOGLE_CLIENT_SECRET="test-client-secret",
        GOOGLE_REDIRECT_URI="http://localhost:5174/oauth/google/callback",
        TOKEN_ENCRYPTION_KEY=enc_key,
        _env_file=None,
    )


def _sign_id_token(private_key, kid: str, *, sub: str, email: str, nonce: str) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "iss": "https://accounts.google.com",
            "aud": "test-client-id",
            "sub": sub,
            "email": email,
            "email_verified": True,
            "name": "Lifecycle User",
            "nonce": nonce,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=10)).timestamp()),
        },
        private_key,
        algorithm="RS256",
        headers={"kid": kid},
    )


@pytest.mark.asyncio
async def test_token_lifecycle_refresh_rotation_invalid_grant_and_key_rotation(client, auth_headers, db_session):
    old_key = Fernet.generate_key().decode()
    new_key = Fernet.generate_key().decode()
    old_cipher = MultiFernetTokenCipher(old_key)
    priv_key, jwk_dict = _gen_rsa_jwk("kid-1")

    state_box = {"nonce": "", "mode": "link"}

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == GOOGLE_TOKEN_URL:
            if state_box["mode"] == "link":
                return httpx.Response(
                    200,
                    json={
                        "access_token": "ya29.initial-access",
                        "refresh_token": "1//initial-refresh",
                        "id_token": _sign_id_token(
                            priv_key,
                            "kid-1",
                            sub="sub-lifecycle",
                            email="life@gmail.com",
                            nonce=state_box["nonce"],
                        ),
                        "expires_in": 3600,
                    },
                )
            if state_box["mode"] == "refresh_rotate":
                return httpx.Response(
                    200,
                    json={
                        "access_token": "ya29.refreshed-access",
                        "refresh_token": "1//rotated-refresh",
                        "expires_in": 7200,
                    },
                )
            return httpx.Response(400, json={"error": "invalid_grant"})
        if str(request.url) == GOOGLE_JWKS_URL:
            return httpx.Response(200, json={"keys": [jwk_dict]})
        if str(request.url) == GOOGLE_REVOKE_URL:
            return httpx.Response(200)
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    old_svc = GoogleOAuthService(
        settings=_make_settings(old_key),
        cipher=old_cipher,
        http_client_factory=lambda: httpx.AsyncClient(transport=transport, timeout=5.0),
    )
    app.dependency_overrides[get_google_oauth_service] = lambda: old_svc

    try:
        # 1. Link account under old_key
        auth_res = client.post("/api/v1/oauth/google/authorize", headers=auth_headers).json()
        qs = parse_qs(urlparse(auth_res["authorization_url"]).query)
        state_box["nonce"] = qs["nonce"][0]

        cb = client.post(
            "/api/v1/oauth/google/callback",
            json={"code": "auth-code-life", "state": qs["state"][0]},
            headers=auth_headers,
        )
        assert cb.status_code == 200
        account_id = cb.json()["id"]

        stored_tok = db_session.query(OAuthToken).filter(OAuthToken.connected_account_id == account_id).first()
        assert stored_tok is not None
        assert stored_tok.expires_at is not None
        assert stored_tok.encryption_key_id == old_cipher.key_id

        # 2. Rotate encryption key to `new_key,old_key` and refresh Google access token
        rotated_cipher = MultiFernetTokenCipher(f"{new_key},{old_key}")
        rotated_svc = GoogleOAuthService(
            settings=_make_settings(f"{new_key},{old_key}"),
            cipher=rotated_cipher,
            http_client_factory=lambda: httpx.AsyncClient(transport=transport, timeout=5.0),
        )
        state_box["mode"] = "refresh_rotate"
        refreshed = await rotated_svc.refresh_access_token(stored_tok.refresh_token_encrypted)

        assert refreshed.encryption_key_id == rotated_cipher.key_id
        assert rotated_cipher.decrypt(refreshed.access_token_encrypted) == "ya29.refreshed-access"
        assert rotated_cipher.decrypt(refreshed.refresh_token_encrypted) == "1//rotated-refresh"

        # 3. Invalid/revoked refresh token fails safely without leaking secret
        state_box["mode"] = "invalid_grant"
        with pytest.raises(GoogleTokenRefreshError) as exc_info:
            await rotated_svc.refresh_access_token(refreshed.refresh_token_encrypted)
        assert "1//rotated-refresh" not in str(exc_info.value)

        # 4. Disconnect account and verify it cannot be used for further API operations
        disc = client.delete(f"/api/v1/oauth/accounts/{account_id}", headers=auth_headers)
        assert disc.status_code == 200
        assert client.get("/api/v1/oauth/accounts", headers=auth_headers).json() == []
        assert client.delete(f"/api/v1/oauth/accounts/{account_id}", headers=auth_headers).status_code == 404
        assert db_session.get(ConnectedAccount, account_id) is None
        assert db_session.query(OAuthToken).filter(OAuthToken.connected_account_id == account_id).first() is None
    finally:
        app.dependency_overrides.pop(get_google_oauth_service, None)


def test_callback_rate_limit_and_no_reuse_after_provider_failure(client, auth_headers):
    enc_key = Fernet.generate_key().decode()
    cipher = MultiFernetTokenCipher(enc_key)

    def fail_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "invalid_grant"})

    svc = GoogleOAuthService(
        settings=_make_settings(enc_key),
        cipher=cipher,
        http_client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(fail_handler), timeout=5.0),
    )
    app.dependency_overrides[get_google_oauth_service] = lambda: svc

    try:
        auth_res = client.post("/api/v1/oauth/google/authorize", headers=auth_headers).json()
        state = parse_qs(urlparse(auth_res["authorization_url"]).query)["state"][0]

        # First callback consumes state and fails at Google
        r1 = client.post(
            "/api/v1/oauth/google/callback",
            json={"code": "bad-code", "state": state},
            headers=auth_headers,
        )
        assert r1.status_code == 400

        # Replay of the consumed state also fails (never reusable)
        r2 = client.post(
            "/api/v1/oauth/google/callback",
            json={"code": "bad-code", "state": state},
            headers=auth_headers,
        )
        assert r2.status_code == 400

        # Exhaust 10/minute rate limit on /google/callback -> 11th returns 429
        for _ in range(8):
            r = client.post(
                "/api/v1/oauth/google/callback",
                json={"code": "bad-code", "state": "s" * 24},
                headers=auth_headers,
            )
            assert r.status_code == 400

        r_limited = client.post(
            "/api/v1/oauth/google/callback",
            json={"code": "bad-code", "state": "s" * 24},
            headers=auth_headers,
        )
        assert r_limited.status_code == 429
    finally:
        app.dependency_overrides.pop(get_google_oauth_service, None)
