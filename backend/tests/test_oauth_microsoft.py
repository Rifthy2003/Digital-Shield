"""
Tests for Provider Capability Registry & Microsoft Personal Account OAuth (P1-C).
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa

from app.api.routes.oauth import get_microsoft_oauth_service
from app.config import Settings, get_settings
from app.core.crypto import MultiFernetTokenCipher
from app.main import app
from app.models.oauth import ConnectedAccount, OAuthState, OAuthToken
from app.services.oauth_google import hash_oauth_value, verify_pkce_challenge
from app.services.oauth_microsoft import (
    MICROSOFT_CONSUMERS_TENANT_ID,
    MICROSOFT_GRAPH_ME_URL,
    MICROSOFT_JWKS_URL,
    MICROSOFT_PERSONAL_SCOPES,
    MICROSOFT_TOKEN_URL,
    MicrosoftIdTokenValidationError,
    MicrosoftOAuthService,
)
from app.services.oauth_registry import (
    CapabilityStatus,
    get_provider_entry,
    list_connectable_providers,
)


def _generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    public_jwk["kid"] = "ms-test-key-1"
    public_jwk["use"] = "sig"
    public_jwk["alg"] = "RS256"
    return private_key, public_jwk


def _make_ms_settings(fernet_key: str) -> Settings:
    return Settings(
        DATABASE_URL="sqlite:///./_test.db",
        JWT_SECRET_KEY="test-secret-key-not-for-production",
        TOKEN_ENCRYPTION_KEY=fernet_key,
        MICROSOFT_CLIENT_ID="ms-client-id-123",
        MICROSOFT_CLIENT_SECRET="ms-client-secret-xyz",
        MICROSOFT_REDIRECT_URI="http://localhost:5174/oauth/microsoft/callback",
    )


def _register_and_login(client, email: str, password: str = "StrongPassword123!") -> str:
    reg = client.post("/api/v1/auth/register", json={"email": email, "password": password})
    assert reg.status_code == 201
    login = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200
    return login.json()["access_token"]


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_provider_capability_registry_separates_personal_and_enterprise():
    connectable = {p.provider: p for p in list_connectable_providers()}
    assert set(connectable.keys()) == {"google", "microsoft"}

    ms = connectable["microsoft"]
    assert ms.account_type == "personal"
    assert ms.required_permissions == ("openid", "profile", "email", "User.Read")
    assert ms.capabilities.oauth_connection == CapabilityStatus.SUPPORTED
    assert ms.capabilities.identity_verification == CapabilityStatus.SUPPORTED
    assert ms.capabilities.login_history == CapabilityStatus.REQUIRES_ENTERPRISE
    assert ms.capabilities.device_session_visibility == CapabilityStatus.REQUIRES_ENTERPRISE
    assert ms.capabilities.mfa_status == CapabilityStatus.REQUIRES_ENTERPRISE
    assert ms.capabilities.token_revocation == CapabilityStatus.UNAVAILABLE

    ms_ent = get_provider_entry("microsoft_entra")
    gg_ent = get_provider_entry("google_workspace")
    assert ms_ent is not None and ms_ent.connectable is False and ms_ent.account_type == "enterprise"
    assert gg_ent is not None and gg_ent.connectable is False and gg_ent.account_type == "enterprise"


def test_providers_endpoint_includes_microsoft_capabilities(client, monkeypatch):
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("TOKEN_ENCRYPTION_KEY", key)
    monkeypatch.setenv("MICROSOFT_CLIENT_ID", "ms-client-1")
    monkeypatch.setenv("MICROSOFT_CLIENT_SECRET", "ms-secret-1")
    monkeypatch.setenv("MICROSOFT_REDIRECT_URI", "http://localhost:5174/oauth/microsoft/callback")
    get_settings.cache_clear()

    try:
        token = _register_and_login(client, "registry@example.com")
        res = client.get("/api/v1/oauth/providers", headers=_headers(token))
        assert res.status_code == 200
        providers = {p["provider"]: p for p in res.json()["providers"]}
        assert "google" in providers
        assert "microsoft" in providers
        ms = providers["microsoft"]
        assert ms["configured"] is True
        assert ms["account_type"] == "personal"
        assert ms["scopes"] == list(MICROSOFT_PERSONAL_SCOPES)
        assert ms["capabilities"]["login_history"] == "requires_enterprise"
        assert ms["capabilities"]["mfa_status"] == "requires_enterprise"
        assert ms["capabilities"]["device_session_visibility"] == "requires_enterprise"
    finally:
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_microsoft_pkce_state_id_token_validation_and_refresh():
    fernet_key = Fernet.generate_key().decode()
    cipher = MultiFernetTokenCipher(fernet_key)
    settings = _make_ms_settings(fernet_key)
    private_key, public_jwk = _generate_rsa_keypair()

    captured_token_request: dict[str, str] = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == MICROSOFT_JWKS_URL:
            return httpx.Response(200, json={"keys": [public_jwk]})
        if url == MICROSOFT_TOKEN_URL:
            body = parse_qs(request.content.decode())
            grant_type = body["grant_type"][0]
            if grant_type == "authorization_code":
                captured_token_request["code_verifier"] = body["code_verifier"][0]
                now = int(time.time())
                id_token = jwt.encode(
                    {
                        "iss": f"https://login.microsoftonline.com/{MICROSOFT_CONSUMERS_TENANT_ID}/v2.0",
                        "tid": MICROSOFT_CONSUMERS_TENANT_ID,
                        "sub": "ms-sub-001",
                        "oid": "00000000-0000-0000-0000-000000000001",
                        "aud": "ms-client-id-123",
                        "iat": now,
                        "exp": now + 3600,
                        "nonce": "raw-nonce-123",
                        "email": "alice@outlook.com",
                        "name": "Alice Outlook",
                    },
                    private_key,
                    algorithm="RS256",
                    headers={"kid": "ms-test-key-1"},
                )
                return httpx.Response(
                    200,
                    json={
                        "access_token": "ms-access-token-1",
                        "refresh_token": "ms-refresh-token-1",
                        "id_token": id_token,
                        "expires_in": 3600,
                        "token_type": "Bearer",
                        "scope": "openid profile email User.Read",
                    },
                )
            if grant_type == "refresh_token":
                return httpx.Response(
                    200,
                    json={
                        "access_token": "ms-access-token-2",
                        "refresh_token": "ms-refresh-token-2",
                        "expires_in": 3600,
                        "token_type": "Bearer",
                    },
                )
        if url == MICROSOFT_GRAPH_ME_URL:
            return httpx.Response(
                200,
                json={
                    "id": "00000000-0000-0000-0000-000000000001",
                    "displayName": "Alice Outlook",
                    "mail": "alice@outlook.com",
                    "userPrincipalName": "alice@outlook.com",
                },
            )
        return httpx.Response(404)

    svc = MicrosoftOAuthService(
        settings=settings,
        cipher=cipher,
        http_client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(_handler)),
    )

    artifacts = svc.build_authorization_request(raw_state="raw-state-123", raw_nonce="raw-nonce-123")
    parsed = urlparse(artifacts.authorization_url)
    qs = parse_qs(parsed.query)
    assert parsed.netloc == "login.microsoftonline.com"
    assert "/consumers/" in parsed.path
    assert qs["code_challenge_method"] == ["S256"]
    assert qs["scope"] == ["openid profile email User.Read"]
    for forbidden in ("Mail.", "Files.", "Contacts.", "Calendars."):
        assert forbidden not in qs["scope"][0]

    decrypted_verifier = cipher.decrypt(artifacts.code_verifier_encrypted)
    assert verify_pkce_challenge(decrypted_verifier, qs["code_challenge"][0])

    result = await svc.exchange_code_for_tokens(
        code="auth-code-123",
        code_verifier_encrypted=artifacts.code_verifier_encrypted,
        expected_nonce_hash=artifacts.nonce_hash,
    )
    assert captured_token_request["code_verifier"] == decrypted_verifier
    assert result.identity.email == "alice@outlook.com"
    assert result.identity.display_name == "Alice Outlook"
    assert cipher.decrypt(result.tokens.access_token_encrypted) == "ms-access-token-1"
    assert result.tokens.refresh_token_encrypted is not None
    assert cipher.decrypt(result.tokens.refresh_token_encrypted) == "ms-refresh-token-1"

    rotated = await svc.refresh_access_token(result.tokens.refresh_token_encrypted)
    assert cipher.decrypt(rotated.access_token_encrypted) == "ms-access-token-2"
    assert rotated.refresh_token_encrypted is not None
    assert cipher.decrypt(rotated.refresh_token_encrypted) == "ms-refresh-token-2"

    # Reject invalid issuer, audience, nonce, and expired token
    now = int(time.time())
    bad_cases = [
        {"iss": "https://login.microsoftonline.com/other-tenant/v2.0", "aud": "ms-client-id-123", "exp": now + 300, "nonce": "raw-nonce-123"},
        {"iss": f"https://login.microsoftonline.com/{MICROSOFT_CONSUMERS_TENANT_ID}/v2.0", "aud": "wrong-aud", "exp": now + 300, "nonce": "raw-nonce-123"},
        {"iss": f"https://login.microsoftonline.com/{MICROSOFT_CONSUMERS_TENANT_ID}/v2.0", "aud": "ms-client-id-123", "exp": now + 300, "nonce": "wrong-nonce"},
        {"iss": f"https://login.microsoftonline.com/{MICROSOFT_CONSUMERS_TENANT_ID}/v2.0", "aud": "ms-client-id-123", "exp": now - 120, "nonce": "raw-nonce-123"},
    ]
    for bad in bad_cases:
        token = jwt.encode(
            {"sub": "s", "iat": now - 200, **bad},
            private_key,
            algorithm="RS256",
            headers={"kid": "ms-test-key-1"},
        )
        with pytest.raises(MicrosoftIdTokenValidationError):
            await svc.validate_id_token(token, expected_nonce_hash=hash_oauth_value("raw-nonce-123"))


def test_microsoft_routes_multi_account_cross_user_replay_and_unlink(client, db_session):
    fernet_key = Fernet.generate_key().decode()
    cipher = MultiFernetTokenCipher(fernet_key)
    settings = _make_ms_settings(fernet_key)
    private_key, public_jwk = _generate_rsa_keypair()

    current_profile = {"sub": "ms-user-1", "email": "one@outlook.com", "name": "MS One"}
    captured_nonces: list[str] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == MICROSOFT_JWKS_URL:
            return httpx.Response(200, json={"keys": [public_jwk]})
        if url == MICROSOFT_TOKEN_URL:
            now = int(time.time())
            nonce_val = captured_nonces[-1]
            id_token = jwt.encode(
                {
                    "iss": f"https://login.microsoftonline.com/{MICROSOFT_CONSUMERS_TENANT_ID}/v2.0",
                    "tid": MICROSOFT_CONSUMERS_TENANT_ID,
                    "sub": current_profile["sub"],
                    "oid": current_profile["sub"],
                    "aud": "ms-client-id-123",
                    "iat": now,
                    "exp": now + 3600,
                    "nonce": nonce_val,
                    "email": current_profile["email"],
                    "name": current_profile["name"],
                },
                private_key,
                algorithm="RS256",
                headers={"kid": "ms-test-key-1"},
            )
            return httpx.Response(
                200,
                json={
                    "access_token": f"access-{current_profile['sub']}",
                    "refresh_token": f"refresh-{current_profile['sub']}",
                    "id_token": id_token,
                    "expires_in": 3600,
                    "token_type": "Bearer",
                },
            )
        if url == MICROSOFT_GRAPH_ME_URL:
            return httpx.Response(
                200,
                json={
                    "id": current_profile["sub"],
                    "displayName": current_profile["name"],
                    "mail": current_profile["email"],
                },
            )
        return httpx.Response(404)

    svc = MicrosoftOAuthService(
        settings=settings,
        cipher=cipher,
        http_client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(_handler)),
    )
    app.dependency_overrides[get_microsoft_oauth_service] = lambda: svc

    try:
        token_a = _register_and_login(client, "usera@example.com")
        token_b = _register_and_login(client, "userb@example.com")

        # Link first Microsoft account for User A
        auth1 = client.post("/api/v1/oauth/microsoft/authorize", headers=_headers(token_a))
        assert auth1.status_code == 200
        qs1 = parse_qs(urlparse(auth1.json()["authorization_url"]).query)
        captured_nonces.append(qs1["nonce"][0])

        cb1 = client.post(
            "/api/v1/oauth/microsoft/callback",
            json={"code": "code-1", "state": qs1["state"][0]},
            headers=_headers(token_a),
        )
        assert cb1.status_code == 200
        ms_id_1 = cb1.json()["id"]
        assert cb1.json()["provider"] == "microsoft"
        assert cb1.json()["provider_email"] == "one@outlook.com"

        # Replay of same state fails
        replay = client.post(
            "/api/v1/oauth/microsoft/callback",
            json={"code": "code-1", "state": qs1["state"][0]},
            headers=_headers(token_a),
        )
        assert replay.status_code == 400

        # Link second Microsoft account for User A
        current_profile.update({"sub": "ms-user-2", "email": "two@hotmail.com", "name": "MS Two"})
        auth2 = client.post("/api/v1/oauth/microsoft/authorize", headers=_headers(token_a))
        qs2 = parse_qs(urlparse(auth2.json()["authorization_url"]).query)
        captured_nonces.append(qs2["nonce"][0])
        cb2 = client.post(
            "/api/v1/oauth/microsoft/callback",
            json={"code": "code-2", "state": qs2["state"][0]},
            headers=_headers(token_a),
        )
        assert cb2.status_code == 200
        assert cb2.json()["provider_email"] == "two@hotmail.com"

        # Add a Google connected account for User A directly to verify unlink isolation
        user_a = db_session.query(ConnectedAccount).filter(ConnectedAccount.id == ms_id_1).first()
        google_acc = ConnectedAccount(
            user_id=user_a.user_id,
            provider="google",
            provider_user_id="g-sub-1",
            provider_email="a@gmail.com",
            provider_email_verified=True,
            status="active",
        )
        db_session.add(google_acc)
        db_session.commit()

        # Tokens are stored encrypted
        stored_token = db_session.query(OAuthToken).filter(OAuthToken.connected_account_id == ms_id_1).first()
        assert stored_token is not None
        assert "access-ms-user-1" not in stored_token.access_token_encrypted

        # Cross-user linking of ms-user-1 by User B is rejected with 409
        current_profile.update({"sub": "ms-user-1", "email": "one@outlook.com", "name": "MS One"})
        auth_b = client.post("/api/v1/oauth/microsoft/authorize", headers=_headers(token_b))
        qsb = parse_qs(urlparse(auth_b.json()["authorization_url"]).query)
        captured_nonces.append(qsb["nonce"][0])
        cb_b = client.post(
            "/api/v1/oauth/microsoft/callback",
            json={"code": "code-b", "state": qsb["state"][0]},
            headers=_headers(token_b),
        )
        assert cb_b.status_code == 409

        # Unlinking Microsoft does not affect Google or second Microsoft account
        del_res = client.delete(f"/api/v1/oauth/accounts/{ms_id_1}", headers=_headers(token_a))
        assert del_res.status_code == 200
        assert del_res.json()["upstream_revocation_status"] == "unsupported"

        remaining = client.get("/api/v1/oauth/accounts", headers=_headers(token_a)).json()
        assert len(remaining) == 2
        assert {a["provider"] for a in remaining} == {"google", "microsoft"}

        # Verify local OAuthToken for unlinked account was deleted
        assert db_session.query(OAuthToken).filter(OAuthToken.connected_account_id == ms_id_1).first() is None
    finally:
        app.dependency_overrides.pop(get_microsoft_oauth_service, None)


@pytest.mark.asyncio
async def test_microsoft_invalid_signature_redirect_uri_and_refresh_preservation():
    from app.services.oauth_microsoft import MicrosoftOAuthProviderError

    fernet_key = Fernet.generate_key().decode()
    cipher = MultiFernetTokenCipher(fernet_key)
    settings = _make_ms_settings(fernet_key)
    private_key, public_jwk = _generate_rsa_keypair()
    wrong_private_key, _ = _generate_rsa_keypair()

    def _handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == MICROSOFT_JWKS_URL:
            return httpx.Response(200, json={"keys": [public_jwk]})
        if url == MICROSOFT_TOKEN_URL:
            return httpx.Response(
                200,
                json={
                    "access_token": "ms-access-rotated-only",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                },
            )
        return httpx.Response(404)

    svc = MicrosoftOAuthService(
        settings=settings,
        cipher=cipher,
        http_client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(_handler)),
    )

    # 1. Invalid RSA signature rejected
    now = int(time.time())
    forged_token = jwt.encode(
        {
            "iss": f"https://login.microsoftonline.com/{MICROSOFT_CONSUMERS_TENANT_ID}/v2.0",
            "sub": "s",
            "aud": "ms-client-id-123",
            "iat": now,
            "exp": now + 300,
            "nonce": "raw-nonce",
        },
        wrong_private_key,
        algorithm="RS256",
        headers={"kid": "ms-test-key-1"},
    )
    with pytest.raises(MicrosoftIdTokenValidationError):
        await svc.validate_id_token(forged_token, expected_nonce_hash=hash_oauth_value("raw-nonce"))

    # 2. Invalid redirect URI and non-consumers authority rejected by Settings
    with pytest.raises(ValueError, match="MICROSOFT_REDIRECT_URI"):
        Settings(
            DATABASE_URL="sqlite:///./_test.db",
            JWT_SECRET_KEY="test-secret-key-not-for-production",
            TOKEN_ENCRYPTION_KEY=fernet_key,
            MICROSOFT_CLIENT_ID="ms-client-id-123",
            MICROSOFT_CLIENT_SECRET="ms-client-secret-xyz",
            MICROSOFT_REDIRECT_URI="javascript:alert(1)",
        )
    with pytest.raises(ValueError, match="MICROSOFT_AUTHORITY"):
        Settings(
            DATABASE_URL="sqlite:///./_test.db",
            JWT_SECRET_KEY="test-secret-key-not-for-production",
            TOKEN_ENCRYPTION_KEY=fernet_key,
            MICROSOFT_CLIENT_ID="ms-client-id-123",
            MICROSOFT_CLIENT_SECRET="ms-client-secret-xyz",
            MICROSOFT_REDIRECT_URI="http://localhost:5174/oauth/microsoft/callback",
            MICROSOFT_AUTHORITY="https://login.microsoftonline.com/organizations",
        )

    # 3. Mismatched expected_redirect_uri rejected before token exchange
    artifacts = svc.build_authorization_request(raw_state="s1", raw_nonce="n1")
    with pytest.raises(MicrosoftOAuthProviderError, match="Redirect URI mismatch"):
        await svc.exchange_code_for_tokens(
            code="code-1",
            code_verifier_encrypted=artifacts.code_verifier_encrypted,
            expected_nonce_hash=artifacts.nonce_hash,
            expected_redirect_uri="https://evil.example/callback",
        )

    # 4. Refresh-token preservation when Microsoft omits refresh_token in response
    existing_rt_enc = cipher.encrypt("original-refresh-token")
    refreshed = await svc.refresh_access_token(existing_rt_enc)
    assert cipher.decrypt(refreshed.access_token_encrypted) == "ms-access-rotated-only"
    assert refreshed.refresh_token_encrypted == existing_rt_enc


def test_microsoft_invalid_expired_state_and_rate_limit(client, db_session):
    fernet_key = Fernet.generate_key().decode()
    cipher = MultiFernetTokenCipher(fernet_key)
    settings = _make_ms_settings(fernet_key)
    svc = MicrosoftOAuthService(settings=settings, cipher=cipher)
    app.dependency_overrides[get_microsoft_oauth_service] = lambda: svc

    try:
        token = _register_and_login(client, "ratelimit_ms@example.com")

        # Unknown state rejected
        bad_state = client.post(
            "/api/v1/oauth/microsoft/callback",
            json={"code": "c1", "state": "unknown-state-value-123456"},
            headers=_headers(token),
        )
        assert bad_state.status_code == 400

        # Expired state rejected
        auth_res = client.post("/api/v1/oauth/microsoft/authorize", headers=_headers(token))
        assert auth_res.status_code == 200
        raw_state = parse_qs(urlparse(auth_res.json()["authorization_url"]).query)["state"][0]
        state_row = db_session.query(OAuthState).filter(OAuthState.state_hash == hash_oauth_value(raw_state)).first()
        state_row.expires_at = datetime.utcnow() - timedelta(minutes=1)
        db_session.commit()

        expired = client.post(
            "/api/v1/oauth/microsoft/callback",
            json={"code": "c1", "state": raw_state},
            headers=_headers(token),
        )
        assert expired.status_code == 400

        # Callback rate limiting (10/minute)
        statuses = []
        for _ in range(12):
            r = client.post(
                "/api/v1/oauth/microsoft/callback",
                json={"code": "c1", "state": "unknown-state-value-123456"},
                headers=_headers(token),
            )
            statuses.append(r.status_code)
        assert 429 in statuses
    finally:
        app.dependency_overrides.pop(get_microsoft_oauth_service, None)


def test_microsoft_mobile_android_ios_public_client_and_platform_binding(client, db_session):
    fernet_key = Fernet.generate_key().decode()
    cipher = MultiFernetTokenCipher(fernet_key)
    settings = Settings(
        DATABASE_URL="sqlite:///./_test.db",
        JWT_SECRET_KEY="test-secret-key-not-for-production",
        TOKEN_ENCRYPTION_KEY=fernet_key,
        MICROSOFT_CLIENT_ID="ms-web-client-id",
        MICROSOFT_CLIENT_SECRET="ms-web-secret-never-sent-to-mobile",
        MICROSOFT_REDIRECT_URI="http://localhost:5174/oauth/microsoft/callback",
        MICROSOFT_MOBILE_CLIENT_ID="ms-mobile-client-id",
        MICROSOFT_ANDROID_REDIRECT_URI="msauth://com.inforatech.digitalshield/android-sig-hash",
        MICROSOFT_IOS_REDIRECT_URI="msauth.com.inforatech.digitalshield://auth",
    )
    private_key, public_jwk = _generate_rsa_keypair()

    captured_token_posts: list[dict[str, list[str]]] = []
    captured_nonces: list[str] = []
    active_sub = {"sub": "ms-android-1", "email": "android@outlook.com", "aud": "ms-mobile-client-id"}

    def _handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == MICROSOFT_JWKS_URL:
            return httpx.Response(200, json={"keys": [public_jwk]})
        if url == MICROSOFT_TOKEN_URL:
            body = parse_qs(request.content.decode())
            captured_token_posts.append(body)
            now = int(time.time())
            id_token = jwt.encode(
                {
                    "iss": f"https://login.microsoftonline.com/{MICROSOFT_CONSUMERS_TENANT_ID}/v2.0",
                    "tid": MICROSOFT_CONSUMERS_TENANT_ID,
                    "sub": active_sub["sub"],
                    "oid": active_sub["sub"],
                    "aud": active_sub["aud"],
                    "iat": now,
                    "exp": now + 3600,
                    "nonce": captured_nonces[-1],
                    "email": active_sub["email"],
                    "name": "Mobile User",
                },
                private_key,
                algorithm="RS256",
                headers={"kid": "ms-test-key-1"},
            )
            return httpx.Response(
                200,
                json={
                    "access_token": f"access-{active_sub['sub']}",
                    "refresh_token": f"refresh-{active_sub['sub']}",
                    "id_token": id_token,
                    "expires_in": 3600,
                    "token_type": "Bearer",
                },
            )
        if url == MICROSOFT_GRAPH_ME_URL:
            return httpx.Response(
                200,
                json={"id": active_sub["sub"], "displayName": "Mobile User", "mail": active_sub["email"]},
            )
        return httpx.Response(404)

    svc = MicrosoftOAuthService(
        settings=settings,
        cipher=cipher,
        http_client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(_handler)),
    )
    app.dependency_overrides[get_microsoft_oauth_service] = lambda: svc

    try:
        token = _register_and_login(client, "mobile@example.com")

        # Arbitrary redirect_uri in authorize or callback payload is rejected (422)
        bad_auth = client.post(
            "/api/v1/oauth/microsoft/authorize",
            json={"platform": "android", "redirect_uri": "https://attacker.example/cb"},
            headers=_headers(token),
        )
        assert bad_auth.status_code == 422
        bad_cb = client.post(
            "/api/v1/oauth/microsoft/callback",
            json={"code": "c", "state": "s" * 20, "platform": "android", "redirect_uri": "https://attacker.example/cb"},
            headers=_headers(token),
        )
        assert bad_cb.status_code == 422

        # Android authorization uses mobile client_id + Android redirect_uri + PKCE S256
        android_auth = client.post(
            "/api/v1/oauth/microsoft/authorize",
            json={"platform": "android"},
            headers=_headers(token),
        )
        assert android_auth.status_code == 200
        assert android_auth.json()["platform"] == "android"
        qs_a = parse_qs(urlparse(android_auth.json()["authorization_url"]).query)
        assert qs_a["client_id"] == ["ms-mobile-client-id"]
        assert qs_a["redirect_uri"] == ["msauth://com.inforatech.digitalshield/android-sig-hash"]
        assert qs_a["code_challenge_method"] == ["S256"]

        # Platform mismatch: submitting Android state with platform="web" or "ios" fails (400)
        mismatch = client.post(
            "/api/v1/oauth/microsoft/callback",
            json={"code": "code-android", "state": qs_a["state"][0], "platform": "web"},
            headers=_headers(token),
        )
        assert mismatch.status_code == 400

        # Valid Android callback exchanges code WITHOUT client_secret and WITH PKCE verifier
        captured_nonces.append(qs_a["nonce"][0])
        android_cb = client.post(
            "/api/v1/oauth/microsoft/callback",
            json={"code": "code-android", "state": qs_a["state"][0], "platform": "android"},
            headers=_headers(token),
        )
        assert android_cb.status_code == 200
        assert android_cb.json()["provider_email"] == "android@outlook.com"
        assert "client_secret" not in captured_token_posts[-1]
        assert captured_token_posts[-1]["client_id"] == ["ms-mobile-client-id"]
        assert captured_token_posts[-1]["redirect_uri"] == ["msauth://com.inforatech.digitalshield/android-sig-hash"]
        assert verify_pkce_challenge(captured_token_posts[-1]["code_verifier"][0], qs_a["code_challenge"][0])

        # iOS authorization & callback also omit client_secret and use iOS redirect URI
        active_sub.update({"sub": "ms-ios-1", "email": "ios@outlook.com", "aud": "ms-mobile-client-id"})
        ios_auth = client.post(
            "/api/v1/oauth/microsoft/authorize",
            json={"platform": "ios"},
            headers=_headers(token),
        )
        assert ios_auth.status_code == 200
        qs_i = parse_qs(urlparse(ios_auth.json()["authorization_url"]).query)
        assert qs_i["redirect_uri"] == ["msauth.com.inforatech.digitalshield://auth"]

        captured_nonces.append(qs_i["nonce"][0])
        ios_cb = client.post(
            "/api/v1/oauth/microsoft/callback",
            json={"code": "code-ios", "state": qs_i["state"][0], "platform": "ios"},
            headers=_headers(token),
        )
        assert ios_cb.status_code == 200
        assert ios_cb.json()["provider_email"] == "ios@outlook.com"
        assert "client_secret" not in captured_token_posts[-1]

        # Web backward compatibility (no platform field) still uses web client_id + client_secret
        active_sub.update({"sub": "ms-web-1", "email": "web@outlook.com", "aud": "ms-web-client-id"})
        web_auth = client.post("/api/v1/oauth/microsoft/authorize", headers=_headers(token))
        assert web_auth.status_code == 200
        qs_w = parse_qs(urlparse(web_auth.json()["authorization_url"]).query)
        assert qs_w["client_id"] == ["ms-web-client-id"]
        captured_nonces.append(qs_w["nonce"][0])
        web_cb = client.post(
            "/api/v1/oauth/microsoft/callback",
            json={"code": "code-web", "state": qs_w["state"][0]},
            headers=_headers(token),
        )
        assert web_cb.status_code == 200
        assert captured_token_posts[-1]["client_secret"] == ["ms-web-secret-never-sent-to-mobile"]
    finally:
        app.dependency_overrides.pop(get_microsoft_oauth_service, None)


def test_microsoft_mobile_config_validation():
    fernet_key = Fernet.generate_key().decode()
    with pytest.raises(ValueError, match="MICROSOFT_ANDROID_REDIRECT_URI"):
        Settings(
            DATABASE_URL="sqlite:///./_test.db",
            JWT_SECRET_KEY="test-secret-key-not-for-production",
            TOKEN_ENCRYPTION_KEY=fernet_key,
            MICROSOFT_MOBILE_CLIENT_ID="ms-mobile-client-id",
            MICROSOFT_ANDROID_REDIRECT_URI="javascript:alert(1)",
        )
    with pytest.raises(ValueError, match="MICROSOFT_MOBILE_CLIENT_ID"):
        Settings(
            DATABASE_URL="sqlite:///./_test.db",
            JWT_SECRET_KEY="test-secret-key-not-for-production",
            TOKEN_ENCRYPTION_KEY=fernet_key,
            MICROSOFT_IOS_REDIRECT_URI="msauth.com.inforatech.digitalshield://auth",
        )
    with pytest.raises(ValueError, match="MICROSOFT_AUTHORITY"):
        Settings(
            DATABASE_URL="sqlite:///./_test.db",
            JWT_SECRET_KEY="test-secret-key-not-for-production",
            TOKEN_ENCRYPTION_KEY=fernet_key,
            MICROSOFT_MOBILE_CLIENT_ID="ms-mobile-client-id",
            MICROSOFT_ANDROID_REDIRECT_URI="com.inforatech.digitalshield://oauth/microsoft/callback",
            MICROSOFT_AUTHORITY="https://login.microsoftonline.com/evil-tenant",
        )


@pytest.mark.asyncio
async def test_microsoft_common_and_consumers_issuer_validation():
    fernet_key = Fernet.generate_key().decode()
    cipher = MultiFernetTokenCipher(fernet_key)
    private_key, public_jwk = _generate_rsa_keypair()

    common_settings = Settings(
        DATABASE_URL="sqlite:///./_test.db",
        JWT_SECRET_KEY="test-secret-key-not-for-production",
        TOKEN_ENCRYPTION_KEY=fernet_key,
        MICROSOFT_CLIENT_ID="ms-client-id-123",
        MICROSOFT_CLIENT_SECRET="ms-client-secret-xyz",
        MICROSOFT_REDIRECT_URI="http://localhost:5174/oauth/microsoft/callback",
        MICROSOFT_AUTHORITY="https://login.microsoftonline.com/common",
    )

    common_jwks_url = "https://login.microsoftonline.com/common/discovery/v2.0/keys"
    common_token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    org_tid = "72f988bf-86f1-41af-91ab-2d7cd011db47"

    def _common_handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == common_jwks_url:
            return httpx.Response(200, json={"keys": [public_jwk]})
        if url == common_token_url:
            now = int(time.time())
            id_token = jwt.encode(
                {
                    "iss": f"https://login.microsoftonline.com/{org_tid}/v2.0",
                    "tid": org_tid,
                    "sub": "org-user-1",
                    "aud": "ms-client-id-123",
                    "iat": now,
                    "exp": now + 3600,
                    "nonce": "nonce-org-1",
                    "preferred_username": "work@contoso.com",
                    "name": "Contoso User",
                },
                private_key,
                algorithm="RS256",
                headers={"kid": "ms-test-key-1"},
            )
            return httpx.Response(
                200,
                json={"access_token": "at-org", "id_token": id_token, "expires_in": 3600, "token_type": "Bearer"},
            )
        if url == MICROSOFT_GRAPH_ME_URL:
            return httpx.Response(200, json={"id": "org-user-1", "displayName": "Contoso User", "mail": "work@contoso.com"})
        return httpx.Response(404)

    common_svc = MicrosoftOAuthService(
        settings=common_settings,
        cipher=cipher,
        http_client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(_common_handler)),
    )

    artifacts = common_svc.build_authorization_request(raw_state="s-common", raw_nonce="nonce-org-1")
    assert artifacts.authorization_url.startswith("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?")

    # /common accepts Work/School organizational issuer
    org_result = await common_svc.exchange_code_for_tokens(
        code="code-org",
        code_verifier_encrypted=artifacts.code_verifier_encrypted,
        expected_nonce_hash=artifacts.nonce_hash,
    )
    assert org_result.identity.email == "work@contoso.com"

    # /common also accepts Personal Microsoft issuer
    now = int(time.time())
    personal_token = jwt.encode(
        {
            "iss": f"https://login.microsoftonline.com/{MICROSOFT_CONSUMERS_TENANT_ID}/v2.0",
            "tid": MICROSOFT_CONSUMERS_TENANT_ID,
            "sub": "personal-sub-1",
            "aud": "ms-client-id-123",
            "iat": now,
            "exp": now + 300,
            "nonce": "nonce-org-1",
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "ms-test-key-1"},
    )
    claims = await common_svc.validate_id_token(personal_token, expected_nonce_hash=hash_oauth_value("nonce-org-1"))
    assert claims["tid"] == MICROSOFT_CONSUMERS_TENANT_ID

    # /common rejects missing tid, non-UUID tid, mismatched tid/iss, and untrusted issuer host
    bad_multi_cases = [
        {"iss": f"https://login.microsoftonline.com/{org_tid}/v2.0"},  # missing tid
        {"iss": "https://login.microsoftonline.com/not-a-uuid/v2.0", "tid": "not-a-uuid"},
        {"iss": f"https://login.microsoftonline.com/{org_tid}/v2.0", "tid": MICROSOFT_CONSUMERS_TENANT_ID},
        {"iss": f"https://evil.example.com/{org_tid}/v2.0", "tid": org_tid},
    ]
    for bad in bad_multi_cases:
        tok = jwt.encode(
            {"sub": "s", "aud": "ms-client-id-123", "iat": now, "exp": now + 300, "nonce": "nonce-org-1", **bad},
            private_key,
            algorithm="RS256",
            headers={"kid": "ms-test-key-1"},
        )
        with pytest.raises(MicrosoftIdTokenValidationError):
            await common_svc.validate_id_token(tok, expected_nonce_hash=hash_oauth_value("nonce-org-1"))

    # /consumers rejects organizational tenant tokens
    consumers_svc = MicrosoftOAuthService(
        settings=_make_ms_settings(fernet_key),
        cipher=cipher,
        http_client_factory=lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"keys": [public_jwk]}))
        ),
    )
    org_tok = jwt.encode(
        {
            "iss": f"https://login.microsoftonline.com/{org_tid}/v2.0",
            "tid": org_tid,
            "sub": "org-user",
            "aud": "ms-client-id-123",
            "iat": now,
            "exp": now + 300,
            "nonce": "nonce-org-1",
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "ms-test-key-1"},
    )
    with pytest.raises(MicrosoftIdTokenValidationError, match="Organizational tenant"):
        await consumers_svc.validate_id_token(org_tok, expected_nonce_hash=hash_oauth_value("nonce-org-1"))


def test_microsoft_web_and_android_authorization_url_parameters_and_missing_client_id(client):
    from app.services.oauth_microsoft import MicrosoftOAuthNotConfiguredError

    fernet_key = Fernet.generate_key().decode()
    cipher = MultiFernetTokenCipher(fernet_key)
    settings = Settings(
        DATABASE_URL="sqlite:///./_test.db",
        JWT_SECRET_KEY="test-secret-key-not-for-production",
        TOKEN_ENCRYPTION_KEY=fernet_key,
        MICROSOFT_CLIENT_ID="ms-web-client-id-exact",
        MICROSOFT_CLIENT_SECRET="ms-web-secret-exact",
        MICROSOFT_REDIRECT_URI="http://localhost:5174/oauth/microsoft/callback",
        MICROSOFT_MOBILE_CLIENT_ID="ms-mobile-client-id-exact",
        MICROSOFT_ANDROID_REDIRECT_URI="com.inforatech.digitalshield://oauth/microsoft/callback",
        MICROSOFT_AUTHORITY="https://login.microsoftonline.com/common",
    )
    svc = MicrosoftOAuthService(settings=settings, cipher=cipher)
    app.dependency_overrides[get_microsoft_oauth_service] = lambda: svc

    try:
        token = _register_and_login(client, "urlparams@example.com")

        # Web authorization URL contains exact MICROSOFT_CLIENT_ID, Web redirect_uri, /common, and all mandatory params
        web_res = client.post("/api/v1/oauth/microsoft/authorize", headers=_headers(token))
        assert web_res.status_code == 200
        web_url = urlparse(web_res.json()["authorization_url"])
        web_qs = parse_qs(web_url.query)
        assert web_url.scheme == "https"
        assert web_url.netloc == "login.microsoftonline.com"
        assert web_url.path == "/common/oauth2/v2.0/authorize"
        assert web_qs["client_id"] == ["ms-web-client-id-exact"]
        assert web_qs["redirect_uri"] == ["http://localhost:5174/oauth/microsoft/callback"]
        assert web_qs["response_type"] == ["code"]
        assert web_qs["scope"] == ["openid profile email User.Read"]
        assert web_qs["code_challenge_method"] == ["S256"]
        assert bool(web_qs["state"][0])
        assert bool(web_qs["nonce"][0])
        assert bool(web_qs["code_challenge"][0])

        # Android authorization URL uses MICROSOFT_MOBILE_CLIENT_ID and Android redirect_uri
        and_res = client.post(
            "/api/v1/oauth/microsoft/authorize",
            json={"platform": "android"},
            headers=_headers(token),
        )
        assert and_res.status_code == 200
        and_url = urlparse(and_res.json()["authorization_url"])
        and_qs = parse_qs(and_url.query)
        assert and_url.path == "/common/oauth2/v2.0/authorize"
        assert and_qs["client_id"] == ["ms-mobile-client-id-exact"]
        assert and_qs["redirect_uri"] == ["com.inforatech.digitalshield://oauth/microsoft/callback"]

        # Missing client_id fails with clear 503 server-side configuration error (never emits URL without client_id)
        unconfigured_settings = Settings(
            DATABASE_URL="sqlite:///./_test.db",
            JWT_SECRET_KEY="test-secret-key-not-for-production",
            TOKEN_ENCRYPTION_KEY=fernet_key,
        )
        unconfigured_svc = MicrosoftOAuthService(settings=unconfigured_settings, cipher=cipher)
        with pytest.raises(MicrosoftOAuthNotConfiguredError):
            unconfigured_svc.build_authorization_request(platform="web")

        app.dependency_overrides[get_microsoft_oauth_service] = lambda: unconfigured_svc
        err_res = client.post("/api/v1/oauth/microsoft/authorize", headers=_headers(token))
        assert err_res.status_code == 503
        assert "not configured" in err_res.json()["detail"].lower()
    finally:
        app.dependency_overrides.pop(get_microsoft_oauth_service, None)
