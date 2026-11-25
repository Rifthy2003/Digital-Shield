"""
API & Security tests for Phase 18 — Task 18.5: OAuth API Routes & Audit Logging.

Uses ephemeral RSA keys and `httpx.MockTransport` — never real Google credentials,
and never weakens RS256 ID-token signature / claims verification.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from app.api.routes.oauth import cleanup_expired_oauth_states, get_google_oauth_service
from app.config import Settings
from app.core.crypto import MultiFernetTokenCipher
from app.core.security import hash_ip
from app.main import app
from app.models.audit_log import AuditLog
from app.models.oauth import ConnectedAccount, OAuthState, OAuthToken
from app.services.oauth_google import (
    GOOGLE_JWKS_URL,
    GOOGLE_REVOKE_URL,
    GOOGLE_TOKEN_URL,
    GoogleOAuthService,
    hash_oauth_value,
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
        GOOGLE_CLIENT_SECRET="test-super-secret-client-secret",
        GOOGLE_REDIRECT_URI="http://localhost:5174/oauth/google/callback",
        TOKEN_ENCRYPTION_KEY=enc_key,
        _env_file=None,
    )


def _sign_id_token(
    private_key,
    kid: str,
    *,
    sub: str,
    email: str,
    nonce: str,
    name: str = "Citizen User",
) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "iss": "https://accounts.google.com",
        "aud": "test-client-id",
        "sub": sub,
        "email": email,
        "email_verified": True,
        "name": name,
        "picture": "https://lh3.googleusercontent.com/a/avatar",
        "nonce": nonce,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=10)).timestamp()),
    }
    return jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})


def _register_and_login(client, email: str, password: str = "CorrectHorse123Battery") -> dict[str, str]:
    reg = client.post("/api/v1/auth/register", json={"email": email, "password": password, "full_name": email})
    assert reg.status_code == 201
    login = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def _extract_state_and_nonce(auth_url: str) -> tuple[str, str]:
    qs = parse_qs(urlparse(auth_url).query)
    return qs["state"][0], qs["nonce"][0]


def test_all_oauth_endpoints_require_authentication(client):
    assert client.get("/api/v1/oauth/providers").status_code == 401
    assert client.get("/api/v1/oauth/accounts").status_code == 401
    assert client.post("/api/v1/oauth/google/authorize").status_code == 401
    assert client.post("/api/v1/oauth/google/callback", json={"code": "c", "state": "s" * 20}).status_code == 401
    assert client.delete("/api/v1/oauth/accounts/nonexistent").status_code == 401


def test_providers_endpoint_hides_secrets(client, auth_headers, monkeypatch):
    enc_key = Fernet.generate_key().decode()
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "top-secret-google-value")
    monkeypatch.setenv("GOOGLE_REDIRECT_URI", "http://localhost:5174/oauth/google/callback")
    monkeypatch.setenv("TOKEN_ENCRYPTION_KEY", enc_key)
    from app.config import get_settings
    get_settings.cache_clear()
    try:
        resp = client.get("/api/v1/oauth/providers", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["providers"][0]["provider"] == "google"
        assert body["providers"][0]["configured"] is True
        assert body["providers"][0]["scopes"] == ["openid", "email", "profile"]
        assert "top-secret-google-value" not in resp.text
        assert enc_key not in resp.text
    finally:
        get_settings.cache_clear()


def test_authorize_persists_state_and_cleans_expired_states(client, auth_headers, db_session):
    enc_key = Fernet.generate_key().decode()
    settings = _make_settings(enc_key)
    cipher = MultiFernetTokenCipher(enc_key)
    svc = GoogleOAuthService(settings=settings, cipher=cipher)
    app.dependency_overrides[get_google_oauth_service] = lambda: svc

    try:
        # Insert an expired OAuthState and an active OAuthState
        me = client.get("/api/v1/auth/me", headers=auth_headers).json()
        expired_state = OAuthState(
            user_id=me["id"],
            provider="google",
            state_hash=hash_oauth_value("expired-state-123456"),
            nonce_hash=hash_oauth_value("expired-nonce"),
            code_verifier_encrypted=cipher.encrypt("v-expired"),
            redirect_uri="http://localhost:5174/oauth/google/callback",
            used=False,
            expires_at=datetime.utcnow() - timedelta(minutes=1),
        )
        active_state = OAuthState(
            user_id=me["id"],
            provider="google",
            state_hash=hash_oauth_value("active-state-123456"),
            nonce_hash=hash_oauth_value("active-nonce"),
            code_verifier_encrypted=cipher.encrypt("v-active"),
            redirect_uri="http://localhost:5174/oauth/google/callback",
            used=False,
            expires_at=datetime.utcnow() + timedelta(minutes=8),
        )
        db_session.add_all([expired_state, active_state])
        db_session.commit()

        resp = client.post("/api/v1/oauth/google/authorize", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["provider"] == "google"
        raw_state, _ = _extract_state_and_nonce(data["authorization_url"])

        # Expired state was cleaned up; active + new state remain
        assert db_session.query(OAuthState).filter(OAuthState.state_hash == hash_oauth_value("expired-state-123456")).first() is None
        assert db_session.query(OAuthState).filter(OAuthState.state_hash == hash_oauth_value("active-state-123456")).first() is not None

        stored = db_session.query(OAuthState).filter(OAuthState.state_hash == hash_oauth_value(raw_state)).first()
        assert stored is not None
        assert stored.used is False
        assert stored.state_hash != raw_state
        assert "test-super-secret-client-secret" not in resp.text

        # Unsupported provider rejected
        assert client.post("/api/v1/oauth/facebook/authorize", headers=auth_headers).status_code == 404
        assert client.post("/api/v1/oauth/facebook/callback", json={"code": "c", "state": "s" * 20}, headers=auth_headers).status_code == 404
    finally:
        app.dependency_overrides.pop(get_google_oauth_service, None)


def test_full_callback_multiple_accounts_refresh_preservation_and_ownership(client, db_session):
    enc_key = Fernet.generate_key().decode()
    settings = _make_settings(enc_key)
    cipher = MultiFernetTokenCipher(enc_key)
    priv_key, jwk_dict = _gen_rsa_jwk("kid-1")

    next_identity = {"sub": "google-sub-1", "email": "one@gmail.com", "nonce": "", "omit_refresh": False, "access": "ya29.access-1", "refresh": "1//refresh-1"}

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == GOOGLE_TOKEN_URL:
            id_tok = _sign_id_token(
                priv_key,
                "kid-1",
                sub=next_identity["sub"],
                email=next_identity["email"],
                nonce=next_identity["nonce"],
            )
            body = {
                "access_token": next_identity["access"],
                "id_token": id_tok,
                "expires_in": 3600,
                "token_type": "Bearer",
                "scope": "openid email profile",
            }
            if not next_identity["omit_refresh"]:
                body["refresh_token"] = next_identity["refresh"]
            return httpx.Response(200, json=body)
        if str(request.url) == GOOGLE_JWKS_URL:
            return httpx.Response(200, json={"keys": [jwk_dict]})
        if str(request.url) == GOOGLE_REVOKE_URL:
            return httpx.Response(200)
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    svc = GoogleOAuthService(
        settings=settings,
        cipher=cipher,
        http_client_factory=lambda: httpx.AsyncClient(transport=transport, timeout=5.0),
    )
    app.dependency_overrides[get_google_oauth_service] = lambda: svc

    try:
        user_a_headers = _register_and_login(client, "usera@example.com")
        user_b_headers = _register_and_login(client, "userb@example.com")

        # 1. Link first Google account to User A
        auth_1 = client.post("/api/v1/oauth/google/authorize", headers=user_a_headers).json()
        state_1, nonce_1 = _extract_state_and_nonce(auth_1["authorization_url"])
        next_identity["nonce"] = nonce_1

        cb_1 = client.post(
            "/api/v1/oauth/google/callback",
            json={"code": "code-1", "state": state_1},
            headers={**user_a_headers, "X-Forwarded-For": "198.51.100.10"},
        )
        assert cb_1.status_code == 200
        acc1_data = cb_1.json()
        assert acc1_data["provider_email"] == "one@gmail.com"
        assert "ya29.access-1" not in cb_1.text
        assert "1//refresh-1" not in cb_1.text

        # Verify encrypted token & encryption_key_id in DB
        tok1 = db_session.query(OAuthToken).filter(OAuthToken.connected_account_id == acc1_data["id"]).first()
        assert tok1 is not None
        assert tok1.encryption_key_id == cipher.key_id
        assert cipher.decrypt(tok1.access_token_encrypted) == "ya29.access-1"
        assert cipher.decrypt(tok1.refresh_token_encrypted) == "1//refresh-1"

        # 2. Replay same state -> rejected (400)
        replay = client.post(
            "/api/v1/oauth/google/callback",
            json={"code": "code-1", "state": state_1},
            headers=user_a_headers,
        )
        assert replay.status_code == 400

        # 3. Link SECOND Google account to same User A
        auth_2 = client.post("/api/v1/oauth/google/authorize", headers=user_a_headers).json()
        state_2, nonce_2 = _extract_state_and_nonce(auth_2["authorization_url"])
        next_identity.update({"sub": "google-sub-2", "email": "two@gmail.com", "nonce": nonce_2, "access": "ya29.access-2", "refresh": "1//refresh-2"})

        cb_2 = client.post(
            "/api/v1/oauth/google/callback",
            json={"code": "code-2", "state": state_2},
            headers=user_a_headers,
        )
        assert cb_2.status_code == 200
        assert cb_2.json()["provider_email"] == "two@gmail.com"

        # User A lists 2 accounts; User B lists 0 accounts
        list_a = client.get("/api/v1/oauth/accounts", headers=user_a_headers)
        assert len(list_a.json()) == 2
        assert "ya29." not in list_a.text
        assert "1//" not in list_a.text
        assert len(client.get("/api/v1/oauth/accounts", headers=user_b_headers).json()) == 0

        # 4. Re-link Google account 1 to User A when Google omits refresh_token -> preserves existing refresh token!
        auth_3 = client.post("/api/v1/oauth/google/authorize", headers=user_a_headers).json()
        state_3, nonce_3 = _extract_state_and_nonce(auth_3["authorization_url"])
        next_identity.update({"sub": "google-sub-1", "email": "one@gmail.com", "nonce": nonce_3, "omit_refresh": True, "access": "ya29.access-1-new"})

        cb_3 = client.post("/api/v1/oauth/google/callback", json={"code": "code-3", "state": state_3}, headers=user_a_headers)
        assert cb_3.status_code == 200
        db_session.refresh(tok1)
        assert cipher.decrypt(tok1.access_token_encrypted) == "ya29.access-1-new"
        assert cipher.decrypt(tok1.refresh_token_encrypted) == "1//refresh-1"

        # 5. User B cannot link google-sub-1 (already owned by User A) -> 409 Conflict without leaking User A
        auth_b = client.post("/api/v1/oauth/google/authorize", headers=user_b_headers).json()
        state_b, nonce_b = _extract_state_and_nonce(auth_b["authorization_url"])
        next_identity.update({"sub": "google-sub-1", "email": "one@gmail.com", "nonce": nonce_b, "omit_refresh": False})

        cb_conflict = client.post("/api/v1/oauth/google/callback", json={"code": "code-b", "state": state_b}, headers=user_b_headers)
        assert cb_conflict.status_code == 409
        assert "usera@example.com" not in cb_conflict.text

        # 6. Cross-user state rejection: User B tries to use User A's state
        auth_a4 = client.post("/api/v1/oauth/google/authorize", headers=user_a_headers).json()
        state_a4, _ = _extract_state_and_nonce(auth_a4["authorization_url"])
        assert client.post("/api/v1/oauth/google/callback", json={"code": "c", "state": state_a4}, headers=user_b_headers).status_code == 400

        # 7. User B cannot disconnect User A's account (404 IDOR protection)
        assert client.delete(f"/api/v1/oauth/accounts/{acc1_data['id']}", headers=user_b_headers).status_code == 404

        # 8. User A disconnects account 1 (revocation succeeds)
        disc = client.delete(f"/api/v1/oauth/accounts/{acc1_data['id']}", headers=user_a_headers)
        assert disc.status_code == 200
        assert disc.json()["upstream_revocation_status"] == "revoked"
        assert db_session.get(ConnectedAccount, acc1_data["id"]) is None

        # 9. Audit log check + secret redaction
        audits = db_session.query(AuditLog).filter(AuditLog.action.like("oauth.%")).all()
        actions = {a.action for a in audits}
        assert {"oauth.authorization_started", "oauth.account_linked", "oauth.callback_failed", "oauth.account_disconnected"}.issubset(actions)
        linked_audit = next(a for a in audits if a.action == "oauth.account_linked")
        assert linked_audit.ip_hash == hash_ip("198.51.100.10")

        serialized_audits = str([(a.action, a.resource, a.details) for a in audits])
        for secret_val in ("ya29.access", "1//refresh", "code-1", state_1, nonce_1, "test-super-secret-client-secret"):
            assert secret_val not in serialized_audits
    finally:
        app.dependency_overrides.pop(get_google_oauth_service, None)


def test_expired_invalid_state_and_revocation_failure_still_deletes_local(client, auth_headers, db_session):
    enc_key = Fernet.generate_key().decode()
    settings = _make_settings(enc_key)
    cipher = MultiFernetTokenCipher(enc_key)
    priv_key, jwk_dict = _gen_rsa_jwk("kid-1")
    nonce_holder = {"nonce": ""}

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == GOOGLE_TOKEN_URL:
            return httpx.Response(
                200,
                json={
                    "access_token": "ya29.acc",
                    "refresh_token": "1//ref",
                    "id_token": _sign_id_token(priv_key, "kid-1", sub="sub-rev-fail", email="rev@gmail.com", nonce=nonce_holder["nonce"]),
                    "expires_in": 3600,
                },
            )
        if str(request.url) == GOOGLE_JWKS_URL:
            return httpx.Response(200, json={"keys": [jwk_dict]})
        if str(request.url) == GOOGLE_REVOKE_URL:
            return httpx.Response(500, json={"error": "server_error"})
        return httpx.Response(404)

    svc = GoogleOAuthService(
        settings=settings,
        cipher=cipher,
        http_client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0),
    )
    app.dependency_overrides[get_google_oauth_service] = lambda: svc

    try:
        # Invalid state rejected
        assert client.post("/api/v1/oauth/google/callback", json={"code": "c", "state": "nonexistent-state-value-123"}, headers=auth_headers).status_code == 400

        # Expired state rejected
        me = client.get("/api/v1/auth/me", headers=auth_headers).json()
        raw_exp_state = "expired-raw-state-1234567890"
        db_session.add(
            OAuthState(
                user_id=me["id"],
                provider="google",
                state_hash=hash_oauth_value(raw_exp_state),
                nonce_hash=hash_oauth_value("n"),
                code_verifier_encrypted=cipher.encrypt("v"),
                redirect_uri="http://localhost:5174/oauth/google/callback",
                used=False,
                expires_at=datetime.utcnow() - timedelta(seconds=10),
            )
        )
        db_session.commit()
        assert client.post("/api/v1/oauth/google/callback", json={"code": "c", "state": raw_exp_state}, headers=auth_headers).status_code == 400

        # Link account, then disconnect when upstream revocation fails -> local record still deleted + audited
        auth = client.post("/api/v1/oauth/google/authorize", headers=auth_headers).json()
        st, nc = _extract_state_and_nonce(auth["authorization_url"])
        nonce_holder["nonce"] = nc
        linked = client.post("/api/v1/oauth/google/callback", json={"code": "c1", "state": st}, headers=auth_headers)
        assert linked.status_code == 200
        acc_id = linked.json()["id"]

        disc = client.delete(f"/api/v1/oauth/accounts/{acc_id}", headers=auth_headers)
        assert disc.status_code == 200
        assert disc.json()["upstream_revocation_status"] == "failed"
        assert db_session.get(ConnectedAccount, acc_id) is None
        assert db_session.query(OAuthToken).filter(OAuthToken.connected_account_id == acc_id).first() is None
        assert db_session.query(AuditLog).filter(AuditLog.action == "oauth.revocation_failed").first() is not None
    finally:
        app.dependency_overrides.pop(get_google_oauth_service, None)


def test_concurrent_callback_attempts_allow_only_one(client, auth_headers):
    enc_key = Fernet.generate_key().decode()
    settings = _make_settings(enc_key)
    cipher = MultiFernetTokenCipher(enc_key)
    priv_key, jwk_dict = _gen_rsa_jwk("kid-1")
    nonce_holder = {"nonce": ""}

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == GOOGLE_TOKEN_URL:
            return httpx.Response(
                200,
                json={
                    "access_token": "ya29.conc",
                    "id_token": _sign_id_token(priv_key, "kid-1", sub="sub-conc", email="conc@gmail.com", nonce=nonce_holder["nonce"]),
                    "expires_in": 3600,
                },
            )
        if str(request.url) == GOOGLE_JWKS_URL:
            return httpx.Response(200, json={"keys": [jwk_dict]})
        return httpx.Response(404)

    svc = GoogleOAuthService(
        settings=settings,
        cipher=cipher,
        http_client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0),
    )
    app.dependency_overrides[get_google_oauth_service] = lambda: svc

    try:
        auth = client.post("/api/v1/oauth/google/authorize", headers=auth_headers).json()
        state, nonce = _extract_state_and_nonce(auth["authorization_url"])
        nonce_holder["nonce"] = nonce

        def send_cb():
            return client.post("/api/v1/oauth/google/callback", json={"code": "conc-code", "state": state}, headers=auth_headers).status_code

        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(pool.map(lambda _: send_cb(), range(2)))

        assert sorted(statuses) == [200, 400]
    finally:
        app.dependency_overrides.pop(get_google_oauth_service, None)


def test_oauth_rate_limiting(client, auth_headers):
    enc_key = Fernet.generate_key().decode()
    settings = _make_settings(enc_key)
    cipher = MultiFernetTokenCipher(enc_key)
    svc = GoogleOAuthService(settings=settings, cipher=cipher)
    app.dependency_overrides[get_google_oauth_service] = lambda: svc

    try:
        # 10/minute on /google/authorize -> 11th returns 429
        for _ in range(10):
            r = client.post("/api/v1/oauth/google/authorize", headers=auth_headers)
            assert r.status_code == 200
        assert client.post("/api/v1/oauth/google/authorize", headers=auth_headers).status_code == 429
    finally:
        app.dependency_overrides.pop(get_google_oauth_service, None)
