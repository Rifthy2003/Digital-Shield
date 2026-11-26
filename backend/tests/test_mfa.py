"""
Tests for Infora Account TOTP MFA & Secure Enrollment (P1-B).
"""

from datetime import datetime, timedelta

import pyotp
import pytest
from cryptography.fernet import Fernet

from app.config import get_settings
from app.core.security import hash_token
from app.models.audit_log import AuditLog
from app.models.mfa import MfaChallenge, MfaRecoveryCode
from app.models.user import User, UserSession


@pytest.fixture
def mfa_encryption_key(monkeypatch):
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("TOKEN_ENCRYPTION_KEY", key)
    get_settings.cache_clear()
    yield key
    get_settings.cache_clear()


def _register_and_login(client, email="mfauser@example.com", password="StrongPassword123!"):
    reg = client.post("/api/v1/auth/register", json={"email": email, "password": password, "full_name": "MFA User"})
    assert reg.status_code == 201
    login = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200
    data = login.json()
    assert data["mfa_required"] is False
    return data["access_token"], data["refresh_token"]


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_totp_enrollment_start_returns_qr_uri_and_keeps_mfa_disabled(client, db_session, mfa_encryption_key):
    access, _ = _register_and_login(client)
    res = client.post("/api/v1/auth/mfa/enroll/start", headers=_auth_headers(access))
    assert res.status_code == 200
    body = res.json()
    assert body["provisioning_uri"].startswith("otpauth://totp/")
    assert "Infora%20Digital%20Shield" in body["provisioning_uri"] or "Infora+Digital+Shield" in body["provisioning_uri"]
    assert len(body["secret"]) >= 16

    user = db_session.query(User).filter(User.email == "mfauser@example.com").first()
    assert user is not None
    assert user.mfa_enabled is False
    assert user.mfa_secret_encrypted is None
    assert user.mfa_pending_secret_encrypted is not None
    # Secret stored encrypted, never plaintext
    assert body["secret"] not in user.mfa_pending_secret_encrypted

    # Security score must NOT award 30 MFA points during pending enrollment
    dash = client.get("/api/v1/dashboard", headers=_auth_headers(access))
    assert dash.status_code == 200
    assert dash.json()["score_breakdown"]["mfa"]["points"] == 0


def test_totp_enrollment_rejects_invalid_code_and_succeeds_with_valid_code(client, db_session, mfa_encryption_key):
    access, _ = _register_and_login(client)
    start = client.post("/api/v1/auth/mfa/enroll/start", headers=_auth_headers(access)).json()

    bad = client.post("/api/v1/auth/mfa/enroll/verify", json={"code": "000000"}, headers=_auth_headers(access))
    assert bad.status_code == 400
    user = db_session.query(User).filter(User.email == "mfauser@example.com").first()
    assert user.mfa_enabled is False

    valid_code = pyotp.TOTP(start["secret"]).now()
    ok = client.post("/api/v1/auth/mfa/enroll/verify", json={"code": valid_code}, headers=_auth_headers(access))
    assert ok.status_code == 200
    ok_body = ok.json()
    assert ok_body["mfa_enabled"] is True
    assert len(ok_body["recovery_codes"]) == 8

    db_session.refresh(user)
    assert user.mfa_enabled is True
    assert user.mfa_pending_secret_encrypted is None
    assert user.mfa_secret_encrypted is not None
    assert start["secret"] not in user.mfa_secret_encrypted

    # Recovery codes are stored only as hashes
    stored_codes = db_session.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == user.id).all()
    assert len(stored_codes) == 8
    for rc in stored_codes:
        assert rc.code_hash not in ok_body["recovery_codes"]
        assert len(rc.code_hash) == 64

    # Security score now awards 30/30 MFA points
    dash = client.get("/api/v1/dashboard", headers=_auth_headers(access))
    assert dash.status_code == 200
    assert dash.json()["score_breakdown"]["mfa"]["points"] == 30


def test_mfa_login_requires_challenge_and_prevents_totp_replay(client, db_session, mfa_encryption_key):
    access, _ = _register_and_login(client)
    start = client.post("/api/v1/auth/mfa/enroll/start", headers=_auth_headers(access)).json()
    totp = pyotp.TOTP(start["secret"])
    enroll_code = totp.now()
    assert client.post("/api/v1/auth/mfa/enroll/verify", json={"code": enroll_code}, headers=_auth_headers(access)).status_code == 200

    # Password login must return challenge, NOT access/refresh tokens
    login_res = client.post("/api/v1/auth/login", json={"email": "mfauser@example.com", "password": "StrongPassword123!"})
    assert login_res.status_code == 200
    login_data = login_res.json()
    assert login_data["mfa_required"] is True
    assert login_data["access_token"] is None
    assert login_data["refresh_token"] is None
    challenge_token = login_data["mfa_challenge_token"]
    assert challenge_token

    # Replaying the exact same TOTP code used at enrollment in the same 30s window must fail!
    replay_res = client.post(
        "/api/v1/auth/mfa/login-verify",
        json={"challenge_token": challenge_token, "code": enroll_code},
    )
    assert replay_res.status_code == 401

    # Next 30s step TOTP code succeeds and consumes the challenge
    next_code = totp.at(datetime.utcnow() + timedelta(seconds=30))
    verify_res = client.post(
        "/api/v1/auth/mfa/login-verify",
        json={"challenge_token": challenge_token, "code": next_code},
    )
    assert verify_res.status_code == 200
    tokens = verify_res.json()
    assert tokens["access_token"]
    assert tokens["refresh_token"]

    # Reusing the same challenge token fails
    reuse_challenge = client.post(
        "/api/v1/auth/mfa/login-verify",
        json={"challenge_token": challenge_token, "code": next_code},
    )
    assert reuse_challenge.status_code == 401


def test_expired_mfa_challenge_is_rejected(client, db_session, mfa_encryption_key):
    access, _ = _register_and_login(client)
    start = client.post("/api/v1/auth/mfa/enroll/start", headers=_auth_headers(access)).json()
    totp = pyotp.TOTP(start["secret"])
    client.post("/api/v1/auth/mfa/enroll/verify", json={"code": totp.now()}, headers=_auth_headers(access))

    login_data = client.post(
        "/api/v1/auth/login",
        json={"email": "mfauser@example.com", "password": "StrongPassword123!"},
    ).json()
    challenge_token = login_data["mfa_challenge_token"]

    # Expire the challenge in DB
    ch = db_session.query(MfaChallenge).filter(MfaChallenge.challenge_hash == hash_token(challenge_token)).first()
    ch.expires_at = datetime.utcnow() - timedelta(minutes=1)
    db_session.commit()

    next_code = totp.at(datetime.utcnow() + timedelta(seconds=30))
    res = client.post(
        "/api/v1/auth/mfa/login-verify",
        json={"challenge_token": challenge_token, "code": next_code},
    )
    assert res.status_code == 401


def test_recovery_code_login_single_use_and_regeneration(client, db_session, mfa_encryption_key):
    access, _ = _register_and_login(client)
    start = client.post("/api/v1/auth/mfa/enroll/start", headers=_auth_headers(access)).json()
    totp = pyotp.TOTP(start["secret"])
    enroll_res = client.post("/api/v1/auth/mfa/enroll/verify", json={"code": totp.now()}, headers=_auth_headers(access)).json()
    recovery_code = enroll_res["recovery_codes"][0]

    # Login with recovery code
    c1 = client.post("/api/v1/auth/login", json={"email": "mfauser@example.com", "password": "StrongPassword123!"}).json()["mfa_challenge_token"]
    ok = client.post("/api/v1/auth/mfa/login-verify", json={"challenge_token": c1, "code": recovery_code})
    assert ok.status_code == 200
    assert ok.json()["access_token"]

    # Same recovery code cannot be reused
    c2 = client.post("/api/v1/auth/login", json={"email": "mfauser@example.com", "password": "StrongPassword123!"}).json()["mfa_challenge_token"]
    reuse = client.post("/api/v1/auth/mfa/login-verify", json={"challenge_token": c2, "code": recovery_code})
    assert reuse.status_code == 401

    # Regenerate recovery codes with password + TOTP (use future step to avoid replay rejection)
    future_code = totp.at(datetime.utcnow() + timedelta(seconds=30))
    regen = client.post(
        "/api/v1/auth/mfa/recovery-codes/regenerate",
        json={"current_password": "StrongPassword123!", "code": future_code},
        headers=_auth_headers(access),
    )
    assert regen.status_code == 200
    new_codes = regen.json()["recovery_codes"]
    assert len(new_codes) == 8
    assert enroll_res["recovery_codes"][1] not in new_codes


def test_disable_mfa_revokes_other_sessions_and_updates_score(client, db_session, mfa_encryption_key):
    access1, _ = _register_and_login(client)
    # Create a second session before enabling MFA
    access2, _ = (
        client.post("/api/v1/auth/login", json={"email": "mfauser@example.com", "password": "StrongPassword123!"}).json()["access_token"],
        None,
    )
    start = client.post("/api/v1/auth/mfa/enroll/start", headers=_auth_headers(access1)).json()
    totp = pyotp.TOTP(start["secret"])
    client.post("/api/v1/auth/mfa/enroll/verify", json={"code": totp.now()}, headers=_auth_headers(access1))

    # Wrong password rejected
    bad_pw = client.post(
        "/api/v1/auth/mfa/disable",
        json={"current_password": "WrongPassword123!", "code": totp.at(datetime.utcnow() + timedelta(seconds=30))},
        headers=_auth_headers(access1),
    )
    assert bad_pw.status_code == 401

    # Valid password + TOTP disables MFA and revokes other session
    disable_res = client.post(
        "/api/v1/auth/mfa/disable",
        json={"current_password": "StrongPassword123!", "code": totp.at(datetime.utcnow() + timedelta(seconds=30))},
        headers=_auth_headers(access1),
    )
    assert disable_res.status_code == 200
    assert disable_res.json()["mfa_enabled"] is False
    assert disable_res.json()["revoked_sessions_count"] >= 1

    # Second session is now rejected
    me2 = client.get("/api/v1/auth/me", headers=_auth_headers(access2))
    assert me2.status_code == 401

    # Score drops back to 0 MFA points
    dash = client.get("/api/v1/dashboard", headers=_auth_headers(access1))
    assert dash.status_code == 200
    assert dash.json()["score_breakdown"]["mfa"]["points"] == 0

    # Audit log recorded lifecycle events
    actions = {row.action for row in db_session.query(AuditLog).all()}
    assert {"mfa.enrollment_started", "mfa.enabled", "mfa.disabled"}.issubset(actions)


def test_mfa_login_verify_is_rate_limited(client, mfa_encryption_key):
    access, _ = _register_and_login(client)
    start = client.post("/api/v1/auth/mfa/enroll/start", headers=_auth_headers(access)).json()
    totp = pyotp.TOTP(start["secret"])
    client.post("/api/v1/auth/mfa/enroll/verify", json={"code": totp.now()}, headers=_auth_headers(access))
    challenge = client.post(
        "/api/v1/auth/login",
        json={"email": "mfauser@example.com", "password": "StrongPassword123!"},
    ).json()["mfa_challenge_token"]

    statuses = []
    for _ in range(12):
        r = client.post("/api/v1/auth/mfa/login-verify", json={"challenge_token": challenge, "code": "000000"})
        statuses.append(r.status_code)
    assert 429 in statuses
