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


def test_challenge_cannot_be_used_as_access_token_or_across_users(client, db_session, mfa_encryption_key):
    access_a, _ = _register_and_login(client, email="alice@example.com")
    start_a = client.post("/api/v1/auth/mfa/enroll/start", headers=_auth_headers(access_a)).json()
    totp_a = pyotp.TOTP(start_a["secret"])
    client.post("/api/v1/auth/mfa/enroll/verify", json={"code": totp_a.now()}, headers=_auth_headers(access_a))

    access_b, _ = _register_and_login(client, email="bob@example.com")
    start_b = client.post("/api/v1/auth/mfa/enroll/start", headers=_auth_headers(access_b)).json()
    totp_b = pyotp.TOTP(start_b["secret"])
    client.post("/api/v1/auth/mfa/enroll/verify", json={"code": totp_b.now()}, headers=_auth_headers(access_b))

    alice = db_session.query(User).filter(User.email == "alice@example.com").first()
    sessions_before = db_session.query(UserSession).filter(UserSession.user_id == alice.id).count()

    # Alice logs in -> gets challenge; no new UserSession created yet
    ch_a = client.post(
        "/api/v1/auth/login",
        json={"email": "alice@example.com", "password": "StrongPassword123!"},
    ).json()["mfa_challenge_token"]
    sessions_pending = db_session.query(UserSession).filter(UserSession.user_id == alice.id).count()
    assert sessions_pending == sessions_before

    # Challenge token is purpose-bound and cannot be used as Bearer JWT
    assert client.get("/api/v1/auth/me", headers=_auth_headers(ch_a)).status_code == 401
    assert client.get("/api/v1/dashboard", headers=_auth_headers(ch_a)).status_code == 401

    # Bob's TOTP code cannot satisfy Alice's challenge
    cross_user = client.post(
        "/api/v1/auth/mfa/login-verify",
        json={"challenge_token": ch_a, "code": totp_b.at(datetime.utcnow() + timedelta(seconds=30))},
    )
    assert cross_user.status_code == 401


def test_atomic_totp_replay_and_recovery_code_concurrency(client, db_session, mfa_encryption_key):
    from concurrent.futures import ThreadPoolExecutor
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.services.mfa import claim_totp_step, consume_recovery_code

    access, _ = _register_and_login(client, email="concurrent@example.com")
    start = client.post("/api/v1/auth/mfa/enroll/start", headers=_auth_headers(access)).json()
    totp = pyotp.TOTP(start["secret"])
    enroll_body = client.post(
        "/api/v1/auth/mfa/enroll/verify",
        json={"code": totp.now()},
        headers=_auth_headers(access),
    ).json()

    user = db_session.query(User).filter(User.email == "concurrent@example.com").first()
    target_step = (user.mfa_last_totp_step or 0) + 1
    rc_to_race = enroll_body["recovery_codes"][0]

    # Issue two separate login challenges and race the same TOTP step across two independent sessions
    c1 = client.post(
        "/api/v1/auth/login",
        json={"email": "concurrent@example.com", "password": "StrongPassword123!"},
    ).json()["mfa_challenge_token"]
    c2 = client.post(
        "/api/v1/auth/login",
        json={"email": "concurrent@example.com", "password": "StrongPassword123!"},
    ).json()["mfa_challenge_token"]

    next_code = totp.at(datetime.utcnow() + timedelta(seconds=30))
    r1 = client.post("/api/v1/auth/mfa/login-verify", json={"challenge_token": c1, "code": next_code})
    r2 = client.post("/api/v1/auth/mfa/login-verify", json={"challenge_token": c2, "code": next_code})
    assert sorted([r1.status_code, r2.status_code]) == [200, 401]

    # Direct DB-level concurrent claim_totp_step & consume_recovery_code against SQLite file DB
    engine = db_session.get_bind()
    SessionFactory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    race_step = target_step + 5

    def _race_claim(_):
        s = SessionFactory()
        try:
            won = claim_totp_step(s, user.id, race_step)
            s.commit()
            return won
        except Exception:
            s.rollback()
            return False
        finally:
            s.close()

    with ThreadPoolExecutor(max_workers=4) as pool:
        claim_results = list(pool.map(_race_claim, range(4)))
    assert claim_results.count(True) == 1

    def _race_recovery(_):
        s = SessionFactory()
        try:
            won = consume_recovery_code(s, user.id, rc_to_race)
            s.commit()
            return won
        except Exception:
            s.rollback()
            return False
        finally:
            s.close()

    with ThreadPoolExecutor(max_workers=4) as pool:
        rc_results = list(pool.map(_race_recovery, range(4)))
    assert rc_results.count(True) == 1


def test_pending_enrollment_expiration_cancel_and_isolation(client, db_session, mfa_encryption_key):
    access_a, _ = _register_and_login(client, email="pending_a@example.com")
    access_b, _ = _register_and_login(client, email="pending_b@example.com")

    start_a = client.post("/api/v1/auth/mfa/enroll/start", headers=_auth_headers(access_a)).json()
    totp_a = pyotp.TOTP(start_a["secret"])

    # User B cannot verify User A's pending secret
    b_verify = client.post(
        "/api/v1/auth/mfa/enroll/verify",
        json={"code": totp_a.now()},
        headers=_auth_headers(access_b),
    )
    assert b_verify.status_code == 400

    # Cancel clears pending enrollment
    assert client.post("/api/v1/auth/mfa/enroll/cancel", headers=_auth_headers(access_a)).status_code == 204
    user_a = db_session.query(User).filter(User.email == "pending_a@example.com").first()
    assert user_a.mfa_pending_secret_encrypted is None
    assert user_a.mfa_pending_expires_at is None

    # Expired pending enrollment is rejected and cleared
    start_a2 = client.post("/api/v1/auth/mfa/enroll/start", headers=_auth_headers(access_a)).json()
    db_session.refresh(user_a)
    user_a.mfa_pending_expires_at = datetime.utcnow() - timedelta(minutes=1)
    db_session.commit()

    expired_verify = client.post(
        "/api/v1/auth/mfa/enroll/verify",
        json={"code": pyotp.TOTP(start_a2["secret"]).now()},
        headers=_auth_headers(access_a),
    )
    assert expired_verify.status_code == 400
    db_session.refresh(user_a)
    assert user_a.mfa_pending_secret_encrypted is None
    assert user_a.mfa_enabled is False


def test_disable_revokes_other_refresh_tokens_and_audit_logs_never_leak_secrets(client, db_session, mfa_encryption_key):
    access1, refresh1 = _register_and_login(client, email="audit@example.com")
    login2 = client.post(
        "/api/v1/auth/login",
        json={"email": "audit@example.com", "password": "StrongPassword123!"},
    ).json()
    refresh2 = login2["refresh_token"]

    start = client.post("/api/v1/auth/mfa/enroll/start", headers=_auth_headers(access1)).json()
    totp = pyotp.TOTP(start["secret"])
    enroll_code = totp.now()
    enroll_body = client.post(
        "/api/v1/auth/mfa/enroll/verify",
        json={"code": enroll_code},
        headers=_auth_headers(access1),
    ).json()
    rc = enroll_body["recovery_codes"][0]

    # Disable using recovery code
    disable_res = client.post(
        "/api/v1/auth/mfa/disable",
        json={"current_password": "StrongPassword123!", "code": rc},
        headers=_auth_headers(access1),
    )
    assert disable_res.status_code == 200

    # Revoked session's refresh token cannot be used
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": refresh2}).status_code == 401
    # Current session's refresh token remains valid
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": refresh1}).status_code == 200

    # Audit logs must never contain plaintext secret, TOTP code, or recovery codes
    logs = db_session.query(AuditLog).all()
    serialized = str([(l.action, l.details) for l in logs])
    assert start["secret"] not in serialized
    assert enroll_code not in serialized
    for code in enroll_body["recovery_codes"]:
        assert code not in serialized

