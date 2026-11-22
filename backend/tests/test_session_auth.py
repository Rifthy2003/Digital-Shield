from datetime import datetime, timedelta
import jwt
import pytest
from app.config import get_settings
from app.core.security import decode_access_token, hash_token, generate_refresh_token, hash_password
from app.models.user import User, UserSession, RefreshToken

settings = get_settings()


def test_successful_login_creates_session_and_binds_tokens(client, registered_user, db_session):
    # 1. Login
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36",
            "X-Client-Type": "web",
            "X-Device-Name": "Workstation Laptop",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    access_token = data["access_token"]
    refresh_token = data["refresh_token"]

    # 2. Check Access Token contains correct sid
    payload = decode_access_token(access_token)
    assert "sid" in payload
    session_id = payload["sid"]
    assert payload["sub"] is not None

    # 3. Check exactly one UserSession created
    user = db_session.query(User).filter(User.email == registered_user["email"]).first()
    assert len(user.sessions) == 1
    session = user.sessions[0]
    assert session.id == session_id
    assert session.device_name == "Workstation Laptop"
    assert session.client_type == "web"
    assert "Chrome" in session.user_agent
    assert session.is_active is True

    # 4. Check Refresh Token in DB is bound to the same session
    token_hash = hash_token(refresh_token)
    stored_token = db_session.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()
    assert stored_token is not None
    assert stored_token.session_id == session.id
    assert stored_token.revoked is False


def test_two_separate_logins_create_independent_sessions(client, registered_user, db_session):
    # First login (Web)
    r1 = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
        headers={"User-Agent": "Chrome on Windows", "X-Client-Type": "web"},
    )
    assert r1.status_code == 200
    token1 = r1.json()["access_token"]
    sid1 = decode_access_token(token1)["sid"]

    # Second login (Mobile)
    r2 = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
        headers={"User-Agent": "InforaApp/1.0 (iPhone 15)", "X-Client-Type": "mobile", "X-Device-Name": "iPhone 15"},
    )
    assert r2.status_code == 200
    token2 = r2.json()["access_token"]
    sid2 = decode_access_token(token2)["sid"]

    assert sid1 != sid2

    user = db_session.query(User).filter(User.email == registered_user["email"]).first()
    assert len(user.sessions) == 2
    session_ids = {s.id for s in user.sessions}
    assert sid1 in session_ids
    assert sid2 in session_ids


def test_refresh_rotation_preserves_session_id(client, registered_user, db_session):
    # Login
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
    )
    login_data = login_resp.json()
    initial_access_token = login_data["access_token"]
    initial_refresh_token = login_data["refresh_token"]
    initial_sid = decode_access_token(initial_access_token)["sid"]

    # First Refresh
    refresh_resp = client.post("/api/v1/auth/refresh", json={"refresh_token": initial_refresh_token})
    assert refresh_resp.status_code == 200
    refresh_data = refresh_resp.json()
    new_access_token = refresh_data["access_token"]
    new_refresh_token = refresh_data["refresh_token"]

    # Sid must be identical in new access token
    new_sid = decode_access_token(new_access_token)["sid"]
    assert new_sid == initial_sid

    # New refresh token in DB must also be bound to the original session
    new_hash = hash_token(new_refresh_token)
    new_stored = db_session.query(RefreshToken).filter(RefreshToken.token_hash == new_hash).first()
    assert new_stored.session_id == initial_sid

    # Total sessions for user must still be 1 (rotation does not create duplicate sessions)
    user = db_session.query(User).filter(User.email == registered_user["email"]).first()
    assert len(user.sessions) == 1
    assert len(user.sessions[0].refresh_tokens) == 2  # 1 revoked, 1 active


def test_failed_login_does_not_create_session(client, registered_user, db_session):
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": "WrongPassword123!"},
    )
    assert resp.status_code == 401

    user = db_session.query(User).filter(User.email == registered_user["email"]).first()
    assert len(user.sessions) == 0


def test_inactive_and_locked_users_cannot_create_sessions(client, db_session):
    # 1. Inactive user
    inactive_user = User(
        email="inactive@example.com",
        password_hash=hash_password("Password12345!"),
        is_active=False,
    )
    db_session.add(inactive_user)

    # 2. Locked user
    locked_user = User(
        email="locked@example.com",
        password_hash=hash_password("Password12345!"),
        is_active=True,
        locked_until=datetime.utcnow() + timedelta(minutes=15),
    )
    db_session.add(locked_user)
    db_session.commit()

    resp_inactive = client.post("/api/v1/auth/login", json={"email": "inactive@example.com", "password": "Password12345!"})
    assert resp_inactive.status_code in (401, 403)

    resp_locked = client.post("/api/v1/auth/login", json={"email": "locked@example.com", "password": "Password12345!"})
    assert resp_locked.status_code == 423

    assert db_session.query(UserSession).filter(UserSession.user_id == inactive_user.id).count() == 0
    assert db_session.query(UserSession).filter(UserSession.user_id == locked_user.id).count() == 0


def test_legacy_refresh_token_compatibility_migrates_to_session(client, registered_user, db_session):
    # Simulate a legacy refresh token with session_id = NULL
    user = db_session.query(User).filter(User.email == registered_user["email"]).first()
    raw_legacy, legacy_hash, expires_at = generate_refresh_token()

    legacy_record = RefreshToken(
        session_id=None,
        user_id=user.id,
        token_hash=legacy_hash,
        expires_at=expires_at,
        revoked=False,
    )
    db_session.add(legacy_record)
    db_session.commit()

    # User currently has 0 sessions
    assert len(user.sessions) == 0

    # Client presents the legacy refresh token
    resp = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": raw_legacy},
        headers={"User-Agent": "Legacy Client Mozilla/5.0", "X-Device-Name": "Upgraded Device"},
    )
    assert resp.status_code == 200
    data = resp.json()
    new_access_token = data["access_token"]
    new_refresh_token = data["refresh_token"]

    # 1. Access token now carries a newly provisioned sid
    payload = decode_access_token(new_access_token)
    assert "sid" in payload
    new_sid = payload["sid"]

    # 2. Database now has a UserSession created for this client
    db_session.refresh(user)
    assert len(user.sessions) == 1
    session = user.sessions[0]
    assert session.id == new_sid
    assert session.device_name == "Upgraded Device"

    # 3. Both the rotated new refresh token and the old legacy record now link to this session
    db_session.refresh(legacy_record)
    assert legacy_record.session_id == session.id
    assert legacy_record.revoked is True

    new_hash = hash_token(new_refresh_token)
    new_stored = db_session.query(RefreshToken).filter(RefreshToken.token_hash == new_hash).first()
    assert new_stored.session_id == session.id


def test_revoked_or_invalid_refresh_token_rejected_before_session_creation(client, registered_user, db_session):
    # Invalid token
    resp = client.post("/api/v1/auth/refresh", json={"refresh_token": "non_existent_token"})
    assert resp.status_code == 401

    # Revoked token
    user = db_session.query(User).filter(User.email == registered_user["email"]).first()
    raw_token, token_hash, expires_at = generate_refresh_token()
    db_session.add(RefreshToken(
        session_id=None,
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires_at,
        revoked=True,
    ))
    db_session.commit()

    resp_revoked = client.post("/api/v1/auth/refresh", json={"refresh_token": raw_token})
    assert resp_revoked.status_code == 401

    # No sessions created on failure
    assert db_session.query(UserSession).filter(UserSession.user_id == user.id).count() == 0
