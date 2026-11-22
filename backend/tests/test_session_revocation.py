from datetime import datetime, timedelta
import pytest
import jwt
from app.config import get_settings
from app.core.security import create_access_token, decode_access_token, generate_refresh_token, hash_token, hash_password
from app.models.user import User, UserSession, RefreshToken, UserRole

settings = get_settings()


def test_valid_session_token_can_access_protected_endpoint(client, registered_user):
    # 1. Login to get session-bound token
    resp = client.post("/api/v1/auth/login", json={"email": registered_user["email"], "password": registered_user["password"]})
    assert resp.status_code == 200
    token = resp.json()["access_token"]

    # 2. Access /me
    me_resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == registered_user["email"]


def test_token_missing_sid_is_rejected(client, registered_user):
    user = registered_user
    # Create legacy token without sid
    legacy_token = create_access_token(subject="fake-user-id", role="citizen", session_id=None)
    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {legacy_token}"})
    assert resp.status_code == 401


def test_token_with_nonexistent_session_is_rejected(client, registered_user):
    # Token with non-existent session UUID
    token = create_access_token(subject="some-user-id", role="citizen", session_id="00000000-0000-0000-0000-000000000000")
    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


def test_token_with_session_of_another_user_is_rejected(client, registered_user, db_session):
    # Create user B and session for user B
    user_b = User(
        email="user_b@example.com",
        password_hash=hash_password("Password123!"),
    )
    db_session.add(user_b)
    db_session.commit()

    now = datetime.utcnow()
    session_b = UserSession(
        user_id=user_b.id,
        device_name="User B Device",
        expires_at=now + timedelta(days=7),
    )
    db_session.add(session_b)
    db_session.commit()

    # User A crafts token with sub=user_a but sid=session_b.id
    user_a = db_session.query(User).filter(User.email == registered_user["email"]).first()
    mismatched_token = create_access_token(subject=user_a.id, role="citizen", session_id=session_b.id)

    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {mismatched_token}"})
    assert resp.status_code == 401


def test_token_with_inactive_session_is_rejected(client, registered_user, db_session):
    # Login
    resp = client.post("/api/v1/auth/login", json={"email": registered_user["email"], "password": registered_user["password"]})
    token = resp.json()["access_token"]
    sid = decode_access_token(token)["sid"]

    # Deactivate session in DB
    session = db_session.get(UserSession, sid)
    session.is_active = False
    db_session.commit()

    # Access /me must now fail
    me_resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 401


def test_token_with_expired_session_is_rejected(client, registered_user, db_session):
    # Login
    resp = client.post("/api/v1/auth/login", json={"email": registered_user["email"], "password": registered_user["password"]})
    token = resp.json()["access_token"]
    sid = decode_access_token(token)["sid"]

    # Expire session in DB
    session = db_session.get(UserSession, sid)
    session.expires_at = datetime.utcnow() - timedelta(minutes=1)
    db_session.commit()

    me_resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 401


def test_token_with_inactive_user_is_rejected(client, registered_user, db_session):
    # Login
    resp = client.post("/api/v1/auth/login", json={"email": registered_user["email"], "password": registered_user["password"]})
    token = resp.json()["access_token"]

    # Disable user account
    user = db_session.query(User).filter(User.email == registered_user["email"]).first()
    user.is_active = False
    db_session.commit()

    me_resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 401


def test_access_token_is_immediately_invalid_after_logout(client, registered_user):
    # 1. Login
    login_resp = client.post("/api/v1/auth/login", json={"email": registered_user["email"], "password": registered_user["password"]})
    assert login_resp.status_code == 200
    tokens = login_resp.json()
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]
    headers = {"Authorization": f"Bearer {access_token}"}

    # 2. Pre-logout verify access works
    pre_resp = client.get("/api/v1/auth/me", headers=headers)
    assert pre_resp.status_code == 200

    # 3. Call Logout
    logout_resp = client.post("/api/v1/auth/logout", json={"refresh_token": refresh_token}, headers=headers)
    assert logout_resp.status_code == 204

    # 4. Immediate invalidation: calling /me with the SAME access token must return 401!
    post_resp = client.get("/api/v1/auth/me", headers=headers)
    assert post_resp.status_code == 401

    # 5. Refresh token must also fail
    ref_resp = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert ref_resp.status_code == 401


def test_logout_of_device_a_does_not_invalidate_device_b(client, registered_user):
    # Login on Device A
    login_a = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
        headers={"User-Agent": "Device A Chrome", "X-Device-Name": "Device A"},
    )
    tokens_a = login_a.json()
    headers_a = {"Authorization": f"Bearer {tokens_a['access_token']}"}

    # Login on Device B
    login_b = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
        headers={"User-Agent": "Device B Safari", "X-Device-Name": "Device B"},
    )
    tokens_b = login_b.json()
    headers_b = {"Authorization": f"Bearer {tokens_b['access_token']}"}

    # Both devices can access /me
    assert client.get("/api/v1/auth/me", headers=headers_a).status_code == 200
    assert client.get("/api/v1/auth/me", headers=headers_b).status_code == 200

    # Device A logs out
    logout_a = client.post("/api/v1/auth/logout", json={"refresh_token": tokens_a["refresh_token"]}, headers=headers_a)
    assert logout_a.status_code == 204

    # Device A is now locked out
    assert client.get("/api/v1/auth/me", headers=headers_a).status_code == 401

    # Device B is STILL authenticated and operational!
    assert client.get("/api/v1/auth/me", headers=headers_b).status_code == 200

    # Device B can still refresh
    ref_b = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens_b["refresh_token"]})
    assert ref_b.status_code == 200


def test_revoked_session_cannot_refresh(client, registered_user, db_session):
    login = client.post("/api/v1/auth/login", json={"email": registered_user["email"], "password": registered_user["password"]})
    tokens = login.json()
    sid = decode_access_token(tokens["access_token"])["sid"]

    # Deactivate session directly
    session = db_session.get(UserSession, sid)
    session.is_active = False
    db_session.commit()

    # Attempt to refresh
    ref = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert ref.status_code == 401


def test_refresh_token_associated_with_wrong_user_or_session_rejected(client, registered_user, db_session):
    # User B
    user_b = User(email="victim@example.com", password_hash=hash_password("Pass123!"))
    db_session.add(user_b)
    db_session.commit()

    now = datetime.utcnow()
    session_b = UserSession(user_id=user_b.id, device_name="Device B", expires_at=now + timedelta(days=7))
    db_session.add(session_b)
    db_session.commit()

    # Refresh token belongs to user A, but points to session_b of user B
    user_a = db_session.query(User).filter(User.email == registered_user["email"]).first()
    raw_token, token_hash, expires_at = generate_refresh_token()
    mismatched_token = RefreshToken(
        session_id=session_b.id,
        user_id=user_a.id,
        token_hash=token_hash,
        expires_at=expires_at,
        revoked=False,
    )
    db_session.add(mismatched_token)
    db_session.commit()

    ref = client.post("/api/v1/auth/refresh", json={"refresh_token": raw_token})
    assert ref.status_code == 401


def test_logout_behavior_is_repeatable(client, registered_user):
    login = client.post("/api/v1/auth/login", json={"email": registered_user["email"], "password": registered_user["password"]})
    tokens = login.json()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    # First logout succeeds
    r1 = client.post("/api/v1/auth/logout", json={"refresh_token": tokens["refresh_token"]}, headers=headers)
    assert r1.status_code == 204

    # Subsequent request using the invalidated access token fails with 401
    r2 = client.post("/api/v1/auth/logout", json={"refresh_token": tokens["refresh_token"]}, headers=headers)
    assert r2.status_code == 401


def test_admin_rbac_still_works_with_session_validation(client, db_session):
    admin_user = User(
        email="admin_session@example.com",
        password_hash=hash_password("AdminPass123!"),
        role=UserRole.ADMIN,
    )
    db_session.add(admin_user)
    db_session.commit()

    login = client.post("/api/v1/auth/login", json={"email": "admin_session@example.com", "password": "AdminPass123!"})
    assert login.status_code == 200
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Admin route succeeds
    admin_resp = client.get("/api/v1/admin/stats", headers=headers)
    assert admin_resp.status_code == 200
    assert "total_users" in admin_resp.json()
