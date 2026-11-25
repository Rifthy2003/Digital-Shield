"""
Security tests for SEC-05: Refresh Token Replay Detection & Session Invalidation.

Verifies:
1. Valid refresh token — rotation succeeds and issues new access/refresh tokens.
2. Rotated refresh token — cannot be reused to obtain new tokens.
3. Revoked refresh token (e.g. after logout) — cannot be reused.
4. Replay of a previously consumed token — immediately invalidates the associated session and all tokens in its family.
5. Session invalidation — existing access tokens for the affected session become unusable (HTTP 401).
6. Expired refresh token — fails without extending or resurrecting the session.
7. Invalid/random refresh token — fails safely without modifying any database state.
8. Unrelated sessions — remain active and unaffected when another session suffers replay invalidation.
9. Refresh token hashes — no plaintext refresh tokens stored in the database.
"""
from datetime import datetime, timedelta
import secrets

from app.core.security import decode_access_token, generate_refresh_token, hash_token
from app.models.audit_log import AuditLog
from app.models.user import RefreshToken, User, UserSession


def test_valid_refresh_token_succeeds(client, registered_user, db_session):
    """A valid, active refresh token rotates successfully and issues new tokens."""
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
    )
    assert login_resp.status_code == 200
    tokens = login_resp.json()
    old_rt = tokens["refresh_token"]

    refresh_resp = client.post("/api/v1/auth/refresh", json={"refresh_token": old_rt})
    assert refresh_resp.status_code == 200
    new_tokens = refresh_resp.json()
    assert "access_token" in new_tokens
    assert "refresh_token" in new_tokens
    assert new_tokens["refresh_token"] != old_rt

    # Stored old token must now be marked revoked
    old_record = db_session.query(RefreshToken).filter(RefreshToken.token_hash == hash_token(old_rt)).first()
    assert old_record.revoked is True


def test_rotated_refresh_token_cannot_be_reused(client, registered_user):
    """An already rotated refresh token cannot be used to obtain new tokens."""
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
    )
    tokens = login_resp.json()
    rt_1 = tokens["refresh_token"]

    # First refresh succeeds
    r1 = client.post("/api/v1/auth/refresh", json={"refresh_token": rt_1})
    assert r1.status_code == 200

    # Second refresh with the consumed token fails
    r2 = client.post("/api/v1/auth/refresh", json={"refresh_token": rt_1})
    assert r2.status_code == 401
    assert r2.json()["detail"] == "Invalid or expired refresh token"


def test_revoked_refresh_token_cannot_be_reused(client, registered_user):
    """A refresh token revoked via logout cannot be used to obtain new tokens."""
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
    )
    tokens = login_resp.json()
    rt = tokens["refresh_token"]
    at = tokens["access_token"]

    logout_resp = client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": rt},
        headers={"Authorization": f"Bearer {at}"},
    )
    assert logout_resp.status_code == 204

    # Attempt to refresh with revoked token
    ref_resp = client.post("/api/v1/auth/refresh", json={"refresh_token": rt})
    assert ref_resp.status_code == 401


def test_replay_of_consumed_token_invalidates_session(client, registered_user, db_session):
    """
    Core SEC-05 Requirement:
    When a previously consumed refresh token is replayed, the authorization server
    detects token reuse, deactivates the associated UserSession, revokes all tokens
    in that session family, and records an audit event.
    """
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
    )
    tokens = login_resp.json()
    rt_1 = tokens["refresh_token"]

    # 1. Legitimate client rotates rt_1 -> receives rt_2
    r1 = client.post("/api/v1/auth/refresh", json={"refresh_token": rt_1})
    assert r1.status_code == 200
    rt_2 = r1.json()["refresh_token"]

    # Verify session is initially active
    sid = decode_access_token(tokens["access_token"])["sid"]
    session = db_session.get(UserSession, sid)
    assert session.is_active is True

    # 2. Attacker replays consumed token rt_1
    replay_resp = client.post("/api/v1/auth/refresh", json={"refresh_token": rt_1})
    assert replay_resp.status_code == 401

    # 3. Session must now be deactivated in the database
    db_session.expire_all()
    session = db_session.get(UserSession, sid)
    assert session.is_active is False

    # 4. The subsequent token rt_2 must also be revoked
    rt2_record = db_session.query(RefreshToken).filter(RefreshToken.token_hash == hash_token(rt_2)).first()
    assert rt2_record.revoked is True

    # 5. Security audit log must record the replay event
    audit_event = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "security.refresh_token_replayed", AuditLog.resource == sid)
        .first()
    )
    assert audit_event is not None
    assert audit_event.details.get("session_id") == sid


def test_session_invalidation_makes_access_token_unusable(client, registered_user):
    """
    When replay detection invalidates a session, all access tokens associated with that
    session are immediately rejected on protected routes (via get_current_user).
    """
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
    )
    tokens = login_resp.json()
    rt_1 = tokens["refresh_token"]

    # Legitimate client rotates rt_1 -> receives at_2, rt_2
    r1 = client.post("/api/v1/auth/refresh", json={"refresh_token": rt_1})
    assert r1.status_code == 200
    at_2 = r1.json()["access_token"]
    headers_2 = {"Authorization": f"Bearer {at_2}"}

    # Verify at_2 currently works
    pre_check = client.get("/api/v1/auth/me", headers=headers_2)
    assert pre_check.status_code == 200

    # Attacker replays consumed token rt_1
    replay_resp = client.post("/api/v1/auth/refresh", json={"refresh_token": rt_1})
    assert replay_resp.status_code == 401

    # Access token at_2 must now be IMMEDIATELY REJECTED on protected routes
    post_check = client.get("/api/v1/auth/me", headers=headers_2)
    assert post_check.status_code == 401
    assert post_check.json()["detail"] == "Could not validate credentials"


def test_expired_refresh_token_fails_without_resurrecting_session(client, registered_user, db_session):
    """An expired refresh token fails safely and cannot be refreshed or used to resurrect a session."""
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
    )
    tokens = login_resp.json()
    rt = tokens["refresh_token"]

    # Manually expire the token in DB
    record = db_session.query(RefreshToken).filter(RefreshToken.token_hash == hash_token(rt)).first()
    record.expires_at = datetime.utcnow() - timedelta(minutes=10)
    db_session.commit()

    ref_resp = client.post("/api/v1/auth/refresh", json={"refresh_token": rt})
    assert ref_resp.status_code == 401
    assert ref_resp.json()["detail"] == "Invalid or expired refresh token"


def test_invalid_random_refresh_token_fails_safely(client, db_session):
    """An arbitrary or random refresh token not in the database fails safely without error."""
    pre_sessions = db_session.query(UserSession).count()
    pre_tokens = db_session.query(RefreshToken).count()

    random_rt = secrets.token_urlsafe(64)
    resp = client.post("/api/v1/auth/refresh", json={"refresh_token": random_rt})
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid or expired refresh token"

    # Confirm no state was created or altered
    assert db_session.query(UserSession).count() == pre_sessions
    assert db_session.query(RefreshToken).count() == pre_tokens


def test_unrelated_sessions_remain_active_when_one_session_replayed(client, registered_user, db_session):
    """
    Replay invalidation of Session A does NOT invalidate independent Session B
    on a different device belonging to the same user.
    """
    # 1. Login on Device A
    login_a = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
        headers={"User-Agent": "Device A Browser", "X-Device-Name": "Device A"},
    )
    tokens_a = login_a.json()
    rt_a1 = tokens_a["refresh_token"]
    sid_a = decode_access_token(tokens_a["access_token"])["sid"]

    # 2. Login on Device B
    login_b = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
        headers={"User-Agent": "Device B Mobile", "X-Device-Name": "Device B"},
    )
    tokens_b = login_b.json()
    at_b = tokens_b["access_token"]
    rt_b1 = tokens_b["refresh_token"]
    sid_b = decode_access_token(tokens_b["access_token"])["sid"]

    # Both sessions are active
    assert sid_a != sid_b
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {at_b}"}).status_code == 200

    # 3. Device A rotates rt_a1 -> rt_a2
    r_a1 = client.post("/api/v1/auth/refresh", json={"refresh_token": rt_a1})
    assert r_a1.status_code == 200

    # 4. Attacker replays consumed token rt_a1
    replay_a = client.post("/api/v1/auth/refresh", json={"refresh_token": rt_a1})
    assert replay_a.status_code == 401

    # 5. Device A session is now deactivated
    db_session.expire_all()
    session_a = db_session.get(UserSession, sid_a)
    assert session_a.is_active is False

    # 6. Device B session MUST REMAIN ACTIVE AND UNTOUCHED
    session_b = db_session.get(UserSession, sid_b)
    assert session_b.is_active is True

    # Device B can still access protected routes
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {at_b}"}).status_code == 200

    # Device B can still successfully rotate its refresh token
    ref_b = client.post("/api/v1/auth/refresh", json={"refresh_token": rt_b1})
    assert ref_b.status_code == 200
    assert "access_token" in ref_b.json()


def test_refresh_token_hashes_no_plaintext_storage(client, registered_user, db_session):
    """Verify refresh tokens are stored exclusively as SHA-256 hashes, never plaintext."""
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
    )
    raw_rt = login_resp.json()["refresh_token"]

    user = db_session.query(User).filter(User.email == registered_user["email"]).first()
    records = db_session.query(RefreshToken).filter(RefreshToken.user_id == user.id).all()
    assert len(records) >= 1

    for rec in records:
        # Must be a 64-character SHA-256 hex digest
        assert len(rec.token_hash) == 64
        # Plaintext raw token string must never appear in the database record
        assert raw_rt != rec.token_hash
        assert raw_rt not in rec.token_hash
