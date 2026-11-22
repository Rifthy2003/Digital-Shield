from datetime import datetime, timedelta
import pytest
from app.core.security import decode_access_token, hash_token, generate_refresh_token, hash_password
from app.models.user import User, UserSession, RefreshToken


def test_list_active_sessions_and_identify_current(client, registered_user):
    # 1. Login on Device 1
    resp1 = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
        headers={"User-Agent": "Chrome on Windows", "X-Device-Name": "Desktop PC"},
    )
    tokens1 = resp1.json()
    token1 = tokens1["access_token"]
    sid1 = decode_access_token(token1)["sid"]

    # 2. Login on Device 2
    resp2 = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
        headers={"User-Agent": "Safari on iOS", "X-Device-Name": "iPhone 15"},
    )
    tokens2 = resp2.json()
    token2 = tokens2["access_token"]
    sid2 = decode_access_token(token2)["sid"]

    # 3. Call GET /sessions from Device 1
    list_resp = client.get("/api/v1/auth/sessions", headers={"Authorization": f"Bearer {token1}"})
    assert list_resp.status_code == 200
    sessions = list_resp.json()
    assert len(sessions) == 2

    # Map by id
    sess_map = {s["id"]: s for s in sessions}
    assert sid1 in sess_map
    assert sid2 in sess_map

    # From Device 1 perspective: sid1 is current, sid2 is NOT current
    assert sess_map[sid1]["is_current"] is True
    assert sess_map[sid1]["device_name"] == "Desktop PC"
    assert sess_map[sid2]["is_current"] is False
    assert sess_map[sid2]["device_name"] == "iPhone 15"

    # 4. Call GET /sessions from Device 2
    list_resp2 = client.get("/api/v1/auth/sessions", headers={"Authorization": f"Bearer {token2}"})
    assert list_resp2.status_code == 200
    sess_map2 = {s["id"]: s for s in list_resp2.json()}
    # From Device 2 perspective: sid2 is current, sid1 is NOT current
    assert sess_map2[sid2]["is_current"] is True
    assert sess_map2[sid1]["is_current"] is False


def test_user_session_isolation(client, registered_user, db_session):
    # Create User B
    user_b = User(
        email="user_b_isolation@example.com",
        password_hash=hash_password("Password123!"),
    )
    db_session.add(user_b)
    db_session.commit()

    # User B logs in
    login_b = client.post(
        "/api/v1/auth/login",
        json={"email": "user_b_isolation@example.com", "password": "Password123!"},
        headers={"X-Device-Name": "User B Device"},
    )
    token_b = login_b.json()["access_token"]

    # User A logs in
    login_a = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
        headers={"X-Device-Name": "User A Device"},
    )
    token_a = login_a.json()["access_token"]

    # User A gets sessions: must only see User A's session
    sessions_a = client.get("/api/v1/auth/sessions", headers={"Authorization": f"Bearer {token_a}"}).json()
    assert len(sessions_a) == 1
    assert sessions_a[0]["device_name"] == "User A Device"

    # User B gets sessions: must only see User B's session
    sessions_b = client.get("/api/v1/auth/sessions", headers={"Authorization": f"Bearer {token_b}"}).json()
    assert len(sessions_b) == 1
    assert sessions_b[0]["device_name"] == "User B Device"


def test_inactive_and_expired_sessions_excluded_from_listing(client, registered_user, db_session):
    # Login
    login = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
    )
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    user = db_session.query(User).filter(User.email == registered_user["email"]).first()

    # Create inactive session
    now = datetime.utcnow()
    s_inactive = UserSession(
        user_id=user.id,
        device_name="Old Inactive Device",
        is_active=False,
        expires_at=now + timedelta(days=7),
    )
    # Create expired session
    s_expired = UserSession(
        user_id=user.id,
        device_name="Expired Device",
        is_active=True,
        expires_at=now - timedelta(hours=1),
    )
    db_session.add_all([s_inactive, s_expired])
    db_session.commit()

    # Listing must only return the 1 active non-expired session
    sessions = client.get("/api/v1/auth/sessions", headers=headers).json()
    assert len(sessions) == 1
    returned_ids = [s["id"] for s in sessions]
    assert s_inactive.id not in returned_ids
    assert s_expired.id not in returned_ids


def test_revoke_specific_session_immediately_invalidates_token(client, registered_user, db_session):
    # Device 1
    d1 = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
        headers={"X-Device-Name": "Device 1"},
    ).json()
    token1 = d1["access_token"]
    refresh1 = d1["refresh_token"]
    h1 = {"Authorization": f"Bearer {token1}"}

    # Device 2
    d2 = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
        headers={"X-Device-Name": "Device 2"},
    ).json()
    token2 = d2["access_token"]
    refresh2 = d2["refresh_token"]
    sid2 = decode_access_token(token2)["sid"]
    h2 = {"Authorization": f"Bearer {token2}"}

    # Both working
    assert client.get("/api/v1/auth/me", headers=h1).status_code == 200
    assert client.get("/api/v1/auth/me", headers=h2).status_code == 200

    # Device 1 revokes Device 2's session
    del_resp = client.delete(f"/api/v1/auth/sessions/{sid2}", headers=h1)
    assert del_resp.status_code == 200
    assert del_resp.json()["revoked_session_id"] == sid2

    # Device 2 access token is IMMEDIATELY invalid (401)
    assert client.get("/api/v1/auth/me", headers=h2).status_code == 401

    # Device 2 refresh token is also revoked
    ref_resp = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh2})
    assert ref_resp.status_code == 401

    # Device 1 remains completely unaffected
    assert client.get("/api/v1/auth/me", headers=h1).status_code == 200


def test_revoke_nonexistent_session_returns_404(client, registered_user):
    login = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
    ).json()
    token = login["access_token"]
    h = {"Authorization": f"Bearer {token}"}

    resp = client.delete("/api/v1/auth/sessions/00000000-0000-0000-0000-000000000000", headers=h)
    assert resp.status_code == 404
    assert "Session not found" in resp.json()["detail"]


def test_cross_user_session_revocation_attempt_fails_with_404(client, registered_user, db_session):
    # User B
    user_b = User(
        email="victim_user@example.com",
        password_hash=hash_password("Password123!"),
    )
    db_session.add(user_b)
    db_session.commit()

    login_b = client.post(
        "/api/v1/auth/login",
        json={"email": "victim_user@example.com", "password": "Password123!"},
        headers={"X-Device-Name": "User B Phone"},
    ).json()
    sid_b = decode_access_token(login_b["access_token"])["sid"]

    # User A (attacker)
    login_a = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
    ).json()
    token_a = login_a["access_token"]
    h_a = {"Authorization": f"Bearer {token_a}"}

    # User A attempts to delete User B's session
    resp = client.delete(f"/api/v1/auth/sessions/{sid_b}", headers=h_a)
    assert resp.status_code == 404
    assert "Session not found" in resp.json()["detail"]

    # User B's session remains active and untouched
    session_b = db_session.get(UserSession, sid_b)
    assert session_b.is_active is True
    # User B can still access /me
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {login_b['access_token']}"}).status_code == 200


def test_logout_all_other_devices(client, registered_user):
    # Device A (Current)
    da = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
        headers={"X-Device-Name": "Current Laptop"},
    ).json()
    token_a = da["access_token"]
    ha = {"Authorization": f"Bearer {token_a}"}

    # Device B (Other 1)
    db_resp = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
        headers={"X-Device-Name": "Tablet"},
    ).json()
    token_b = db_resp["access_token"]
    hb = {"Authorization": f"Bearer {token_b}"}

    # Device C (Other 2)
    dc = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
        headers={"X-Device-Name": "Phone"},
    ).json()
    token_c = dc["access_token"]
    hc = {"Authorization": f"Bearer {token_c}"}

    # All 3 active
    assert client.get("/api/v1/auth/me", headers=ha).status_code == 200
    assert client.get("/api/v1/auth/me", headers=hb).status_code == 200
    assert client.get("/api/v1/auth/me", headers=hc).status_code == 200

    # Call /logout-all from Device A
    resp = client.post("/api/v1/auth/logout-all", headers=ha)
    assert resp.status_code == 200
    data = resp.json()
    assert data["revoked_sessions_count"] == 2

    # Device A (current) is PRESERVED and remains authenticated
    assert client.get("/api/v1/auth/me", headers=ha).status_code == 200

    # Device B and Device C are IMMEDIATELY INVALIDATED (401)
    assert client.get("/api/v1/auth/me", headers=hb).status_code == 401
    assert client.get("/api/v1/auth/me", headers=hc).status_code == 401

    # Device B and Device C refresh tokens are revoked
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": db_resp["refresh_token"]}).status_code == 401
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": dc["refresh_token"]}).status_code == 401

    # Active sessions list for Device A now has exactly 1 session
    sessions_a = client.get("/api/v1/auth/sessions", headers=ha).json()
    assert len(sessions_a) == 1
    assert sessions_a[0]["is_current"] is True
    assert sessions_a[0]["device_name"] == "Current Laptop"
