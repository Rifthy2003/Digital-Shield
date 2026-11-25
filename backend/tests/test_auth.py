def test_register_success(client):
    resp = client.post("/api/v1/auth/register", json={
        "email": "newuser@example.com", "password": "StrongPass123word", "full_name": "New User",
    })
    assert resp.status_code == 201
    body = resp.json()
    assert body["email"] == "newuser@example.com"
    assert "password" not in body
    assert "password_hash" not in body


def test_register_weak_password_rejected(client):
    resp = client.post("/api/v1/auth/register", json={"email": "weak@example.com", "password": "short"})
    assert resp.status_code == 422


def test_register_oversized_password_rejected(client):
    # 129 characters exceeds the 128-character maximum length limit
    oversized = "StrongPass123" + "a" * 116
    assert len(oversized) == 129
    resp = client.post("/api/v1/auth/register", json={"email": "oversized@example.com", "password": oversized})
    assert resp.status_code == 422


def test_login_oversized_password_rejected(client):
    # 129 characters exceeds the 128-character maximum length limit
    oversized = "A" * 129
    resp = client.post("/api/v1/auth/login", json={"email": "anyone@example.com", "password": oversized})
    assert resp.status_code == 422


def test_register_and_login_max_length_password_succeeds(client):
    # Exactly 128 characters (maximum allowed boundary)
    max_len_password = "StrongPass123" + "a" * 115
    assert len(max_len_password) == 128
    payload = {"email": "boundary@example.com", "password": max_len_password, "full_name": "Boundary User"}
    resp = client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 201

    # Login with the exact same 128-character password succeeds and is not truncated
    login_resp = client.post("/api/v1/auth/login", json={"email": payload["email"], "password": max_len_password})
    assert login_resp.status_code == 200
    assert "access_token" in login_resp.json()


def test_register_duplicate_email_rejected(client, registered_user):
    resp = client.post("/api/v1/auth/register", json=registered_user)
    assert resp.status_code == 400


def test_login_success_returns_tokens(client, registered_user):
    resp = client.post("/api/v1/auth/login", json={"email": registered_user["email"], "password": registered_user["password"]})
    assert resp.status_code == 200
    body = resp.json()
    assert "access_token" in body and "refresh_token" in body


def test_login_wrong_password_rejected(client, registered_user):
    resp = client.post("/api/v1/auth/login", json={"email": registered_user["email"], "password": "WrongPassword123"})
    assert resp.status_code == 401


def test_login_lockout_after_repeated_failures(client, registered_user):
    for _ in range(5):
        resp = client.post("/api/v1/auth/login", json={"email": registered_user["email"], "password": "WrongPassword123"})
        assert resp.status_code == 401
    # 6th attempt from the same IP is rate-limited (HTTP 429), not globally locked (SEC-02)
    resp = client.post("/api/v1/auth/login", json={"email": registered_user["email"], "password": registered_user["password"]})
    assert resp.status_code == 429


def test_protected_route_requires_token(client):
    resp = client.get("/api/v1/auth/me")
    assert resp.status_code == 401


def test_protected_route_rejects_garbage_token(client):
    resp = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer not-a-real-token"})
    assert resp.status_code == 401


def test_me_returns_current_user(client, auth_headers, registered_user):
    resp = client.get("/api/v1/auth/me", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["email"] == registered_user["email"]


def test_refresh_token_rotation(client, registered_user):
    login = client.post("/api/v1/auth/login", json={"email": registered_user["email"], "password": registered_user["password"]})
    refresh_token = login.json()["refresh_token"]

    resp = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert resp.status_code == 200
    new_refresh = resp.json()["refresh_token"]
    assert new_refresh != refresh_token

    # Old refresh token must now be rejected (rotation / replay protection)
    replay = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert replay.status_code == 401


def test_logout_revokes_refresh_token(client, auth_headers, registered_user):
    login = client.post("/api/v1/auth/login", json={"email": registered_user["email"], "password": registered_user["password"]})
    refresh_token = login.json()["refresh_token"]

    resp = client.post("/api/v1/auth/logout", json={"refresh_token": refresh_token}, headers=auth_headers)
    assert resp.status_code == 204

    reuse = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert reuse.status_code == 401


def test_non_admin_cannot_reach_admin_routes(client, auth_headers):
    resp = client.get("/api/v1/admin/stats", headers=auth_headers)
    assert resp.status_code == 403
