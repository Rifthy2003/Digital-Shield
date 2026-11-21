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
    # 6th attempt should now be locked even with the CORRECT password
    resp = client.post("/api/v1/auth/login", json={"email": registered_user["email"], "password": registered_user["password"]})
    assert resp.status_code == 423


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
