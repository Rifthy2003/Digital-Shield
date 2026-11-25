"""
Security tests for SEC-03: Prevent User Account Enumeration.

Verifies:
1. All login failure scenarios return the exact same HTTP status code (401 Unauthorized):
   - Non-existent user
   - Wrong password for existing user
   - Locked user account
   - Disabled/inactive user account
2. All login failure scenarios return the exact same response body:
   {"detail": "Invalid email or password"}
3. All login failure scenarios return consistent HTTP headers (WWW-Authenticate: Bearer).
4. Locked and disabled accounts still cannot authenticate or create sessions.
5. Legitimate active accounts with correct credentials continue to log in successfully.
"""
from datetime import datetime, timedelta

from app.core.security import hash_password
from app.models.user import User, UserSession


def test_login_failure_response_consistency(client, db_session, registered_user):
    """
    Core SEC-03 Assertion:
    Ensure that non-existent email, wrong password, locked account, and disabled account
    produce byte-for-byte indistinguishable status codes and response bodies.
    """
    # Create locked user
    locked_user = User(
        email="locked.user@example.com",
        password_hash=hash_password("ValidPassword123!"),
        is_active=True,
        locked_until=datetime.utcnow() + timedelta(minutes=15),
    )
    db_session.add(locked_user)

    # Create disabled/inactive user
    inactive_user = User(
        email="inactive.user@example.com",
        password_hash=hash_password("ValidPassword123!"),
        is_active=False,
    )
    db_session.add(inactive_user)
    db_session.commit()

    # 1. Non-existent account
    resp_nonexistent = client.post(
        "/api/v1/auth/login",
        json={"email": "nonexistent.account@example.com", "password": "AnyPassword123!"},
        headers={"X-Forwarded-For": "10.0.1.1"},
    )

    # 2. Existing account, wrong password
    resp_wrong_password = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": "WrongPassword123!"},
        headers={"X-Forwarded-For": "10.0.1.2"},
    )

    # 3. Locked account, valid password
    resp_locked = client.post(
        "/api/v1/auth/login",
        json={"email": "locked.user@example.com", "password": "ValidPassword123!"},
        headers={"X-Forwarded-For": "10.0.1.3"},
    )

    # 4. Inactive/disabled account, valid password
    resp_inactive = client.post(
        "/api/v1/auth/login",
        json={"email": "inactive.user@example.com", "password": "ValidPassword123!"},
        headers={"X-Forwarded-For": "10.0.1.4"},
    )

    responses = [resp_nonexistent, resp_wrong_password, resp_locked, resp_inactive]

    # All must return HTTP 401
    for r in responses:
        assert r.status_code == 401
        assert r.json() == {"detail": "Invalid email or password"}
        assert "bearer" in r.headers.get("www-authenticate", "").lower()

    # Assert response bodies are completely identical across all 4 scenarios
    bodies = [r.text for r in responses]
    assert len(set(bodies)) == 1, f"Response bodies differed across failure cases: {bodies}"


def test_locked_user_cannot_create_session(client, db_session):
    """Verify that a locked user cannot log in and no session is created in the database."""
    locked_user = User(
        email="locked.check@example.com",
        password_hash=hash_password("ValidPassword123!"),
        is_active=True,
        locked_until=datetime.utcnow() + timedelta(minutes=30),
    )
    db_session.add(locked_user)
    db_session.commit()

    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "locked.check@example.com", "password": "ValidPassword123!"},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid email or password"

    # Confirm zero sessions were created
    session_count = db_session.query(UserSession).filter(UserSession.user_id == locked_user.id).count()
    assert session_count == 0


def test_inactive_user_cannot_create_session(client, db_session):
    """Verify that a disabled user cannot log in and no session is created in the database."""
    inactive_user = User(
        email="inactive.check@example.com",
        password_hash=hash_password("ValidPassword123!"),
        is_active=False,
    )
    db_session.add(inactive_user)
    db_session.commit()

    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "inactive.check@example.com", "password": "ValidPassword123!"},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid email or password"

    # Confirm zero sessions were created
    session_count = db_session.query(UserSession).filter(UserSession.user_id == inactive_user.id).count()
    assert session_count == 0


def test_valid_user_can_still_login_successfully(client, registered_user):
    """Verify that legitimate active users with correct credentials log in with HTTP 200."""
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "access_token" in body
    assert "refresh_token" in body
    assert body["token_type"] == "bearer"
