"""
Security tests for SEC-04: Prevent Login Timing-Based Account Enumeration.

Verifies:
1. Dummy password verification is executed when a user account does not exist.
2. Existing-user wrong-password verification executes real password verification using the stored hash.
3. Locked accounts execute password verification to equalize timing while failing authentication.
4. Disabled/inactive accounts execute password verification to equalize timing while failing authentication.
5. Legitimate active accounts with valid credentials log in successfully.
6. The mitigation uses a static pre-computed hash and does not generate hashes on the fly.
7. Failed login attempts do not create sessions in the database.
"""
from datetime import datetime, timedelta

from app.core.security import DUMMY_PASSWORD_HASH, dummy_verify_password, hash_password
from app.models.user import User, UserSession
import app.api.routes.auth as auth_route


def test_dummy_argon2_hash_parameters():
    """Verify pre-computed dummy hash has standard Argon2id cost parameters and fails verification."""
    assert DUMMY_PASSWORD_HASH.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    assert dummy_verify_password("wrong_password") is False


def test_nonexistent_user_triggers_dummy_verification(client, monkeypatch):
    """
    Core SEC-04 assertion:
    When a user does not exist, dummy_verify_password is executed with the submitted password,
    consuming constant CPU time and returning HTTP 401.
    """
    called_with = []

    def mock_dummy_verify(plain_password: str) -> bool:
        called_with.append(plain_password)
        return False

    monkeypatch.setattr(auth_route, "dummy_verify_password", mock_dummy_verify)

    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "ghost.user@example.com", "password": "SamplePassword123!"},
        headers={"X-Forwarded-For": "10.0.2.1"},
    )
    assert resp.status_code == 401
    assert resp.json() == {"detail": "Invalid email or password"}
    assert called_with == ["SamplePassword123!"]


def test_existing_user_wrong_password_uses_stored_hash(client, registered_user, db_session, monkeypatch):
    """
    When an existing user submits a wrong password, verify_password is executed
    against the actual stored password hash.
    """
    user = db_session.query(User).filter(User.email == registered_user["email"]).first()
    verification_calls = []

    real_verify = auth_route.verify_password

    def spy_verify(plain: str, hashed: str) -> bool:
        verification_calls.append((plain, hashed))
        return real_verify(plain, hashed)

    monkeypatch.setattr(auth_route, "verify_password", spy_verify)

    resp = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": "WrongPassword123!"},
        headers={"X-Forwarded-For": "10.0.2.2"},
    )
    assert resp.status_code == 401
    assert resp.json() == {"detail": "Invalid email or password"}
    assert len(verification_calls) == 1
    assert verification_calls[0][0] == "WrongPassword123!"
    assert verification_calls[0][1] == user.password_hash


def test_locked_user_performs_verification_and_denies_session(client, db_session, monkeypatch):
    """
    A locked account executes password verification to equalize timing,
    fails with HTTP 401, and creates zero sessions.
    """
    locked_user = User(
        email="locked.timing@example.com",
        password_hash=hash_password("RealPassword123!"),
        is_active=True,
        locked_until=datetime.utcnow() + timedelta(minutes=15),
    )
    db_session.add(locked_user)
    db_session.commit()

    called = []
    real_verify = auth_route.verify_password

    def spy_verify(plain: str, hashed: str) -> bool:
        called.append((plain, hashed))
        return real_verify(plain, hashed)

    monkeypatch.setattr(auth_route, "verify_password", spy_verify)

    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "locked.timing@example.com", "password": "RealPassword123!"},
        headers={"X-Forwarded-For": "10.0.2.3"},
    )
    assert resp.status_code == 401
    assert resp.json() == {"detail": "Invalid email or password"}
    assert len(called) == 1
    assert called[0][1] == locked_user.password_hash

    # Confirm zero sessions created
    sessions = db_session.query(UserSession).filter(UserSession.user_id == locked_user.id).all()
    assert len(sessions) == 0


def test_inactive_user_performs_verification_and_denies_session(client, db_session, monkeypatch):
    """
    A disabled account executes password verification to equalize timing,
    fails with HTTP 401, and creates zero sessions.
    """
    inactive_user = User(
        email="inactive.timing@example.com",
        password_hash=hash_password("RealPassword123!"),
        is_active=False,
    )
    db_session.add(inactive_user)
    db_session.commit()

    called = []
    real_verify = auth_route.verify_password

    def spy_verify(plain: str, hashed: str) -> bool:
        called.append((plain, hashed))
        return real_verify(plain, hashed)

    monkeypatch.setattr(auth_route, "verify_password", spy_verify)

    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "inactive.timing@example.com", "password": "RealPassword123!"},
        headers={"X-Forwarded-For": "10.0.2.4"},
    )
    assert resp.status_code == 401
    assert resp.json() == {"detail": "Invalid email or password"}
    assert len(called) == 1
    assert called[0][1] == inactive_user.password_hash

    sessions = db_session.query(UserSession).filter(UserSession.user_id == inactive_user.id).all()
    assert len(sessions) == 0


def test_no_hash_generation_during_login(client, monkeypatch):
    """
    Ensure hash_password is NOT called during login for non-existent or failed users.
    Only verification against the pre-computed hash should occur.
    """
    hash_calls = []

    def mock_hash(pwd: str) -> str:
        hash_calls.append(pwd)
        return "fake_hash"

    monkeypatch.setattr(auth_route, "hash_password", mock_hash)

    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "no.hash.test@example.com", "password": "AnyPassword123!"},
        headers={"X-Forwarded-For": "10.0.2.5"},
    )
    assert resp.status_code == 401
    # hash_password must NEVER be called during login
    assert len(hash_calls) == 0


def test_valid_user_can_still_login_successfully(client, registered_user):
    """Ensure normal valid logins remain unaffected and succeed with HTTP 200."""
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "access_token" in body
    assert "refresh_token" in body
