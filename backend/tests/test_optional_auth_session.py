"""
Security tests for SEC-01: Optional Authentication Session Revocation Bypass.

Verifies that both URL Checker and Message Checker:
1. Preserve anonymous scanning functionality when no Authorization header is provided.
2. Authenticate users properly when a valid Bearer token and active session are provided,
   associating scans and security alerts with the user.
3. Reject invalid credentials with HTTP 401 instead of silently degrading to anonymous requests:
   - Revoked / logged-out session tokens -> 401
   - Expired sessions -> 401
   - Invalid token type (e.g. type="refresh") -> 401
   - Inactive user accounts -> 401
   - Invalid / tampered JWTs -> 401
   - Malformed / non-Bearer Authorization headers -> 401
4. Prevent revoked sessions from creating authenticated scan records or user-associated alerts.
"""
from datetime import datetime, timedelta
import jwt

from app.config import get_settings
from app.core.security import create_access_token, decode_access_token, hash_password
from app.models.alert import Alert
from app.models.message_check import MessageCheck
from app.models.url_check import UrlCheck
from app.models.user import User, UserSession

settings = get_settings()


# ---------------------------------------------------------------------------
# URL Checker Tests
# ---------------------------------------------------------------------------

def test_url_checker_anonymous_request_succeeds_without_user(client, db_session):
    """Anonymous URL check without Authorization header succeeds; no user or alert created."""
    resp = client.post("/api/v1/url-checker/check", json={"url": "http://192.0.2.10/verify-login"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["risk_level"] in {"low", "medium", "high"}

    # Verify UrlCheck created with user_id = None
    records = db_session.query(UrlCheck).all()
    assert len(records) == 1
    assert records[0].user_id is None

    # Verify no alert was created
    alerts = db_session.query(Alert).all()
    assert len(alerts) == 0


def test_url_checker_authenticated_valid_session_succeeds(client, db_session, registered_user):
    """Authenticated URL check with active session succeeds and records user."""
    login_resp = client.post("/api/v1/auth/login", json={"email": registered_user["email"], "password": registered_user["password"]})
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]

    resp = client.post(
        "/api/v1/url-checker/check",
        json={"url": "http://192.0.2.10/verify-login"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["risk_level"] in {"low", "medium", "high"}

    # Verify UrlCheck is associated with user.id
    user = db_session.query(User).filter(User.email == registered_user["email"]).first()
    records = db_session.query(UrlCheck).filter(UrlCheck.user_id == user.id).all()
    assert len(records) == 1


def test_url_checker_authenticated_high_risk_triggers_alert(client, db_session, registered_user, monkeypatch):
    """When an authenticated user scans a high-risk URL, a security Alert is recorded."""
    from app.services.url_analysis import UrlAnalysisResult
    import app.api.routes.url_checker as url_checker_route

    monkeypatch.setattr(
        url_checker_route,
        "analyze_url",
        lambda url: UrlAnalysisResult(url=url, domain="malicious.example", risk_score=90, risk_level="high", indicators=[]),
    )

    login_resp = client.post("/api/v1/auth/login", json={"email": registered_user["email"], "password": registered_user["password"]})
    token = login_resp.json()["access_token"]

    resp = client.post(
        "/api/v1/url-checker/check",
        json={"url": "https://malicious.example/steal"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["risk_level"] == "high"

    user = db_session.query(User).filter(User.email == registered_user["email"]).first()
    alerts = db_session.query(Alert).filter(Alert.user_id == user.id).all()
    assert len(alerts) == 1
    assert alerts[0].category.value == "high_risk_url"


def test_url_checker_logged_out_revoked_session_returns_401(client, db_session, registered_user):
    """A revoked access token from a logged-out session MUST return 401 and create NO records."""
    login_resp = client.post("/api/v1/auth/login", json={"email": registered_user["email"], "password": registered_user["password"]})
    tokens = login_resp.json()
    token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # Logout to revoke session
    logout_resp = client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": refresh_token},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert logout_resp.status_code == 204

    # Record counts before scan attempt
    user = db_session.query(User).filter(User.email == registered_user["email"]).first()
    pre_scan_count = db_session.query(UrlCheck).count()
    pre_alert_count = db_session.query(Alert).count()

    # Attempt scan with revoked token -> MUST return 401
    resp = client.post(
        "/api/v1/url-checker/check",
        json={"url": "http://192.0.2.10/verify-login"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Could not validate credentials"

    # Verify no records or alerts were created
    assert db_session.query(UrlCheck).count() == pre_scan_count
    assert db_session.query(Alert).count() == pre_alert_count


def test_url_checker_expired_session_returns_401(client, db_session, registered_user):
    """A token whose associated session has expired MUST return 401."""
    login_resp = client.post("/api/v1/auth/login", json={"email": registered_user["email"], "password": registered_user["password"]})
    token = login_resp.json()["access_token"]
    sid = decode_access_token(token)["sid"]

    # Expire session in DB
    session = db_session.get(UserSession, sid)
    session.expires_at = datetime.utcnow() - timedelta(minutes=5)
    db_session.commit()

    resp = client.post(
        "/api/v1/url-checker/check",
        json={"url": "http://192.0.2.10/verify-login"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401


def test_url_checker_invalid_token_type_returns_401(client, db_session, registered_user):
    """A token with type != 'access' MUST return 401."""
    user = db_session.query(User).filter(User.email == registered_user["email"]).first()
    now = datetime.utcnow()
    session = UserSession(
        user_id=user.id,
        device_name="Test Device",
        expires_at=now + timedelta(days=7),
    )
    db_session.add(session)
    db_session.commit()

    # Craft token with type="refresh"
    payload = {
        "sub": user.id,
        "sid": session.id,
        "role": "citizen",
        "type": "refresh",
        "exp": datetime.utcnow() + timedelta(minutes=15),
    }
    bad_token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

    resp = client.post(
        "/api/v1/url-checker/check",
        json={"url": "http://192.0.2.10/verify-login"},
        headers={"Authorization": f"Bearer {bad_token}"},
    )
    assert resp.status_code == 401


def test_url_checker_inactive_user_returns_401(client, db_session, registered_user):
    """A token belonging to a deactivated user MUST return 401."""
    login_resp = client.post("/api/v1/auth/login", json={"email": registered_user["email"], "password": registered_user["password"]})
    token = login_resp.json()["access_token"]

    user = db_session.query(User).filter(User.email == registered_user["email"]).first()
    user.is_active = False
    db_session.commit()

    resp = client.post(
        "/api/v1/url-checker/check",
        json={"url": "http://192.0.2.10/verify-login"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401


def test_url_checker_invalid_jwt_returns_401(client):
    """An invalid, malformed, or tampered JWT in Authorization header MUST return 401."""
    resp = client.post(
        "/api/v1/url-checker/check",
        json={"url": "http://192.0.2.10/verify-login"},
        headers={"Authorization": "Bearer invalid.jwt.signature"},
    )
    assert resp.status_code == 401


def test_url_checker_malformed_auth_header_returns_401(client):
    """A non-Bearer or malformed Authorization header MUST return 401."""
    resp = client.post(
        "/api/v1/url-checker/check",
        json={"url": "http://192.0.2.10/verify-login"},
        headers={"Authorization": "Basic dXNlcjpwYXNz"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Message Checker Tests
# ---------------------------------------------------------------------------

def test_message_checker_anonymous_request_succeeds_without_user(client, db_session):
    """Anonymous message check without Authorization header succeeds; no user or alert created."""
    resp = client.post("/api/v1/message-checker/check", json={"content": "Hello, see you at noon!"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["risk_level"] in {"low", "medium", "high"}

    records = db_session.query(MessageCheck).all()
    assert len(records) == 1
    assert records[0].user_id is None

    alerts = db_session.query(Alert).all()
    assert len(alerts) == 0


def test_message_checker_authenticated_valid_session_succeeds(client, db_session, registered_user):
    """Authenticated message check with active session succeeds and records user and alert."""
    login_resp = client.post("/api/v1/auth/login", json={"email": registered_user["email"], "password": registered_user["password"]})
    token = login_resp.json()["access_token"]

    high_risk_msg = "URGENT: Your bank account will be suspended! Click http://scam.ru/verify immediately and enter OTP."
    resp = client.post(
        "/api/v1/message-checker/check",
        json={"content": high_risk_msg},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["risk_level"] == "high"

    user = db_session.query(User).filter(User.email == registered_user["email"]).first()
    records = db_session.query(MessageCheck).filter(MessageCheck.user_id == user.id).all()
    assert len(records) == 1

    alerts = db_session.query(Alert).filter(Alert.user_id == user.id).all()
    assert len(alerts) == 1
    assert alerts[0].category.value == "high_risk_message"


def test_message_checker_logged_out_revoked_session_returns_401(client, db_session, registered_user):
    """A revoked access token from a logged-out session MUST return 401 and create NO records."""
    login_resp = client.post("/api/v1/auth/login", json={"email": registered_user["email"], "password": registered_user["password"]})
    tokens = login_resp.json()
    token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    logout_resp = client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": refresh_token},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert logout_resp.status_code == 204

    pre_scan_count = db_session.query(MessageCheck).count()
    pre_alert_count = db_session.query(Alert).count()

    resp = client.post(
        "/api/v1/message-checker/check",
        json={"content": "URGENT: Verify account at http://scam.example/now"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Could not validate credentials"

    assert db_session.query(MessageCheck).count() == pre_scan_count
    assert db_session.query(Alert).count() == pre_alert_count


def test_message_checker_expired_session_returns_401(client, db_session, registered_user):
    """A token whose associated session has expired MUST return 401."""
    login_resp = client.post("/api/v1/auth/login", json={"email": registered_user["email"], "password": registered_user["password"]})
    token = login_resp.json()["access_token"]
    sid = decode_access_token(token)["sid"]

    session = db_session.get(UserSession, sid)
    session.expires_at = datetime.utcnow() - timedelta(minutes=5)
    db_session.commit()

    resp = client.post(
        "/api/v1/message-checker/check",
        json={"content": "Some message content"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401


def test_message_checker_invalid_token_type_returns_401(client, db_session, registered_user):
    """A token with type != 'access' MUST return 401."""
    user = db_session.query(User).filter(User.email == registered_user["email"]).first()
    now = datetime.utcnow()
    session = UserSession(
        user_id=user.id,
        device_name="Test Device",
        expires_at=now + timedelta(days=7),
    )
    db_session.add(session)
    db_session.commit()

    payload = {
        "sub": user.id,
        "sid": session.id,
        "role": "citizen",
        "type": "refresh",
        "exp": datetime.utcnow() + timedelta(minutes=15),
    }
    bad_token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

    resp = client.post(
        "/api/v1/message-checker/check",
        json={"content": "Some message content"},
        headers={"Authorization": f"Bearer {bad_token}"},
    )
    assert resp.status_code == 401


def test_message_checker_inactive_user_returns_401(client, db_session, registered_user):
    """A token belonging to a deactivated user MUST return 401."""
    login_resp = client.post("/api/v1/auth/login", json={"email": registered_user["email"], "password": registered_user["password"]})
    token = login_resp.json()["access_token"]

    user = db_session.query(User).filter(User.email == registered_user["email"]).first()
    user.is_active = False
    db_session.commit()

    resp = client.post(
        "/api/v1/message-checker/check",
        json={"content": "Some message content"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401


def test_message_checker_invalid_jwt_returns_401(client):
    """An invalid, malformed, or tampered JWT in Authorization header MUST return 401."""
    resp = client.post(
        "/api/v1/message-checker/check",
        json={"content": "Some message content"},
        headers={"Authorization": "Bearer bad.token.here"},
    )
    assert resp.status_code == 401


def test_message_checker_malformed_auth_header_returns_401(client):
    """A non-Bearer or malformed Authorization header MUST return 401."""
    resp = client.post(
        "/api/v1/message-checker/check",
        json={"content": "Some message content"},
        headers={"Authorization": "Basic dXNlcjpwYXNz"},
    )
    assert resp.status_code == 401
