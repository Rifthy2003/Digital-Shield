"""
Security tests for SEC-02: Remediate Targeted Account Lockout DoS.

Verifies:
1. Repeated failed login attempts from the same IP are rate-limited (HTTP 429).
2. Attackers CANNOT lock a target account through failed login requests:
   - Attacker exhausts rate limit for their own IP.
   - Legitimate user on a different IP logs in successfully with the correct password.
3. Attackers cannot bypass rate limiting by cycling through different email addresses.
4. Rate limits are cleanly isolated between different client IPs.
5. Untrusted direct client connections cannot spoof client IP via arbitrary X-Forwarded-For headers.
6. Legitimate login with correct credentials succeeds without hindrance.
"""
from app.core.rate_limit import get_client_ip


def test_repeated_failed_logins_from_same_ip_rate_limited(client, registered_user):
    """5 failed attempts return 401; the 6th attempt from the same IP returns HTTP 429."""
    for _ in range(5):
        resp = client.post(
            "/api/v1/auth/login",
            json={"email": registered_user["email"], "password": "WrongPassword123"},
            headers={"X-Forwarded-For": "198.51.100.1"},
        )
        assert resp.status_code == 401

    # 6th attempt from the same IP triggers HTTP 429 Too Many Requests
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": "WrongPassword123"},
        headers={"X-Forwarded-For": "198.51.100.1"},
    )
    assert resp.status_code == 429
    assert "rate limit exceeded" in resp.text.lower()


def test_targeted_attacker_cannot_lock_legitimate_user_account(client, registered_user):
    """
    Core SEC-02 Verification:
    An attacker repeatedly fails login targeting a victim's email address.
    The attacker is blocked by IP rate limiting (429).
    The legitimate user connecting from another IP can still immediately log in with their password (200 OK).
    """
    attacker_ip = "198.51.100.50"
    victim_ip = "203.0.113.10"

    # Attacker sends 5 failed login attempts for victim's email
    for _ in range(5):
        resp = client.post(
            "/api/v1/auth/login",
            json={"email": registered_user["email"], "password": "AttackerWrongPassword1"},
            headers={"X-Forwarded-For": attacker_ip},
        )
        assert resp.status_code == 401

    # Attacker's 6th attempt is throttled with 429
    attacker_blocked = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": "AttackerWrongPassword1"},
        headers={"X-Forwarded-For": attacker_ip},
    )
    assert attacker_blocked.status_code == 429

    # The legitimate user from victim_ip logs in with correct password
    # MUST succeed with 200 OK! Victim account is NOT locked!
    legitimate_login = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
        headers={"X-Forwarded-For": victim_ip},
    )
    assert legitimate_login.status_code == 200
    assert "access_token" in legitimate_login.json()
    assert "refresh_token" in legitimate_login.json()


def test_attacker_cannot_bypass_rate_limit_by_changing_email(client):
    """
    Attackers cannot evade rate limiting by trying different email addresses
    from the same client IP.
    """
    attacker_ip = "198.51.100.99"
    emails = [
        "target1@example.com",
        "target2@example.com",
        "target3@example.com",
        "target4@example.com",
        "target5@example.com",
    ]

    for email in emails:
        resp = client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "WrongPassword123"},
            headers={"X-Forwarded-For": attacker_ip},
        )
        assert resp.status_code == 401

    # 6th attempt with yet another email is still rate-limited on the attacker's IP
    resp_blocked = client.post(
        "/api/v1/auth/login",
        json={"email": "target6@example.com", "password": "WrongPassword123"},
        headers={"X-Forwarded-For": attacker_ip},
    )
    assert resp_blocked.status_code == 429


def test_different_client_ips_have_independent_rate_limits(client, registered_user):
    """Each client IP has its own rate limit counter."""
    ip_a = "192.0.2.1"
    ip_b = "192.0.2.2"

    # Exhaust IP A limit
    for _ in range(5):
        resp = client.post(
            "/api/v1/auth/login",
            json={"email": registered_user["email"], "password": "WrongPassword123"},
            headers={"X-Forwarded-For": ip_a},
        )
        assert resp.status_code == 401

    # IP A is blocked
    assert client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": "WrongPassword123"},
        headers={"X-Forwarded-For": ip_a},
    ).status_code == 429

    # IP B has not made requests yet and is NOT blocked
    resp_b = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
        headers={"X-Forwarded-For": ip_b},
    )
    assert resp_b.status_code == 200


def test_untrusted_direct_peer_ignores_arbitrary_x_forwarded_for():
    """
    Direct untrusted peer IP connections cannot spoof client IP via X-Forwarded-For.
    Only trusted proxies (localhost, testclient, etc.) are allowed to forward IPs.
    """
    class MockClient:
        host = "203.0.113.88"  # External untrusted IP

    class MockRequest:
        client = MockClient()
        headers = {"x-forwarded-for": "10.0.0.1, 1.1.1.1"}

    # Resolves to direct peer_ip because 203.0.113.88 is not a trusted proxy
    resolved = get_client_ip(MockRequest())
    assert resolved == "203.0.113.88"


def test_trusted_proxy_peer_accepts_x_forwarded_for():
    """When connecting through a trusted proxy (e.g. 127.0.0.1), client IP is parsed."""
    class MockClient:
        host = "127.0.0.1"  # Trusted reverse proxy

    class MockRequest:
        client = MockClient()
        headers = {"x-forwarded-for": "198.51.100.77, ::1"}

    resolved = get_client_ip(MockRequest())
    assert resolved == "198.51.100.77"


def test_successful_login_within_rate_limit(client, registered_user):
    """Normal login with valid credentials succeeds."""
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "access_token" in body
    assert "refresh_token" in body
