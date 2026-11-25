"""
Security tests for SEC-07: Secure Client IP Detection & Prevent IP Spoofing.

Verifies:
1. Direct client request without forwarded headers resolves to peer IP.
2. Untrusted client supplying spoofed X-Forwarded-For is ignored.
3. Trusted proxy (explicit IP and CIDR) supplying valid forwarded IP is accepted.
4. Multi-hop trusted proxy chain stops at the trust boundary (ignores client-spoofed prefix
   and does not assume arbitrary private IPs are trusted proxies).
5. Malformed forwarded IP values are rejected safely without trusting spoofed prefixes.
6. Empty / whitespace-only forwarded headers fall back safely.
7. X-Real-IP spoofing from untrusted client is ignored; valid X-Real-IP from trusted proxy works.
8. Device metadata extraction (`extract_client_metadata`) uses the resolved client IP.
9. Session creation (`POST /api/v1/auth/login`) stores the resolved client IP.
10. Audit logging (`AuditLog.ip_hash`) stores `hash_ip(resolved_client_ip)`.
"""
from types import SimpleNamespace

from app.core.client_ip import get_client_ip, resolve_client_ip
from app.core.security import hash_ip
from app.models.audit_log import AuditLog
from app.models.user import UserSession
from app.utils.device import extract_client_metadata


def _make_request(peer_host: str | None, headers: dict[str, str] | None = None):
    client = SimpleNamespace(host=peer_host) if peer_host is not None else None
    normalized_headers = {k.lower(): v for k, v in (headers or {}).items()}
    return SimpleNamespace(client=client, headers=normalized_headers)


def test_direct_client_without_forwarded_headers():
    req_v4 = _make_request("203.0.113.45")
    assert resolve_client_ip(req_v4) == "203.0.113.45"
    assert get_client_ip(req_v4) == "203.0.113.45"

    req_v6 = _make_request("2001:0db8:0000:0000:0000:0000:0000:0001")
    assert resolve_client_ip(req_v6) == "2001:db8::1"


def test_untrusted_client_spoofed_x_forwarded_for_is_ignored():
    req = _make_request(
        "198.51.100.88",
        headers={"X-Forwarded-For": "127.0.0.1, 10.0.0.5"},
    )
    assert resolve_client_ip(req) == "198.51.100.88"
    assert get_client_ip(req) == "198.51.100.88"


def test_trusted_proxy_cidr_accepts_valid_forwarded_ip():
    req = _make_request(
        "10.0.1.25",
        headers={"X-Forwarded-For": "198.51.100.77"},
    )
    # Without 10.0.1.0/24 in trusted proxies, private IP 10.0.1.25 is NOT trusted
    assert resolve_client_ip(req) == "10.0.1.25"

    # With explicit trusted proxy CIDR, forwarded IP is accepted
    assert resolve_client_ip(req, trusted_proxies=["10.0.1.0/24"]) == "198.51.100.77"


def test_trusted_proxy_chain_stops_at_trust_boundary_and_ignores_spoofed_prefix():
    # Client (203.0.113.50) spoofed "1.2.3.4", passed through two trusted proxies (10.0.1.10, 10.0.2.20)
    req = _make_request(
        "10.0.2.20",
        headers={"X-Forwarded-For": "1.2.3.4, 203.0.113.50, 10.0.1.10"},
    )
    resolved = resolve_client_ip(req, trusted_proxies=["10.0.1.0/24", "10.0.2.0/24"])
    assert resolved == "203.0.113.50"

    # If 10.0.1.10 is NOT in trusted_proxies, private IP is NOT assumed trusted
    resolved_untrusted_hop = resolve_client_ip(req, trusted_proxies=["10.0.2.0/24"])
    assert resolved_untrusted_hop == "10.0.1.10"


def test_malformed_forwarded_ip_values_fall_back_safely():
    # Single malformed entry
    req_bad = _make_request("127.0.0.1", headers={"X-Forwarded-For": "not-an-ip"})
    assert resolve_client_ip(req_bad) == "127.0.0.1"

    # Spoofed IP followed by malformed entry before trusted proxy: must NOT skip past malformed entry
    req_smuggled = _make_request(
        "127.0.0.1",
        headers={"X-Forwarded-For": "8.8.8.8, <script>alert(1)</script>, 127.0.0.1"},
    )
    assert resolve_client_ip(req_smuggled) == "127.0.0.1"

    # Port-suffixed IP is rejected by ipaddress validation
    req_port = _make_request("127.0.0.1", headers={"X-Forwarded-For": "198.51.100.1:443"})
    assert resolve_client_ip(req_port) == "127.0.0.1"


def test_empty_forwarded_headers_fall_back_to_peer():
    for val in ("", "   ", ", , "):
        req = _make_request("127.0.0.1", headers={"X-Forwarded-For": val})
        assert resolve_client_ip(req) == "127.0.0.1"


def test_x_real_ip_spoofing_and_trusted_fallback():
    # Untrusted direct client spoofing X-Real-IP -> ignored
    req_untrusted = _make_request("203.0.113.99", headers={"X-Real-IP": "127.0.0.1"})
    assert resolve_client_ip(req_untrusted) == "203.0.113.99"

    # Trusted proxy with valid X-Real-IP and no X-Forwarded-For -> accepted
    req_trusted = _make_request("127.0.0.1", headers={"X-Real-IP": "198.51.100.42"})
    assert resolve_client_ip(req_trusted) == "198.51.100.42"

    # Trusted proxy with malformed X-Real-IP -> falls back to peer
    req_bad_real = _make_request("127.0.0.1", headers={"X-Real-IP": "invalid-ip"})
    assert resolve_client_ip(req_bad_real) == "127.0.0.1"


def test_device_metadata_uses_resolved_ip():
    # Untrusted peer attempting to spoof X-Forwarded-For
    untrusted_req = _make_request(
        "198.51.100.33",
        headers={
            "User-Agent": "Mozilla/5.0",
            "X-Forwarded-For": "1.2.3.4",
            "X-Real-IP": "5.6.7.8",
        },
    )
    meta_untrusted = extract_client_metadata(untrusted_req)
    assert meta_untrusted["ip_address"] == "198.51.100.33"

    # Trusted peer forwarding real client IP
    trusted_req = _make_request(
        "127.0.0.1",
        headers={
            "User-Agent": "Mozilla/5.0",
            "X-Forwarded-For": "198.51.100.55",
        },
    )
    meta_trusted = extract_client_metadata(trusted_req)
    assert meta_trusted["ip_address"] == "198.51.100.55"


def test_session_and_audit_log_use_resolved_ip(client, registered_user, db_session):
    forwarded_ip = "203.0.113.120"
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
        headers={
            "X-Forwarded-For": f"1.1.1.1, {forwarded_ip}, 127.0.0.1",
            "X-Device-Name": "SEC-07 Test Device",
        },
    )
    assert login_resp.status_code == 200
    tokens = login_resp.json()

    # Session record stores the trust-boundary resolved IP (203.0.113.120), NOT 1.1.1.1
    session = (
        db_session.query(UserSession)
        .filter(UserSession.device_name == "SEC-07 Test Device")
        .first()
    )
    assert session is not None
    assert session.ip_address == forwarded_ip

    # /sessions endpoint exposes the resolved IP
    sessions_resp = client.get(
        "/api/v1/auth/sessions",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert sessions_resp.status_code == 200
    assert sessions_resp.json()[0]["ip_address"] == forwarded_ip

    # Audit log for user.login stores hash_ip(resolved_ip)
    login_audit = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "user.login")
        .order_by(AuditLog.created_at.desc())
        .first()
    )
    assert login_audit is not None
    assert login_audit.ip_hash == hash_ip(forwarded_ip)
    assert login_audit.ip_hash != hash_ip("1.1.1.1")
