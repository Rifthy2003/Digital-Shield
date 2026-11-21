import pytest

from app.services.ssrf_guard import UnsafeUrlError, validate_url_is_safe_to_fetch
from app.services.url_analysis import analyze_url


def test_ssrf_guard_blocks_localhost():
    with pytest.raises(UnsafeUrlError):
        validate_url_is_safe_to_fetch("http://localhost/admin")


def test_ssrf_guard_blocks_loopback_ip():
    with pytest.raises(UnsafeUrlError):
        validate_url_is_safe_to_fetch("http://127.0.0.1/secret")


def test_ssrf_guard_blocks_private_range():
    with pytest.raises(UnsafeUrlError):
        validate_url_is_safe_to_fetch("http://192.168.1.1/")


def test_ssrf_guard_blocks_cloud_metadata_endpoint():
    with pytest.raises(UnsafeUrlError):
        validate_url_is_safe_to_fetch("http://169.254.169.254/latest/meta-data/")


def test_ssrf_guard_blocks_disallowed_scheme():
    with pytest.raises(UnsafeUrlError):
        validate_url_is_safe_to_fetch("file:///etc/passwd")


def test_url_analysis_flags_non_https():
    result = analyze_url("http://example-test-domain.invalid/login")
    flagged = {i["key"] for i in result.indicators if i["triggered"]}
    assert "no_https" in flagged


def test_url_analysis_flags_ip_literal_host():
    result = analyze_url("http://192.0.2.10/verify-account")
    flagged = {i["key"] for i in result.indicators if i["triggered"]}
    assert "ip_literal_host" in flagged


def test_url_analysis_flags_punycode_domain():
    result = analyze_url("https://xn--pple-43d.com/")
    flagged = {i["key"] for i in result.indicators if i["triggered"]}
    assert "punycode_host" in flagged


def test_url_analysis_scoring_is_deterministic():
    r1 = analyze_url("http://192.0.2.10/login-verify")
    r2 = analyze_url("http://192.0.2.10/login-verify")
    assert r1.risk_score == r2.risk_score
    assert r1.risk_level == r2.risk_level


def test_url_checker_api_endpoint_anonymous(client):
    resp = client.post("/api/v1/url-checker/check", json={"url": "http://192.0.2.10/verify-login"})
    assert resp.status_code == 200
    body = resp.json()
    assert "risk_score" in body and "risk_level" in body
    assert body["risk_level"] in {"low", "medium", "high"}


def test_url_checker_rejects_too_short_input(client):
    resp = client.post("/api/v1/url-checker/check", json={"url": "a"})
    assert resp.status_code == 422
