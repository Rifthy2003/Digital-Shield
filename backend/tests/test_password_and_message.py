from app.services.message_analysis import analyze_message
from app.services.password_strength import analyze_password_strength


def test_common_password_flagged():
    result = analyze_password_strength("password")
    assert result.is_common is True
    assert result.score == 0


def test_strong_password_scores_well():
    result = analyze_password_strength("Tr0ub4dor&3xtra!Long")
    assert result.score >= 3


def test_password_never_echoed_in_api_response(client):
    resp = client.post("/api/v1/password-health/strength", json={"password": "SuperSecret123!"})
    assert resp.status_code == 200
    assert "SuperSecret123!" not in resp.text


def test_message_analysis_flags_phishing_indicators():
    text = "URGENT: Your account will be suspended. Verify your password and OTP now: http://bit.ly/xyz"
    result = analyze_message(text)
    flagged = {i["key"] for i in result.indicators if i["triggered"]}
    assert "urgency" in flagged
    assert "credential_request" in flagged
    assert "suspicious_link" in flagged
    assert result.risk_level == "high"


def test_message_analysis_benign_message_scores_low():
    result = analyze_message("Hey, are we still on for lunch tomorrow at noon?")
    assert result.risk_level == "low"


def test_message_checker_api_never_stores_raw_text(client, db_session):
    from app.models.message_check import MessageCheck

    resp = client.post("/api/v1/message-checker/check", json={"content": "Hi, lunch tomorrow?"})
    assert resp.status_code == 200
    rows = db_session.query(MessageCheck).all()
    assert len(rows) == 1
    # The raw content must never appear in the stored record.
    assert "lunch" not in str(rows[0].content_hash)
    assert len(rows[0].content_hash) == 64  # sha256 hex digest length


def test_breach_checker_honest_when_unconfigured(client, auth_headers):
    resp = client.post("/api/v1/breach-checker/check", json={"email": "someone@example.com"}, headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["configured"] is False
    assert "not configured" in body["message"].lower()
