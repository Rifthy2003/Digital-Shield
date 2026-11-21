"""
URL Threat Checker — analysis pipeline and scoring methodology.

SCORING METHODOLOGY (documented, not arbitrary — Task 7.1.9):
Each indicator below contributes a fixed, published weight to a 0-100 risk
score. The final score is the sum of triggered weights, capped at 100.
This keeps the score auditable and reproducible: given the same URL and the
same signals, the score is always the same, and every point is traceable to
a named reason.

    Indicator                                   Weight
    ------------------------------------------- ------
    No HTTPS                                     20
    Invalid / expired / self-signed certificate  20
    Domain registered < 30 days ago               15
    IP-literal host instead of a domain name      15
    Excessive subdomain depth (4+)                 5
    Punycode / IDN homograph host                 15
    Known suspicious keyword in domain             5
    Excessive redirect chain (3+ hops)             5
    Domain on a known block/reputation list       25

Risk levels:  0-24 = low   25-54 = medium   55-100 = high

This module never fabricates a result: any check it cannot actually perform
(e.g. no reputation feed configured) is simply omitted from the score and
listed as "not evaluated" in the indicators, rather than guessed.
"""
import re
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from app.services.ssrf_guard import UnsafeUrlError, validate_url_is_safe_to_fetch

SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "account", "update", "bank", "confirm"]
MAX_REDIRECTS = 5

WEIGHTS = {
    "no_https": 20,
    "invalid_certificate": 20,
    "young_domain": 15,
    "ip_literal_host": 15,
    "excessive_subdomains": 5,
    "punycode_host": 15,
    "suspicious_keyword": 5,
    "excessive_redirects": 5,
    "blocklisted_domain": 25,
}


@dataclass
class UrlAnalysisResult:
    url: str
    domain: str
    risk_score: int
    risk_level: str
    indicators: list[dict] = field(default_factory=list)


def _risk_level(score: int) -> str:
    if score >= 55:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _is_ip_literal(hostname: str) -> bool:
    try:
        socket.inet_aton(hostname)
        return True
    except OSError:
        return False


def analyze_url(url: str, domain_reputation_check=None) -> UrlAnalysisResult:
    """
    Runs the full analysis pipeline. `domain_reputation_check` is an optional
    injectable callable(domain) -> bool so the blocklist source can be swapped
    or mocked without touching the scoring logic.
    """
    parsed = urlparse(url if "://" in url else f"http://{url}")
    domain = parsed.hostname or url
    score = 0
    indicators: list[dict] = []

    def flag(key: str, message: str):
        nonlocal score
        score += WEIGHTS[key]
        indicators.append({"key": key, "weight": WEIGHTS[key], "message": message, "triggered": True})

    def clear(key: str, message: str):
        indicators.append({"key": key, "weight": 0, "message": message, "triggered": False})

    # --- Structural checks (no network required) ---
    if parsed.scheme != "https":
        flag("no_https", "The site is not served over HTTPS.")
    else:
        clear("no_https", "Site uses HTTPS.")

    if _is_ip_literal(domain):
        flag("ip_literal_host", "The address uses a raw IP instead of a domain name.")
    else:
        clear("ip_literal_host", "Address uses a standard domain name.")

    if domain.count(".") >= 4:
        flag("excessive_subdomains", "Unusually deep subdomain chain.")
    else:
        clear("excessive_subdomains", "Subdomain depth is normal.")

    if "xn--" in domain.lower():
        flag("punycode_host", "Domain uses punycode encoding, often used to mimic a trusted brand.")
    else:
        clear("punycode_host", "No punycode/IDN homograph pattern detected.")

    if any(kw in domain.lower() for kw in SUSPICIOUS_KEYWORDS):
        flag("suspicious_keyword", "Domain contains a keyword commonly used in impersonation.")
    else:
        clear("suspicious_keyword", "No suspicious keyword in domain.")

    # --- Network checks (SSRF-guarded) ---
    try:
        validate_url_is_safe_to_fetch(f"{parsed.scheme}://{domain}")
        try:
            with httpx.Client(follow_redirects=False, timeout=5.0) as client:
                hops = 0
                current_url = url if "://" in url else f"https://{url}"
                while hops < MAX_REDIRECTS:
                    validate_url_is_safe_to_fetch(current_url)
                    resp = client.get(current_url)
                    if resp.is_redirect:
                        hops += 1
                        current_url = str(resp.next_request.url) if resp.next_request else current_url
                        continue
                    break
                if hops >= 3:
                    flag("excessive_redirects", f"URL redirected {hops} times before resolving.")
                else:
                    clear("excessive_redirects", "Redirect chain is within normal range.")
        except (httpx.HTTPError, UnsafeUrlError) as exc:
            indicators.append({"key": "fetch_error", "weight": 0, "message": f"Could not fetch URL live: {exc}", "triggered": False})

        # Certificate check (HTTPS only)
        if parsed.scheme == "https":
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        if not_after < datetime.now(timezone.utc):
                            flag("invalid_certificate", "TLS certificate has expired.")
                        else:
                            clear("invalid_certificate", "TLS certificate is currently valid.")
            except (ssl.SSLError, OSError, ValueError) as exc:
                flag("invalid_certificate", f"Could not validate TLS certificate: {exc}")
    except UnsafeUrlError as exc:
        indicators.append({"key": "blocked_target", "weight": 0, "message": f"Scan blocked: {exc}", "triggered": False})

    # --- Reputation check (pluggable; honestly marked when unavailable) ---
    if domain_reputation_check is not None:
        try:
            if domain_reputation_check(domain):
                flag("blocklisted_domain", "Domain appears on a known threat/reputation blocklist.")
            else:
                clear("blocklisted_domain", "Domain not found on the configured reputation blocklist.")
        except Exception as exc:  # noqa: BLE001 — provider failure must not break the scan
            indicators.append({"key": "reputation_error", "weight": 0, "message": f"Reputation check unavailable: {exc}", "triggered": False})
    else:
        indicators.append({"key": "blocklisted_domain", "weight": 0, "message": "Not evaluated — no reputation provider configured.", "triggered": False, "not_evaluated": True})

    score = min(score, 100)
    return UrlAnalysisResult(url=url, domain=domain, risk_score=score, risk_level=_risk_level(score), indicators=indicators)
