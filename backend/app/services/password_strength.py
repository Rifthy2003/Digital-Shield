"""
Password strength analysis.

Per the MVP security rules, this analysis happens only transiently on the
value the user is actively setting (e.g. at registration/change time) — it
is never stored, never logged, and the frontend is expected to additionally
offer a client-side-only check so the password need not touch the network
at all for a strength read. See docs/SECURITY.md.
"""
import re
from dataclasses import dataclass

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "password1",
    "111111", "123123", "letmein", "welcome", "admin", "iloveyou",
}


@dataclass
class PasswordStrengthResult:
    score: int  # 0-4 (very weak -> very strong)
    label: str
    is_common: bool
    suggestions: list[str]


def analyze_password_strength(password: str) -> PasswordStrengthResult:
    suggestions: list[str] = []
    length_score = min(len(password) / 16, 1.0)

    variety = sum([
        bool(re.search(r"[a-z]", password)),
        bool(re.search(r"[A-Z]", password)),
        bool(re.search(r"\d", password)),
        bool(re.search(r"[^a-zA-Z0-9]", password)),
    ])

    is_common = password.lower() in COMMON_PASSWORDS
    raw = (length_score * 2) + (variety * 0.5)

    if is_common:
        raw = 0
        suggestions.append("This is one of the most commonly breached passwords — avoid it entirely.")
    if len(password) < 12:
        suggestions.append("Use at least 12 characters.")
    if variety < 3:
        suggestions.append("Mix uppercase, lowercase, numbers, and symbols.")
    if not suggestions and not is_common:
        suggestions.append("Looks strong. Avoid reusing it on other accounts.")

    score = max(0, min(4, round(raw)))
    labels = {0: "very weak", 1: "weak", 2: "fair", 3: "strong", 4: "very strong"}
    return PasswordStrengthResult(score=score, label=labels[score], is_common=is_common, suggestions=suggestions)


def k_anonymity_prefix(sha1_hex_upper: str) -> tuple[str, str]:
    """
    Splits a password's SHA-1 hash for a k-anonymity compromised-password
    check (HIBP Pwned Passwords style): only the first 5 hex characters are
    ever sent anywhere; the full hash and the password itself never leave
    this function's caller.
    """
    return sha1_hex_upper[:5], sha1_hex_upper[5:]
