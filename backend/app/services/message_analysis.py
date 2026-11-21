"""
Scam & Phishing Message Analyzer.

Rule-based, transparent indicator detection (Task 8.1.2 / 8.1.6). This is a
heuristic aid, not a guarantee — the result always carries that caveat
rather than a bare "safe" verdict (per the development rules).

SCORING METHODOLOGY:
    Indicator                                  Weight
    ------------------------------------------- ------
    Urgency / pressure language                  20
    Financial request                            25
    Suspicious or shortened link present          20
    Impersonation phrase (bank/gov/law enforce.)  20
    Request for OTP / PIN / password              30
    Generic greeting + request for personal info  10

Risk levels: 0-24 = low   25-54 = medium   55-100 = high
"""
import re
from dataclasses import dataclass, field

URGENCY_PATTERNS = [r"\burgent\b", r"\bimmediately\b", r"act now", r"within 24 hours", r"your account will be (blocked|suspended|closed)"]
FINANCIAL_PATTERNS = [r"\bpayment\b", r"\brefund\b", r"\btransfer\b", r"won.*(prize|lottery)", r"\binvoice\b"]
LINK_PATTERN = r"https?://\S+|www\.\S+|bit\.ly/\S+"
IMPERSONATION_PATTERNS = [r"\bbank\b", r"\bpolice\b", r"\bgovernment\b", r"\bIRS\b", r"customs? (department|authority)"]
CREDENTIAL_REQUEST_PATTERNS = [r"\bOTP\b", r"\bPIN\b", r"\bpassword\b", r"verification code", r"one.?time.?(code|password)"]
GENERIC_GREETING_PATTERNS = [r"^dear (customer|user|sir/madam)", r"\bvalued customer\b"]

WEIGHTS = {
    "urgency": 20,
    "financial_request": 25,
    "suspicious_link": 20,
    "impersonation": 20,
    "credential_request": 30,
    "generic_greeting": 10,
}


@dataclass
class MessageAnalysisResult:
    risk_score: int
    risk_level: str
    indicators: list[dict] = field(default_factory=list)
    links_found: list[str] = field(default_factory=list)


def _risk_level(score: int) -> str:
    if score >= 55:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _any_match(patterns: list[str], text: str) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


def analyze_message(text: str) -> MessageAnalysisResult:
    score = 0
    indicators: list[dict] = []

    def flag(key: str, message: str):
        nonlocal score
        score += WEIGHTS[key]
        indicators.append({"key": key, "weight": WEIGHTS[key], "message": message, "triggered": True})

    def clear(key: str, message: str):
        indicators.append({"key": key, "weight": 0, "message": message, "triggered": False})

    checks = [
        ("urgency", URGENCY_PATTERNS, "Message uses urgency or pressure language.", "No urgency language detected."),
        ("financial_request", FINANCIAL_PATTERNS, "Message references a payment, refund, or prize.", "No financial request detected."),
        ("impersonation", IMPERSONATION_PATTERNS, "Message references a bank, government body, or law enforcement.", "No impersonation language detected."),
        ("credential_request", CREDENTIAL_REQUEST_PATTERNS, "Message asks for an OTP, PIN, password, or verification code.", "No request for credentials detected."),
        ("generic_greeting", GENERIC_GREETING_PATTERNS, "Message uses a generic greeting typical of mass-sent scams.", "No generic mass-scam greeting detected."),
    ]
    for key, patterns, flag_msg, clear_msg in checks:
        if _any_match(patterns, text):
            flag(key, flag_msg)
        else:
            clear(key, clear_msg)

    links = re.findall(LINK_PATTERN, text, re.IGNORECASE)
    if links:
        flag("suspicious_link", f"Message contains {len(links)} link(s); verify each independently before clicking.")
    else:
        clear("suspicious_link", "No links detected in the message.")

    score = min(score, 100)
    return MessageAnalysisResult(risk_score=score, risk_level=_risk_level(score), indicators=indicators, links_found=links)
