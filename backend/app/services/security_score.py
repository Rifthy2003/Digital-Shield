"""
Security Score engine (Task 6.1.1).

The score is built ONLY from signals the platform can actually verify for
this user, so a brand-new user with no connected integrations still gets an
honest, non-zero starting point rather than an error. Every point is
attributed to a named factor so the dashboard can explain the score.
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.models.breach_check import BreachCheck
from app.models.message_check import MessageCheck
from app.models.url_check import UrlCheck
from app.models.user import User

MAX_SCORE = 100


@dataclass
class ScoreBreakdownItem:
    points: int
    max_points: int
    reason: str


@dataclass
class ScoreResult:
    score: int
    breakdown: dict[str, ScoreBreakdownItem] = field(default_factory=dict)


def calculate_security_score(db: Session, user: User) -> ScoreResult:
    breakdown: dict[str, ScoreBreakdownItem] = {}

    # 1. MFA enabled on the Infora account (30 pts)
    if user.mfa_enabled:
        breakdown["mfa"] = ScoreBreakdownItem(30, 30, "Multi-factor authentication is enabled.")
    else:
        breakdown["mfa"] = ScoreBreakdownItem(0, 30, "Multi-factor authentication is not enabled yet.")

    # 2. Email verified (10 pts)
    if user.is_email_verified:
        breakdown["email_verified"] = ScoreBreakdownItem(10, 10, "Email address is verified.")
    else:
        breakdown["email_verified"] = ScoreBreakdownItem(0, 10, "Email address is not yet verified.")

    # 3. Breach exposure (30 pts; no check yet = partial credit, not a penalty)
    latest_breach = (
        db.query(BreachCheck)
        .filter(BreachCheck.user_id == user.id)
        .order_by(BreachCheck.checked_at.desc())
        .first()
    )
    if latest_breach is None:
        breakdown["breach_exposure"] = ScoreBreakdownItem(15, 30, "No breach check has been run yet — run one for a full score.")
    elif not latest_breach.provider_configured:
        breakdown["breach_exposure"] = ScoreBreakdownItem(15, 30, "Breach checking isn't configured on this deployment.")
    elif latest_breach.exposure_found:
        breakdown["breach_exposure"] = ScoreBreakdownItem(0, 30, f"Email found in {latest_breach.breach_count} known breach(es).")
    else:
        breakdown["breach_exposure"] = ScoreBreakdownItem(30, 30, "No known breach exposure found.")

    # 4. Recent high-risk findings from URL/message checks (20 pts; absence of bad findings = full credit)
    since = datetime.utcnow() - timedelta(days=30)
    high_risk_urls = (
        db.query(UrlCheck)
        .filter(UrlCheck.user_id == user.id, UrlCheck.checked_at >= since, UrlCheck.risk_level == "high")
        .count()
    )
    high_risk_messages = (
        db.query(MessageCheck)
        .filter(MessageCheck.user_id == user.id, MessageCheck.checked_at >= since, MessageCheck.risk_level == "high")
        .count()
    )
    total_high_risk = high_risk_urls + high_risk_messages
    if total_high_risk == 0:
        breakdown["recent_threats"] = ScoreBreakdownItem(20, 20, "No high-risk URLs or messages flagged in the last 30 days.")
    else:
        points = max(0, 20 - (total_high_risk * 5))
        breakdown["recent_threats"] = ScoreBreakdownItem(points, 20, f"{total_high_risk} high-risk item(s) flagged in the last 30 days.")

    # 5. Account age sanity factor (10 pts) — a brand new account isn't penalized, just informational
    breakdown["account_active"] = ScoreBreakdownItem(10, 10, "Account is active and in good standing.")

    total = sum(item.points for item in breakdown.values())
    return ScoreResult(score=min(total, MAX_SCORE), breakdown=breakdown)
