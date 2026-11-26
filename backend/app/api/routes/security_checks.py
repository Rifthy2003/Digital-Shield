from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.core.rate_limit import limiter
from app.core.rbac import CurrentUser
from app.core.security import hash_identifier
from app.database import get_db
from app.models.alert import Alert, AlertCategory, AlertSeverity
from app.models.breach_check import BreachCheck
from app.schemas.breach_check import (
    BreachCheckRequest,
    BreachCheckResponse,
    PasswordStrengthRequest,
    PasswordStrengthResponse,
)
from app.services.breach_provider import get_breach_provider
from app.services.password_strength import analyze_password_strength

router = APIRouter(tags=["security-checks"])


@router.post("/breach-checker/check", response_model=BreachCheckResponse)
@limiter.limit("10/minute")
async def check_breach(request: Request, payload: BreachCheckRequest, user: CurrentUser, db: Session = Depends(get_db)):
    provider = get_breach_provider()
    result = await provider.check_email(payload.email)

    record = BreachCheck(
        user_id=user.id,
        email_hash=hash_identifier(payload.email),
        provider_configured=result.configured,
        exposure_found=result.exposure_found,
        breach_count=result.breach_count,
        details={"breach_names": result.breach_names} if result.configured else {},
    )
    db.add(record)

    recommended_actions: list[str] = []
    if result.exposure_found:
        recommended_actions = [
            "Change the password for this email on every affected account.",
            "Enable multi-factor authentication wherever available.",
            "Review active sessions on affected accounts.",
            "Review third-party applications connected to affected accounts.",
        ]
        db.add(
            Alert(
                user_id=user.id,
                severity=AlertSeverity.HIGH,
                category=AlertCategory.BREACH_EXPOSURE,
                title="Breach exposure found",
                message=f"Your email appeared in {result.breach_count} known breach(es).",
            )
        )
    db.commit()

    return BreachCheckResponse(
        configured=result.configured,
        exposure_found=result.exposure_found,
        breach_count=result.breach_count,
        message=result.message,
        recommended_actions=recommended_actions,
    )


@router.post("/password-health/strength", response_model=PasswordStrengthResponse, deprecated=True)
@limiter.limit("30/minute")
def check_password_strength(request: Request, payload: PasswordStrengthRequest):
    """
    Deprecated for web clients (P1-A): password strength is now evaluated
    100% locally in the browser. Retained for backward API compatibility only;
    stateless in-memory analysis, never stored or logged.
    """
    result = analyze_password_strength(payload.password)
    return PasswordStrengthResponse(
        score=result.score, label=result.label, is_common=result.is_common, suggestions=result.suggestions
    )
