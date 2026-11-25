from datetime import datetime

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.core.rate_limit import limiter
from app.core.rbac import OptionalCurrentUser, get_optional_current_user
from app.core.security import hash_identifier
from app.database import get_db
from app.models.alert import Alert, AlertCategory, AlertSeverity
from app.models.url_check import UrlCheck
from app.models.user import User
from app.schemas.url_check import UrlCheckRequest, UrlCheckResponse
from app.services.url_analysis import analyze_url

router = APIRouter(prefix="/url-checker", tags=["url-checker"])

# Alias for backwards compatibility
_optional_user = get_optional_current_user


@router.post("/check", response_model=UrlCheckResponse)
@limiter.limit("20/minute")
def check_url(
    request: Request,
    payload: UrlCheckRequest,
    db: Session = Depends(get_db),
    user: OptionalCurrentUser = None,
):
    result = analyze_url(payload.url)

    record = UrlCheck(
        user_id=user.id if user else None,
        url_hash=hash_identifier(result.url),
        domain=result.domain,
        risk_score=result.risk_score,
        risk_level=result.risk_level,
        indicators=result.indicators,
    )
    db.add(record)

    if user and result.risk_level == "high":
        db.add(
            Alert(
                user_id=user.id,
                severity=AlertSeverity.HIGH,
                category=AlertCategory.HIGH_RISK_URL,
                title="High-risk URL checked",
                message=f"The URL you checked ({result.domain}) scored {result.risk_score}/100 risk.",
            )
        )
    db.commit()

    return UrlCheckResponse(
        url=result.url,
        domain=result.domain,
        risk_score=result.risk_score,
        risk_level=result.risk_level,
        indicators=result.indicators,
        checked_at=datetime.utcnow().isoformat(),
    )
