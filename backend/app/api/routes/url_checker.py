from datetime import datetime

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.core.rate_limit import limiter
from app.core.rbac import get_current_user
from app.core.security import hash_identifier
from app.database import get_db
from app.models.alert import Alert, AlertCategory, AlertSeverity
from app.models.url_check import UrlCheck
from app.models.user import User
from app.schemas.url_check import UrlCheckRequest, UrlCheckResponse
from app.services.url_analysis import analyze_url

router = APIRouter(prefix="/url-checker", tags=["url-checker"])


def _optional_user(request: Request, db: Session = Depends(get_db)) -> User | None:
    """The URL checker works for anonymous visitors too; logged-in users get history + alerts."""
    auth_header = request.headers.get("authorization")
    if not auth_header:
        return None
    try:
        from app.core.security import decode_access_token

        token = auth_header.removeprefix("Bearer ").strip()
        payload = decode_access_token(token)
        return db.get(User, payload.get("sub"))
    except Exception:  # noqa: BLE001
        return None


@router.post("/check", response_model=UrlCheckResponse)
@limiter.limit("20/minute")
def check_url(request: Request, payload: UrlCheckRequest, db: Session = Depends(get_db), user: User | None = Depends(_optional_user)):
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
