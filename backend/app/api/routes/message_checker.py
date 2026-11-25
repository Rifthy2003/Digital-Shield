from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.core.rate_limit import limiter
from app.core.rbac import OptionalCurrentUser
from app.core.security import hash_identifier
from app.database import get_db
from app.models.alert import Alert, AlertCategory, AlertSeverity
from app.models.message_check import MessageCheck
from app.schemas.message_check import MessageCheckRequest, MessageCheckResponse
from app.services.message_analysis import analyze_message

router = APIRouter(prefix="/message-checker", tags=["message-checker"])


@router.post("/check", response_model=MessageCheckResponse)
@limiter.limit("20/minute")
def check_message(
    request: Request,
    payload: MessageCheckRequest,
    db: Session = Depends(get_db),
    user: OptionalCurrentUser = None,
):
    result = analyze_message(payload.content)

    # Only the hash of the content is persisted — never the raw text (data minimization).
    record = MessageCheck(
        user_id=user.id if user else None,
        content_hash=hash_identifier(payload.content),
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
                category=AlertCategory.HIGH_RISK_MESSAGE,
                title="High-risk message checked",
                message=f"A message you submitted scored {result.risk_score}/100 risk.",
            )
        )
    db.commit()

    return MessageCheckResponse(
        risk_score=result.risk_score,
        risk_level=result.risk_level,
        indicators=result.indicators,
        links_found=result.links_found,
    )
