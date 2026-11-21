from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.rbac import CurrentUser
from app.database import get_db
from app.models.alert import Alert, AlertSeverity
from app.models.security_score import SecurityScore
from app.schemas.alert import AlertResponse, DashboardResponse
from app.services.security_score import calculate_security_score

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


def _build_recommendations(breakdown: dict) -> list[str]:
    recs = []
    for key, item in breakdown.items():
        if item.points < item.max_points:
            recs.append(item.reason)
    return recs


@router.get("", response_model=DashboardResponse)
def get_dashboard(user: CurrentUser, db: Session = Depends(get_db)):
    result = calculate_security_score(db, user)

    db.add(
        SecurityScore(
            user_id=user.id,
            score=result.score,
            breakdown={k: vars(v) for k, v in result.breakdown.items()},
        )
    )
    db.commit()

    alerts_query = db.query(Alert).filter(Alert.user_id == user.id, Alert.is_resolved.is_(False))
    alerts_summary = {
        "high": alerts_query.filter(Alert.severity == AlertSeverity.HIGH).count(),
        "medium": alerts_query.filter(Alert.severity == AlertSeverity.MEDIUM).count(),
        "info": alerts_query.filter(Alert.severity == AlertSeverity.INFO).count(),
    }
    recent_alerts = alerts_query.order_by(Alert.created_at.desc()).limit(5).all()

    return DashboardResponse(
        score=result.score,
        score_breakdown={k: vars(v) for k, v in result.breakdown.items()},
        alerts_summary=alerts_summary,
        recent_alerts=[
            AlertResponse(
                id=a.id,
                severity=a.severity.value,
                category=a.category.value,
                title=a.title,
                message=a.message,
                is_read=a.is_read,
                is_resolved=a.is_resolved,
                created_at=a.created_at.isoformat(),
            )
            for a in recent_alerts
        ],
        recommendations=_build_recommendations(result.breakdown),
        demo_data_notice=None,  # all figures above are live-calculated, never simulated
    )
