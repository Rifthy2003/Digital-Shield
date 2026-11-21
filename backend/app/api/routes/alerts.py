from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.rbac import CurrentUser
from app.database import get_db
from app.models.alert import Alert
from app.schemas.alert import AlertResponse

router = APIRouter(prefix="/alerts", tags=["alerts"])


def _serialize(a: Alert) -> AlertResponse:
    return AlertResponse(
        id=a.id, severity=a.severity.value, category=a.category.value, title=a.title,
        message=a.message, is_read=a.is_read, is_resolved=a.is_resolved, created_at=a.created_at.isoformat(),
    )


@router.get("", response_model=list[AlertResponse])
def list_alerts(user: CurrentUser, db: Session = Depends(get_db)):
    alerts = db.query(Alert).filter(Alert.user_id == user.id).order_by(Alert.created_at.desc()).all()
    return [_serialize(a) for a in alerts]


def _get_owned_alert(alert_id: str, user, db: Session) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None or alert.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert


@router.post("/{alert_id}/read", response_model=AlertResponse)
def mark_read(alert_id: str, user: CurrentUser, db: Session = Depends(get_db)):
    alert = _get_owned_alert(alert_id, user, db)
    alert.is_read = True
    db.commit()
    return _serialize(alert)


@router.post("/{alert_id}/resolve", response_model=AlertResponse)
def mark_resolved(alert_id: str, user: CurrentUser, db: Session = Depends(get_db)):
    alert = _get_owned_alert(alert_id, user, db)
    alert.is_resolved = True
    db.commit()
    return _serialize(alert)
