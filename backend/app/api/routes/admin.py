from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.rbac import AdminUser
from app.database import get_db
from app.models.incident_report import IncidentReport
from app.models.url_check import UrlCheck
from app.models.user import User
from app.schemas.incident_report import IncidentReportResponse
from app.utils.audit import record_audit_event

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/stats")
def platform_stats(admin: AdminUser, db: Session = Depends(get_db)):
    """
    Aggregate, non-identifying statistics only. Viewing an individual user's
    record requires a separate, explicitly logged action (see /admin/users/{id}).
    """
    return {
        "total_users": db.query(func.count(User.id)).scalar(),
        "total_url_checks": db.query(func.count(UrlCheck.id)).scalar(),
        "total_incident_reports": db.query(func.count(IncidentReport.id)).scalar(),
        "open_incident_reports": db.query(func.count(IncidentReport.id)).filter(IncidentReport.status == "submitted").count(),
    }


@router.get("/incidents", response_model=list[IncidentReportResponse])
def list_all_incidents(admin: AdminUser, db: Session = Depends(get_db)):
    reports = db.query(IncidentReport).order_by(IncidentReport.created_at.desc()).all()
    record_audit_event(db, actor_id=admin.id, action="admin.view_all_incidents")
    return [
        IncidentReportResponse(
            report_id=r.report_id, category=r.category.value, description=r.description,
            status=r.status.value, created_at=r.created_at.isoformat(),
        )
        for r in reports
    ]


@router.get("/users/{user_id}")
def view_user_record(user_id: str, admin: AdminUser, db: Session = Depends(get_db)):
    """
    Deliberately logged every time: an admin viewing an individual citizen's
    record is a sensitive, auditable action, never a side effect of a
    general listing.
    """
    user = db.get(User, user_id)
    record_audit_event(db, actor_id=admin.id, action="admin.view_user_record", resource=user_id)
    if user is None:
        return {"found": False}
    return {
        "found": True,
        "id": user.id,
        "email": user.email,
        "role": user.role.value,
        "is_active": user.is_active,
        "mfa_enabled": user.mfa_enabled,
        "created_at": user.created_at.isoformat(),
        # Deliberately excluded: password_hash, refresh tokens, raw check content.
    }
