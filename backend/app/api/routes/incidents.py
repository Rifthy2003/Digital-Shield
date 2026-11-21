import random
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.rbac import CurrentUser
from app.database import get_db
from app.models.incident_report import IncidentCategory, IncidentReport
from app.schemas.incident_report import IncidentReportCreate, IncidentReportResponse

router = APIRouter(prefix="/incidents", tags=["incidents"])

DISCLAIMER = (
    "Infora's incident reporting is a citizen support tool and is NOT a replacement for "
    "official police or government cybercrime reporting. For urgent matters, contact your "
    "local law enforcement or national cybercrime authority directly."
)


def _generate_report_id() -> str:
    year = datetime.utcnow().year
    return f"INF-CS-{year}-{random.randint(100000, 999999)}"


def _serialize(r: IncidentReport) -> IncidentReportResponse:
    return IncidentReportResponse(
        report_id=r.report_id, category=r.category.value, description=r.description,
        status=r.status.value, created_at=r.created_at.isoformat(),
    )


@router.post("", response_model=IncidentReportResponse, status_code=status.HTTP_201_CREATED)
def submit_incident(payload: IncidentReportCreate, user: CurrentUser, db: Session = Depends(get_db)):
    try:
        category = IncidentCategory(payload.category)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown incident category")

    report = IncidentReport(
        report_id=_generate_report_id(),
        user_id=user.id,
        category=category,
        description=payload.description,
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return _serialize(report)


@router.get("", response_model=list[IncidentReportResponse])
def list_my_incidents(user: CurrentUser, db: Session = Depends(get_db)):
    reports = (
        db.query(IncidentReport)
        .filter(IncidentReport.user_id == user.id)
        .order_by(IncidentReport.created_at.desc())
        .all()
    )
    return [_serialize(r) for r in reports]


@router.get("/{report_id}", response_model=IncidentReportResponse)
def get_incident(report_id: str, user: CurrentUser, db: Session = Depends(get_db)):
    report = db.query(IncidentReport).filter(IncidentReport.report_id == report_id, IncidentReport.user_id == user.id).first()
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return _serialize(report)
