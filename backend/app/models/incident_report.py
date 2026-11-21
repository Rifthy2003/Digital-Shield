import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class IncidentCategory(str, enum.Enum):
    ONLINE_SCAM = "online_scam"
    PHISHING = "phishing"
    FAKE_WEBSITE = "fake_website"
    FAKE_JOB = "fake_job"
    ACCOUNT_HACKING = "account_hacking"
    IDENTITY_THEFT = "identity_theft"
    SOCIAL_MEDIA_ATTACK = "social_media_attack"
    CYBERBULLYING = "cyberbullying"
    FINANCIAL_FRAUD = "financial_fraud"
    OTHER = "other"


class IncidentStatus(str, enum.Enum):
    SUBMITTED = "submitted"
    UNDER_REVIEW = "under_review"
    RESOLVED = "resolved"


class IncidentReport(Base):
    __tablename__ = "incident_reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    report_id: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)  # e.g. INF-CS-2026-000124
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    category: Mapped[IncidentCategory] = mapped_column(Enum(IncidentCategory), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_file_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status: Mapped[IncidentStatus] = mapped_column(Enum(IncidentStatus), default=IncidentStatus.SUBMITTED, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )
