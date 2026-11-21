import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class BreachCheck(Base):
    __tablename__ = "breach_checks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    email_hash: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    provider_configured: Mapped[bool] = mapped_column(Boolean, nullable=False)
    exposure_found: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    breach_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    details: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)
