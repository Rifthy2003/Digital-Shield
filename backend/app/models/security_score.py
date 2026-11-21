import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class SecurityScore(Base):
    """
    A point-in-time snapshot of a user's computed security score. History is
    kept (one row per calculation) so the dashboard can show a trend.
    """

    __tablename__ = "security_scores"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    score: Mapped[int] = mapped_column(Integer, nullable=False)  # 0-100
    breakdown: Mapped[dict] = mapped_column(JSON, nullable=False)  # {"factor": {"points": int, "max": int, "reason": str}}
    calculated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)
