import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class UrlCheck(Base):
    __tablename__ = "url_checks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    url_hash: Mapped[str] = mapped_column(String(64), index=True, nullable=False)  # sha256 of normalized URL
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)  # 0-100, higher = riskier
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False)  # low | medium | high
    indicators: Mapped[dict] = mapped_column(JSON, nullable=False)
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)
