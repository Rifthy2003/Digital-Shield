import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class AlertSeverity(str, enum.Enum):
    HIGH = "high"
    MEDIUM = "medium"
    INFO = "info"


class AlertCategory(str, enum.Enum):
    BREACH_EXPOSURE = "breach_exposure"
    WEAK_PASSWORD = "weak_password"
    HIGH_RISK_URL = "high_risk_url"
    HIGH_RISK_MESSAGE = "high_risk_message"
    SCORE_DROP = "score_drop"
    ACCOUNT = "account"
    SYSTEM = "system"


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    severity: Mapped[AlertSeverity] = mapped_column(Enum(AlertSeverity), nullable=False)
    category: Mapped[AlertCategory] = mapped_column(Enum(AlertCategory), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_resolved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)
