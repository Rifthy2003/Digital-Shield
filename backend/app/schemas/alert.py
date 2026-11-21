from pydantic import BaseModel


class AlertResponse(BaseModel):
    id: str
    severity: str
    category: str
    title: str
    message: str
    is_read: bool
    is_resolved: bool
    created_at: str

    class Config:
        from_attributes = True


class DashboardResponse(BaseModel):
    score: int
    score_breakdown: dict
    alerts_summary: dict  # {"high": int, "medium": int, "info": int}
    recent_alerts: list[AlertResponse]
    recommendations: list[str]
    demo_data_notice: str | None = None
