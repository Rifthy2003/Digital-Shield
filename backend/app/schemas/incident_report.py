from pydantic import BaseModel, Field


class IncidentReportCreate(BaseModel):
    category: str
    description: str = Field(..., min_length=10, max_length=5000)


class IncidentReportResponse(BaseModel):
    report_id: str
    category: str
    description: str
    status: str
    created_at: str

    class Config:
        from_attributes = True
