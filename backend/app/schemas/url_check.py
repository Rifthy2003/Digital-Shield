from pydantic import BaseModel, Field


class UrlCheckRequest(BaseModel):
    url: str = Field(..., min_length=4, max_length=2048)


class UrlCheckResponse(BaseModel):
    url: str
    domain: str
    risk_score: int
    risk_level: str
    indicators: list[dict]
    checked_at: str
