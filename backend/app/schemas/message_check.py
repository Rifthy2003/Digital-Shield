from pydantic import BaseModel, Field


class MessageCheckRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=5000)


class MessageCheckResponse(BaseModel):
    risk_score: int
    risk_level: str
    indicators: list[dict]
    links_found: list[str]
    disclaimer: str = (
        "This is an automated heuristic assessment, not a guarantee. "
        "A low score does not mean a message is definitely safe."
    )
