from pydantic import BaseModel, EmailStr


class BreachCheckRequest(BaseModel):
    email: EmailStr


class BreachCheckResponse(BaseModel):
    configured: bool
    exposure_found: bool
    breach_count: int
    message: str
    recommended_actions: list[str]


class PasswordStrengthRequest(BaseModel):
    password: str


class PasswordStrengthResponse(BaseModel):
    score: int
    label: str
    is_common: bool
    suggestions: list[str]
