"""
AI Cybersecurity Assistant.

If AI_PROVIDER_API_KEY is not configured, this endpoint does NOT pretend to
call an external model. It runs a small rule-based fallback grounded in the
platform's own message/URL analyzers and says plainly that the full AI
assistant is not configured, per the development rules.
"""
from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from app.config import get_settings
from app.core.rate_limit import limiter
from app.services.message_analysis import analyze_message
from app.services.url_analysis import analyze_url
import re

router = APIRouter(prefix="/assistant", tags=["ai-assistant"])


class AssistantRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=2000)


class AssistantResponse(BaseModel):
    answer: str
    mode: str  # "ai_provider" | "rule_based_fallback"
    grounded_check: dict | None = None


SAFETY_FOOTER = (
    "\n\nI'm a security guidance tool, not a bank, government agency, or law enforcement. "
    "If you're unsure, contact the organization directly using a number or website you already trust."
)


def _rule_based_answer(question: str) -> AssistantResponse:
    url_match = re.search(r"https?://\S+|www\.\S+", question)
    if url_match:
        result = analyze_url(url_match.group(0))
        answer = (
            f"I checked that link: risk score {result.risk_score}/100 ({result.risk_level} risk). "
            + ("Avoid clicking it and verify the source independently." if result.risk_level != "low" else "No major red flags found, but always stay cautious.")
            + SAFETY_FOOTER
        )
        return AssistantResponse(answer=answer, mode="rule_based_fallback", grounded_check={"type": "url", "result": result.__dict__})

    if len(question.split()) > 4:
        result = analyze_message(question)
        answer = (
            f"Based on the wording, this looks like {result.risk_level} risk ({result.risk_score}/100). "
            + ("Treat it with caution and don't share codes, passwords, or payments." if result.risk_level != "low" else "No strong scam indicators found, but stay cautious with unexpected messages.")
            + SAFETY_FOOTER
        )
        return AssistantResponse(answer=answer, mode="rule_based_fallback", grounded_check={"type": "message", "result": result.__dict__})

    answer = (
        "I can help explain suspicious links or messages, guide you through securing a hacked "
        "account, or point you to the right module (Password Health, Breach Checker, Incident "
        "Reporting). Paste a suspicious link or message, or ask a specific security question."
        + SAFETY_FOOTER
    )
    return AssistantResponse(answer=answer, mode="rule_based_fallback", grounded_check=None)


@router.post("/ask", response_model=AssistantResponse)
@limiter.limit("20/minute")
def ask_assistant(request: Request, payload: AssistantRequest):
    settings = get_settings()
    if not settings.AI_PROVIDER_API_KEY:
        return _rule_based_answer(payload.question)

    # Placeholder for a real provider integration. Kept deliberately explicit
    # rather than silently falling back, so a misconfiguration is visible.
    return AssistantResponse(
        answer="AI provider integration is configured but not yet implemented in this build.",
        mode="ai_provider",
    )
