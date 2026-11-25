from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api.routes import admin, ai_assistant, alerts, auth, dashboard, incidents, message_checker, oauth, security_checks, url_checker
from app.config import get_settings
from app.core.rate_limit import limiter

settings = get_settings()

app = FastAPI(
    title=settings.APP_NAME,
    version="0.1.0-mvp",
    description="Personal Digital Security Center — API",
    docs_url="/api/docs" if settings.ENVIRONMENT != "production" else None,
    redoc_url=None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    if settings.ENVIRONMENT == "production":
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


@app.get("/api/health", tags=["health"])
def health_check():
    return {"status": "ok", "service": settings.APP_NAME, "environment": settings.ENVIRONMENT}


api_prefix = settings.API_V1_PREFIX
app.include_router(auth.router, prefix=api_prefix)
app.include_router(dashboard.router, prefix=api_prefix)
app.include_router(url_checker.router, prefix=api_prefix)
app.include_router(message_checker.router, prefix=api_prefix)
app.include_router(security_checks.router, prefix=api_prefix)
app.include_router(alerts.router, prefix=api_prefix)
app.include_router(incidents.router, prefix=api_prefix)
app.include_router(ai_assistant.router, prefix=api_prefix)
app.include_router(admin.router, prefix=api_prefix)
app.include_router(oauth.router, prefix=api_prefix)
