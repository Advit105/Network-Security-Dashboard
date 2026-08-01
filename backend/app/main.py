"""Application entry point.

Security decisions
------------------
* A generic exception handler ensures stack traces / internal errors are NEVER
  returned to the client — details are logged server-side, the client sees a
  neutral message. Prevents information disclosure.
* CORS is restricted to an explicit allow-list of origins with credentials
  enabled — never "*" together with credentials (the browser forbids it, and it
  would be unsafe for cookie auth anyway).
* Rate limiting is wired in globally via slowapi.
* API docs are disabled in production to reduce surface / info leakage.
"""
import logging

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api.v1.router import api_router
from app.config import get_settings
from app.core.middleware import SecurityHeadersMiddleware
from app.core.rate_limit import limiter

settings = get_settings()
logger = logging.getLogger("sentinelx")

app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None,
    openapi_url=None if settings.is_production else "/openapi.json",
)

# Rate limiter (slowapi wires state + a 429 handler).
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Middleware order matters: security headers wrap everything.
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,   # explicit origins only
    allow_credentials=True,                    # cookies
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-CSRF-Token", "X-Abuse-Key"],
    max_age=600,
)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    # Log the real error server-side; return a neutral message to the client.
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )


@app.get("/health", tags=["meta"])
async def health() -> dict[str, str]:
    return {"status": "ok"}


app.include_router(api_router, prefix=settings.api_v1_prefix)
