"""Rate limiting.

Security decision: every endpoint is rate-limited to blunt brute-force and
credential-stuffing. Auth endpoints get the tightest limits. The limiter keys on
client IP (see key_func) and, on production, should use a shared Redis store so
limits hold across multiple workers/instances (set RATE_LIMIT_STORAGE_URI).
"""
from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request

from app.config import get_settings

settings = get_settings()


def client_ip(request: Request) -> str:
    """Prefer the left-most X-Forwarded-For hop when behind a trusted proxy.
    NOTE: only trust XFF if your ingress strips/normalizes it; otherwise clients
    can spoof it. Defaults to the socket peer address."""
    if settings.is_production:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    return get_remote_address(request)


limiter = Limiter(
    key_func=client_ip,
    storage_uri=settings.rate_limit_storage_uri,
    enabled=settings.rate_limit_enabled,
)

# Named limits reused across auth routes.
LOGIN_LIMIT = "10/minute"
REGISTER_LIMIT = "5/minute"
RESET_REQUEST_LIMIT = "5/minute"
MFA_VERIFY_LIMIT = "10/minute"
