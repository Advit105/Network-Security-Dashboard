"""Security-headers middleware.

Security decisions (defence-in-depth HTTP headers)
--------------------------------------------------
* Content-Security-Policy: locks the response to same-origin by default. This API
  serves JSON, so a very strict policy is safe and blocks any injected content
  from loading external resources.
* Strict-Transport-Security: forces HTTPS for a year (prod only, once you serve
  over TLS) — defeats SSL-strip downgrade attacks.
* X-Frame-Options: DENY + frame-ancestors 'none' → clickjacking protection.
* X-Content-Type-Options: nosniff → browsers won't MIME-sniff responses.
* Referrer-Policy / Permissions-Policy: minimize metadata leakage and disable
  unused browser features.
* Server header is stripped so we don't advertise the stack/version.
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.config import get_settings

settings = get_settings()

_CSP = (
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        h = response.headers
        h["Content-Security-Policy"] = _CSP
        h["X-Frame-Options"] = "DENY"
        h["X-Content-Type-Options"] = "nosniff"
        h["Referrer-Policy"] = "no-referrer"
        h["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        h["Cache-Control"] = "no-store"
        if settings.is_production:
            h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        # Best-effort strip of any Server header set at the app layer. NOTE: uvicorn
        # adds its own Server header AFTER middleware runs, so also start the server
        # with --no-server-header (or server_header=False) to remove it in prod.
        if "server" in h:
            del h["server"]
        return response
