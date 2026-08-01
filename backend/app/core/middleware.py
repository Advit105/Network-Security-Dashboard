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

Implemented as pure ASGI (not BaseHTTPMiddleware) — headers are injected into the
response-start message directly, avoiding BaseHTTPMiddleware's per-request task
group and response re-streaming overhead.
"""
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.config import get_settings

settings = get_settings()

_CSP = (
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                h = MutableHeaders(scope=message)
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
                del h["server"]
            await send(message)

        await self.app(scope, receive, send_wrapper)
