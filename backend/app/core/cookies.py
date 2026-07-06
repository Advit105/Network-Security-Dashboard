"""Cookie helpers.

Security decisions
------------------
* access_token / refresh_token cookies are HttpOnly (JS can't read them → XSS
  can't steal them), Secure (HTTPS-only in prod), SameSite=Strict (not sent on
  cross-site requests → strong CSRF defence).
* The refresh cookie is scoped to the refresh path so it isn't sent on every
  request, shrinking its exposure.
* csrf_token is a NON-HttpOnly cookie (JS must read it to echo it back in a
  header) — the double-submit-cookie pattern. It is SameSite=Strict too.
"""
from starlette.responses import Response

from app.config import get_settings

settings = get_settings()

ACCESS_COOKIE = "access_token"
REFRESH_COOKIE = "refresh_token"
CSRF_COOKIE = "csrf_token"
REFRESH_PATH = f"{settings.api_v1_prefix}/auth"


# SameSite is configurable: "strict" for same-site deploys; "none" (with Secure)
# is required when the SPA and API live on different registrable domains.
_SAMESITE = settings.cookie_samesite.lower()


def _common(secure: bool, httponly: bool = True) -> dict:
    kw = {"secure": secure, "samesite": _SAMESITE, "httponly": httponly}
    if settings.cookie_domain:
        kw["domain"] = settings.cookie_domain
    return kw


def set_auth_cookies(resp: Response, *, access_token: str, refresh_token: str, csrf_token: str) -> None:
    secure = settings.cookie_secure
    resp.set_cookie(
        ACCESS_COOKIE, access_token, max_age=settings.access_token_ttl_seconds, path="/", **_common(secure)
    )
    resp.set_cookie(
        REFRESH_COOKIE,
        refresh_token,
        max_age=settings.refresh_token_ttl_seconds,
        path=REFRESH_PATH,
        **_common(secure),
    )
    # CSRF token cookie is NOT HttpOnly so a same-origin SPA could read it; a
    # cross-origin SPA instead receives the value from GET /auth/session.
    resp.set_cookie(
        CSRF_COOKIE, csrf_token, max_age=settings.refresh_token_ttl_seconds, path="/",
        **_common(secure, httponly=False),
    )


def clear_auth_cookies(resp: Response) -> None:
    for name, path in ((ACCESS_COOKIE, "/"), (REFRESH_COOKIE, REFRESH_PATH), (CSRF_COOKIE, "/")):
        resp.delete_cookie(name, path=path, domain=settings.cookie_domain or None)
