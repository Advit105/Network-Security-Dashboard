"""Server-side proxy for third-party APIs that browsers cannot call directly.

AbuseIPDB's API sends no CORS headers, so the SPA can never query it from the
browser. The client sends its own user-provided key in X-Abuse-Key; we forward
the check server-side and relay the JSON. The key is never stored or logged.
The target host is fixed and the IP is validated, so this is not an open proxy.
"""
import ipaddress
from typing import Annotated

import httpx
from fastapi import APIRouter, Header, HTTPException, Request, status

from app.core.rate_limit import limiter

router = APIRouter(prefix="/proxy", tags=["proxy"])

ABUSEIPDB_LIMIT = "30/minute"


@router.get("/abuseipdb/check")
@limiter.limit(ABUSEIPDB_LIMIT)
async def abuseipdb_check(
    request: Request,
    ip: str,
    max_age: int = 90,
    x_abuse_key: Annotated[str | None, Header(alias="X-Abuse-Key")] = None,
) -> dict:
    if not x_abuse_key or len(x_abuse_key) < 10:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing AbuseIPDB API key")
    try:
        ip = str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid IP address")
    max_age = max(1, min(max_age, 365))

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": max_age, "verbose": ""},
                headers={"Key": x_abuse_key, "Accept": "application/json"},
            )
    except httpx.HTTPError:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Could not reach AbuseIPDB")

    if r.status_code in (401, 403):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="AbuseIPDB rejected the API key")
    if r.status_code == 429:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail="AbuseIPDB rate limit exceeded (free tier: 1,000 checks/day)")
    if r.status_code != 200:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"AbuseIPDB returned {r.status_code}")
    return r.json()
