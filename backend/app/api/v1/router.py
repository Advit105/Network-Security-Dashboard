"""Aggregate all v1 routers.

Security decision: APIs are versioned under /api/v1 so breaking changes ship as
/api/v2 without silently altering existing clients' security assumptions.
"""
from fastapi import APIRouter

from app.api.v1 import auth, blocklist, proxy, users

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(blocklist.router)
api_router.include_router(proxy.router)
