"""Blocklist request/response schemas.

Security decisions
------------------
* Strict inputs (`extra="forbid"`) → mass-assignment safe; the client cannot set
  fields like id/user_id/created_at.
* The IP is validated server-side (never trust the client) using the stdlib
  ipaddress module, which accepts IPv4/IPv6 and rejects anything else.
"""
import ipaddress
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator

from app.models.blocklist import Severity


class BlocklistCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ip: str
    reason: str = ""
    severity: Severity = Severity.danger

    @field_validator("ip")
    @classmethod
    def _valid_ip(cls, v: str) -> str:
        v = v.strip()
        try:
            return str(ipaddress.ip_address(v))
        except ValueError as exc:
            raise ValueError("must be a valid IPv4 or IPv6 address") from exc

    @field_validator("reason")
    @classmethod
    def _trim_reason(cls, v: str) -> str:
        return v.strip()[:300]


class BlocklistOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    ip: str
    reason: str
    severity: Severity
    created_at: datetime
