"""User management schemas (admin surface).

Security decision: role changes go through a dedicated admin-only schema. Regular
users have no endpoint that accepts a role field, so privilege escalation is not
reachable from the normal update path.
"""
from pydantic import BaseModel, ConfigDict

from app.models.user import Role


class RoleUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Role
