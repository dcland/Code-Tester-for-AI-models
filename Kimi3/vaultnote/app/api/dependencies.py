"""
Shared FastAPI dependencies: auth, tenant resolution, role checks.
"""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, Header
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decode_token
from app.models.database import get_db
from app.models.entities import Role
from app.repositories.repositories import MembershipRepository, UserRepository
from app.utils.exceptions import AuthenticationError, AuthorizationError, TenantIsolationError


@dataclass
class CurrentUser:
    id: str
    email: str


@dataclass
class TenantContext:
    user: CurrentUser
    organization_id: str
    role: Role


async def get_current_user(
    authorization: str = Header(...),
    db: AsyncSession = Depends(get_db),
) -> CurrentUser:
    """Extract and validate the JWT bearer token."""
    if not authorization.startswith("Bearer "):
        raise AuthenticationError("Invalid authorization header")
    token = authorization.removeprefix("Bearer ").strip()
    payload = decode_token(token)
    if payload is None or payload.get("type") != "access":
        raise AuthenticationError("Invalid or expired token")
    user_id = payload.get("sub")
    if not user_id:
        raise AuthenticationError("Invalid token claims")

    user = await UserRepository(db).get_by_id(user_id)
    if user is None or not user.is_active or user.deleted_at is not None:
        raise AuthenticationError("User not found or inactive")
    return CurrentUser(id=user.id, email=user.email)


async def get_tenant_context(
    x_organization_id: str = Header(..., alias="X-Organization-ID"),
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TenantContext:
    """Resolve tenant and enforce membership (multi-tenant isolation).

    Raises TenantIsolationError if the user is not a member of the requested org.
    """
    membership = await MembershipRepository(db).get_membership(user.id, x_organization_id)
    if membership is None:
        raise TenantIsolationError()
    return TenantContext(user=user, organization_id=x_organization_id, role=membership.role)


def require_role(*allowed: Role):
    """Role-based access control dependency factory."""
    async def checker(ctx: TenantContext = Depends(get_tenant_context)) -> TenantContext:
        if ctx.role not in allowed:
            raise AuthorizationError(f"Requires role: {', '.join(r.value for r in allowed)}")
        return ctx
    return checker
