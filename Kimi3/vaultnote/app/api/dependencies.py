"""
Shared FastAPI dependencies: auth, tenant resolution, role checks,
workspace binding.
"""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, Header
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decode_token
from app.models.database import get_db
from app.models.entities import Role, Workspace
from app.repositories.repositories import (
    MembershipRepository,
    UserRepository,
    WorkspaceRepository,
)
from app.utils.exceptions import (
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    TenantIsolationError,
)


@dataclass
class CurrentUser:
    id: str
    email: str


@dataclass
class TenantContext:
    user: CurrentUser
    organization_id: str
    role: Role


@dataclass
class WorkspaceContext:
    """Tenant context plus a workspace that is verified to belong to it."""
    user: CurrentUser
    organization_id: str
    role: Role
    workspace: Workspace


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


async def get_workspace_context(
    workspace_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> WorkspaceContext:
    """Bind the ``{workspace_id}`` path parameter to the active tenant.

    A workspace ID from another organization is indistinguishable from a
    non-existent one (404), so tenants cannot probe or touch foreign
    workspaces by guessing IDs.
    """
    workspace = await WorkspaceRepository(db).get_by_id(workspace_id)
    if workspace is None or workspace.organization_id != ctx.organization_id:
        raise NotFoundError("Workspace not found")
    return WorkspaceContext(
        user=ctx.user, organization_id=ctx.organization_id,
        role=ctx.role, workspace=workspace,
    )


def require_role(*allowed: Role):
    """Role-based access control dependency factory."""
    async def checker(ctx: TenantContext = Depends(get_tenant_context)) -> TenantContext:
        if ctx.role not in allowed:
            raise AuthorizationError(f"Requires role: {', '.join(r.value for r in allowed)}")
        return ctx
    return checker
