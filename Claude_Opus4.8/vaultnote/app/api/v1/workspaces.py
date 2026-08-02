"""Workspace (organization) and membership endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    CurrentUser,
    TenantContext,
    get_container,
    get_current_user,
    get_session,
    get_tenant_context,
    rate_limit,
)
from app.core.container import Container
from app.schemas import (
    ConsentOut,
    ConsentRequest,
    InviteRequest,
    MemberOut,
    OrganizationOut,
    RoleChangeRequest,
)
from app.services.compliance_service import ComplianceService
from app.services.workspace_service import WorkspaceService

router = APIRouter(tags=["workspaces"])


@router.get("/me/organizations", response_model=list[OrganizationOut])
async def my_orgs(
    current: CurrentUser = Depends(get_current_user),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> list[OrganizationOut]:
    svc = WorkspaceService(session, container.settings)
    return [
        OrganizationOut(id=org.id, name=org.name, plan=org.plan,
                        role=str(role), created_at=org.created_at)
        for org, role in await svc.list_my_orgs(current.user_id)
    ]


@router.get("/organizations/{org_id}/members", response_model=list[MemberOut])
async def list_members(
    org_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> list[MemberOut]:
    svc = WorkspaceService(session, container.settings)
    return [
        MemberOut(user_id=m.user_id, role=m.role, joined_at=m.created_at)
        for m in await svc.list_members(org_id, ctx.user_id)
    ]


@router.post("/organizations/{org_id}/members", response_model=MemberOut,
             status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(rate_limit("write"))])
async def invite_member(
    org_id: str,
    body: InviteRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> MemberOut:
    svc = WorkspaceService(session, container.settings)
    m = await svc.invite_member(org_id, ctx.user_id, email=body.email,
                                role=body.role)
    return MemberOut(user_id=m.user_id, role=m.role, joined_at=m.created_at)


@router.patch("/organizations/{org_id}/members/{user_id}",
              status_code=status.HTTP_204_NO_CONTENT,
              dependencies=[Depends(rate_limit("write"))])
async def change_role(
    org_id: str,
    user_id: str,
    body: RoleChangeRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> Response:
    svc = WorkspaceService(session, container.settings)
    await svc.change_role(org_id, ctx.user_id, user_id, body.role)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/organizations/{org_id}/members/{user_id}",
               status_code=status.HTTP_204_NO_CONTENT,
               dependencies=[Depends(rate_limit("write"))])
async def remove_member(
    org_id: str,
    user_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> Response:
    svc = WorkspaceService(session, container.settings)
    await svc.remove_member(org_id, ctx.user_id, user_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Consent (account-level, GDPR Art. 7) ---------------------------------


@router.put("/me/consents", response_model=ConsentOut)
async def set_consent(
    body: ConsentRequest,
    current: CurrentUser = Depends(get_current_user),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> ConsentOut:
    svc = ComplianceService(session, container.settings, container.encryptor,
                            container.blob_store)
    await svc.set_consent(current.user_id, body.consent_type, body.granted)
    consents = await svc.get_consents(current.user_id)
    granted, ts = consents[body.consent_type]
    from app.db.base import utcnow
    return ConsentOut(consent_type=body.consent_type, granted=granted,
                      updated_at=ts or utcnow())


@router.get("/me/consents", response_model=list[ConsentOut])
async def get_consents(
    current: CurrentUser = Depends(get_current_user),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> list[ConsentOut]:
    from app.db.base import utcnow
    svc = ComplianceService(session, container.settings, container.encryptor,
                            container.blob_store)
    consents = await svc.get_consents(current.user_id)
    return [
        ConsentOut(consent_type=ct, granted=granted, updated_at=ts or utcnow())
        for ct, (granted, ts) in consents.items()
    ]
