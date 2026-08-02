"""Compliance & admin endpoints (GDPR/CCPA, audit trail)."""

from __future__ import annotations

import io
import json

from fastapi import APIRouter, Depends, Query, Response, status
from fastapi.responses import StreamingResponse
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
from app.core.exceptions import AuthorizationError
from app.models.organization import Role
from app.repositories import AuditRepository
from app.services.audit_service import AuditService
from app.services.compliance_service import ComplianceService

router = APIRouter(tags=["compliance"])


def _compliance(container: Container, session: AsyncSession) -> ComplianceService:
    return ComplianceService(session, container.settings, container.encryptor,
                             container.blob_store)


# --- Data portability (GDPR Art. 15 / CCPA) -------------------------------


@router.get("/me/export", dependencies=[Depends(rate_limit("export"))])
async def export_my_data(
    current: CurrentUser = Depends(get_current_user),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> StreamingResponse:
    archive = await _compliance(container, session).export_user_data(current.user_id)
    headers = {"Content-Disposition": 'attachment; filename="vaultnote-export.zip"'}
    return StreamingResponse(io.BytesIO(archive), media_type="application/zip",
                             headers=headers)


# --- Right to erasure (GDPR Art. 17) --------------------------------------


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT,
               dependencies=[Depends(rate_limit("write"))])
async def erase_my_account(
    current: CurrentUser = Depends(get_current_user),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> Response:
    # GDPR Art. 17 — cascading deletion of the requesting user and orphaned orgs.
    await _compliance(container, session).erase_user(current.user_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/organizations/{org_id}", status_code=status.HTTP_204_NO_CONTENT,
               dependencies=[Depends(rate_limit("write"))])
async def erase_organization(
    org_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> Response:
    # GDPR Art. 17 — owner-only full tenant erasure.
    await _compliance(container, session).erase_organization(org_id, ctx.user_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Audit trail (SOC 2) --------------------------------------------------


@router.get("/organizations/{org_id}/audit")
async def list_audit(
    org_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    ctx: TenantContext = Depends(get_tenant_context),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> list[dict]:
    if not Role(ctx.role).at_least(Role.ADMIN):
        raise AuthorizationError("audit access requires admin role")
    rows = await AuditRepository(session).list_for_org(org_id, limit, offset)
    # Entries are already PII-free; return them verbatim.
    return [
        {
            "id": r.id, "action": r.action, "actor": r.actor_pseudonym,
            "resource_type": r.resource_type, "resource_id": r.resource_id,
            "outcome": r.outcome, "context": json.loads(r.context),
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]


@router.get("/organizations/{org_id}/audit/verify")
async def verify_audit(
    org_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> dict:
    if not Role(ctx.role).at_least(Role.ADMIN):
        raise AuthorizationError("audit access requires admin role")
    ok = await AuditService(session, container.settings).verify_chain(org_id)
    return {"intact": ok}


# --- Retention purge (GDPR Art. 5(1)(e)) — owner triggered / job -----------


@router.post("/organizations/{org_id}/retention/purge",
             dependencies=[Depends(rate_limit("write"))])
async def purge_retention(
    org_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> dict:
    if not Role(ctx.role).at_least(Role.ADMIN):
        raise AuthorizationError("retention purge requires admin role")
    result = await _compliance(container, session).purge_expired()
    return result
