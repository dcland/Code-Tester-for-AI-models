"""Workspace management endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import TenantContext, get_tenant_context
from app.models.database import get_db
from app.models.entities import Workspace
from app.repositories.repositories import WorkspaceRepository
from app.schemas.requests import WorkspaceCreate

router = APIRouter(prefix="/workspaces", tags=["workspaces"])


@router.post("", status_code=201)
async def create_workspace(
    body: WorkspaceCreate,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    ws = Workspace(organization_id=ctx.organization_id, name=body.name)
    await WorkspaceRepository(db).create(ws)
    return {"id": ws.id, "name": ws.name, "organization_id": ws.organization_id}


@router.get("")
async def list_workspaces(
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    workspaces = await WorkspaceRepository(db).list_by_org(ctx.organization_id)
    return [{"id": w.id, "name": w.name} for w in workspaces]
