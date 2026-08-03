"""Notes, folders, sharing, and collaboration endpoints."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import TenantContext, get_tenant_context
from app.core.compliance import AuditLog
from app.core.privacy import pseudonymize
from app.core.security import generate_secure_token, hash_password, hash_token
from app.models.database import get_db
from app.models.entities import Permission, ShareGrant, ShareLink
from app.repositories.repositories import ShareGrantRepository, ShareLinkRepository
from app.schemas.requests import (
    FolderCreate, NoteCreate, NoteUpdate, OperationSubmit, PresenceUpdate,
    ShareGrantCreate, ShareLinkCreate,
)
from app.services.collab_service import CollabService
from app.services.note_service import NoteService
from app.utils.exceptions import NotFoundError, ValidationError

router = APIRouter(prefix="/workspaces/{workspace_id}", tags=["notes"])


# ---- Notes ---------------------------------------------------------------

@router.post("/notes", status_code=201)
async def create_note(
    workspace_id: str, body: NoteCreate,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    svc = NoteService(db)
    note = await svc.create_note(ctx.organization_id, workspace_id, ctx.user.id,
                                 body.title, body.content, body.folder_id)
    AuditLog.record("note_created", actor_id=pseudonymize(ctx.user.id),
                    tenant_id=ctx.organization_id, resource_type="note", resource_id=note.id)
    return {"id": note.id}


@router.get("/notes")
async def list_notes(
    workspace_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    svc = NoteService(db)
    return await svc.list_notes(ctx.organization_id, workspace_id)


@router.get("/notes/{note_id}")
async def get_note(
    workspace_id: str, note_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    svc = NoteService(db)
    return await svc.get_note(ctx.organization_id, note_id)


@router.patch("/notes/{note_id}")
async def update_note(
    workspace_id: str, note_id: str, body: NoteUpdate,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    svc = NoteService(db)
    return await svc.update_note(ctx.organization_id, note_id, body.title, body.content)


@router.delete("/notes/{note_id}", status_code=204)
async def delete_note(
    workspace_id: str, note_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> None:
    svc = NoteService(db)
    await svc.delete_note(ctx.organization_id, note_id)
    AuditLog.record("note_deleted", actor_id=pseudonymize(ctx.user.id),
                    tenant_id=ctx.organization_id, resource_type="note", resource_id=note_id)


# ---- Folders --------------------------------------------------------------

@router.post("/folders", status_code=201)
async def create_folder(
    workspace_id: str, body: FolderCreate,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    svc = NoteService(db)
    folder = await svc.create_folder(ctx.organization_id, workspace_id, body.name, body.parent_id)
    return {"id": folder.id}


@router.get("/folders")
async def list_folders(
    workspace_id: str, parent_id: str | None = None,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    svc = NoteService(db)
    return await svc.list_folders(ctx.organization_id, workspace_id, parent_id)


# ---- Sharing ---------------------------------------------------------------

@router.post("/notes/{note_id}/share", status_code=201)
async def share_note(
    workspace_id: str, note_id: str, body: ShareGrantCreate,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    grant = ShareGrant(
        organization_id=ctx.organization_id, resource_type="note", resource_id=note_id,
        grantee_user_id=body.grantee_user_id, permission=Permission(body.permission),
        created_by=ctx.user.id,
    )
    await ShareGrantRepository(db).create(grant)
    AuditLog.record("note_shared", actor_id=pseudonymize(ctx.user.id),
                    tenant_id=ctx.organization_id, resource_type="note", resource_id=note_id,
                    metadata={"permission": body.permission})
    return {"id": grant.id}


@router.post("/notes/{note_id}/share-link", status_code=201)
async def create_share_link(
    workspace_id: str, note_id: str, body: ShareLinkCreate,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    token = generate_secure_token(32)
    expires_at = None
    if body.expires_in_hours:
        expires_at = datetime.now(timezone.utc) + timedelta(hours=body.expires_in_hours)
    link = ShareLink(
        organization_id=ctx.organization_id, resource_type="note", resource_id=note_id,
        token_hash=hash_token(token),
        password_hash=hash_password(body.password) if body.password else None,
        permission=Permission(body.permission), expires_at=expires_at, created_by=ctx.user.id,
    )
    await ShareLinkRepository(db).create(link)
    return {"share_url": f"/shared/{token}", "token": token}


# ---- Collaboration ---------------------------------------------------------

@router.post("/notes/{note_id}/operations", status_code=201)
async def submit_operation(
    workspace_id: str, note_id: str, body: OperationSubmit,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    svc = CollabService(db)
    return await svc.submit_operation(ctx.organization_id, note_id, ctx.user.id,
                                      body.op_type, body.position, body.content)


@router.get("/notes/{note_id}/operations")
async def get_operations(
    workspace_id: str, note_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    svc = CollabService(db)
    return await svc.get_operations(ctx.organization_id, note_id)


@router.post("/notes/{note_id}/presence", status_code=200)
async def update_presence(
    workspace_id: str, note_id: str, body: PresenceUpdate,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    svc = CollabService(db)
    await svc.update_presence(note_id, ctx.user.id, body.cursor_position)
    return {"ok": True}


@router.get("/notes/{note_id}/presence")
async def get_presence(
    workspace_id: str, note_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    svc = CollabService(db)
    return await svc.get_presence(note_id)
