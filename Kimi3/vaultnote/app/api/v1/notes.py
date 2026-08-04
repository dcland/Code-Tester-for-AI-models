"""Notes, folders, sharing, and collaboration endpoints.

Authorization model (enforced centrally via AccessService):
  * every route binds ``{workspace_id}`` to the active tenant (404 otherwise),
  * note reads require >= read, updates >= write, delete/share >= admin,
  * share grants may only target members of the SAME organization,
  * VIEWERs can never write, even with a grant (role ceiling).
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import WorkspaceContext, get_workspace_context
from app.core.compliance import AuditLog
from app.core.privacy import pseudonymize
from app.core.security import generate_secure_token, hash_password, hash_token
from app.models.database import get_db
from app.models.entities import Permission, Role, ShareGrant, ShareLink
from app.repositories.repositories import ShareGrantRepository, ShareLinkRepository
from app.schemas.requests import (
    FolderCreate,
    NoteCreate,
    NoteUpdate,
    OperationSubmit,
    PresenceUpdate,
    ShareGrantCreate,
    ShareLinkCreate,
)
from app.services.access_service import AccessService
from app.services.collab_service import CollabService
from app.services.note_service import NoteService
from app.utils.exceptions import AuthorizationError

router = APIRouter(prefix="/workspaces/{workspace_id}", tags=["notes"])


def _require_not_viewer(wctx: WorkspaceContext) -> None:
    """Role ceiling: viewers are read-only within a workspace."""
    if wctx.role is Role.VIEWER:
        raise AuthorizationError("Viewers have read-only access")


# ---- Notes ---------------------------------------------------------------

@router.post("/notes", status_code=201)
async def create_note(
    body: NoteCreate,
    wctx: WorkspaceContext = Depends(get_workspace_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    _require_not_viewer(wctx)
    if body.folder_id is not None:
        await AccessService(db).get_folder(wctx.organization_id, body.folder_id)
    svc = NoteService(db)
    note = await svc.create_note(wctx.organization_id, wctx.workspace.id, wctx.user.id,
                                 body.title, body.content, body.folder_id)
    await AuditLog.record(db, "note_created", actor_id=pseudonymize(wctx.user.id),
                          tenant_id=wctx.organization_id, resource_type="note", resource_id=note.id)
    return {"id": note.id}


@router.get("/notes")
async def list_notes(
    wctx: WorkspaceContext = Depends(get_workspace_context),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """List only the notes the caller is allowed to read."""
    svc = NoteService(db)
    return await svc.list_accessible_notes(wctx.organization_id, wctx.workspace.id, wctx.user.id)


@router.get("/notes/{note_id}")
async def get_note(
    note_id: str,
    wctx: WorkspaceContext = Depends(get_workspace_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    access = AccessService(db)
    note = await access.get_note(wctx.organization_id, note_id)
    await access.require_note(wctx.organization_id, wctx.user.id, note, Permission.READ)
    svc = NoteService(db)
    return await svc.get_note(wctx.organization_id, note_id)


@router.patch("/notes/{note_id}")
async def update_note(
    note_id: str, body: NoteUpdate,
    wctx: WorkspaceContext = Depends(get_workspace_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    access = AccessService(db)
    note = await access.get_note(wctx.organization_id, note_id)
    await access.require_note(wctx.organization_id, wctx.user.id, note, Permission.WRITE)
    svc = NoteService(db)
    return await svc.update_note(wctx.organization_id, note_id, body.title, body.content)


@router.delete("/notes/{note_id}", status_code=204)
async def delete_note(
    note_id: str,
    wctx: WorkspaceContext = Depends(get_workspace_context),
    db: AsyncSession = Depends(get_db),
) -> Response:
    access = AccessService(db)
    note = await access.get_note(wctx.organization_id, note_id)
    await access.require_note(wctx.organization_id, wctx.user.id, note, Permission.ADMIN)
    svc = NoteService(db)
    await svc.delete_note(wctx.organization_id, note_id)
    await AuditLog.record(db, "note_deleted", actor_id=pseudonymize(wctx.user.id),
                          tenant_id=wctx.organization_id, resource_type="note", resource_id=note_id)
    # 204 responses must not carry a body - return an explicit empty Response.
    return Response(status_code=204)


# ---- Folders --------------------------------------------------------------

@router.post("/folders", status_code=201)
async def create_folder(
    body: FolderCreate,
    wctx: WorkspaceContext = Depends(get_workspace_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    _require_not_viewer(wctx)
    if body.parent_id is not None:
        await AccessService(db).get_folder(wctx.organization_id, body.parent_id)
    svc = NoteService(db)
    folder = await svc.create_folder(wctx.organization_id, wctx.workspace.id, body.name, body.parent_id)
    return {"id": folder.id}


@router.get("/folders")
async def list_folders(
    parent_id: str | None = None,
    wctx: WorkspaceContext = Depends(get_workspace_context),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    svc = NoteService(db)
    return await svc.list_folders(wctx.organization_id, wctx.workspace.id, parent_id)


# ---- Sharing ---------------------------------------------------------------

@router.post("/notes/{note_id}/share", status_code=201)
async def share_note(
    note_id: str, body: ShareGrantCreate,
    wctx: WorkspaceContext = Depends(get_workspace_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Share a note with another member of the SAME organization.

    Requires admin permission on the note (owner, org admin, or admin
    grant). The grantee's membership in this organization is verified -
    cross-tenant grants are rejected.
    """
    access = AccessService(db)
    note = await access.get_note(wctx.organization_id, note_id)
    await access.require_note(wctx.organization_id, wctx.user.id, note, Permission.ADMIN)
    await access.require_grantee_member(wctx.organization_id, body.grantee_user_id)

    grant = ShareGrant(
        organization_id=wctx.organization_id, resource_type="note", resource_id=note.id,
        grantee_user_id=body.grantee_user_id, permission=Permission(body.permission),
        created_by=wctx.user.id,
    )
    await ShareGrantRepository(db).create(grant)
    await AuditLog.record(db, "note_shared", actor_id=pseudonymize(wctx.user.id),
                          tenant_id=wctx.organization_id, resource_type="note", resource_id=note.id,
                          metadata={"permission": body.permission})
    return {"id": grant.id}


@router.post("/notes/{note_id}/share-link", status_code=201)
async def create_share_link(
    note_id: str, body: ShareLinkCreate,
    wctx: WorkspaceContext = Depends(get_workspace_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    access = AccessService(db)
    note = await access.get_note(wctx.organization_id, note_id)
    await access.require_note(wctx.organization_id, wctx.user.id, note, Permission.ADMIN)

    token = generate_secure_token(32)
    expires_at = None
    if body.expires_in_hours:
        expires_at = datetime.now(UTC) + timedelta(hours=body.expires_in_hours)
    link = ShareLink(
        organization_id=wctx.organization_id, resource_type="note", resource_id=note.id,
        token_hash=hash_token(token),
        password_hash=hash_password(body.password) if body.password else None,
        permission=Permission(body.permission), expires_at=expires_at, created_by=wctx.user.id,
    )
    await ShareLinkRepository(db).create(link)
    return {"share_url": f"/shared/{token}", "token": token}


# ---- Collaboration ---------------------------------------------------------

@router.post("/notes/{note_id}/operations", status_code=201)
async def submit_operation(
    note_id: str, body: OperationSubmit,
    wctx: WorkspaceContext = Depends(get_workspace_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    access = AccessService(db)
    note = await access.get_note(wctx.organization_id, note_id)
    await access.require_note(wctx.organization_id, wctx.user.id, note, Permission.WRITE)
    svc = CollabService(db)
    return await svc.submit_operation(wctx.organization_id, note_id, wctx.user.id,
                                      body.op_type, body.position, body.content)


@router.get("/notes/{note_id}/operations")
async def get_operations(
    note_id: str,
    wctx: WorkspaceContext = Depends(get_workspace_context),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    access = AccessService(db)
    note = await access.get_note(wctx.organization_id, note_id)
    await access.require_note(wctx.organization_id, wctx.user.id, note, Permission.READ)
    svc = CollabService(db)
    return await svc.get_operations(wctx.organization_id, note_id)


@router.post("/notes/{note_id}/presence", status_code=200)
async def update_presence(
    note_id: str, body: PresenceUpdate,
    wctx: WorkspaceContext = Depends(get_workspace_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    access = AccessService(db)
    note = await access.get_note(wctx.organization_id, note_id)
    await access.require_note(wctx.organization_id, wctx.user.id, note, Permission.READ)
    svc = CollabService(db)
    await svc.update_presence(wctx.organization_id, note_id, wctx.user.id, body.cursor_position)
    return {"ok": True}


@router.get("/notes/{note_id}/presence")
async def get_presence(
    note_id: str,
    wctx: WorkspaceContext = Depends(get_workspace_context),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    access = AccessService(db)
    note = await access.get_note(wctx.organization_id, note_id)
    await access.require_note(wctx.organization_id, wctx.user.id, note, Permission.READ)
    svc = CollabService(db)
    return await svc.get_presence(wctx.organization_id, note_id)
