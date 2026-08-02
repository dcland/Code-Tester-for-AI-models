"""Notes, folders, sharing, and collaboration endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    TenantContext,
    get_container,
    get_session,
    get_tenant_context,
    rate_limit,
)
from app.core.container import Container
from app.core.exceptions import NotFoundError
from app.schemas import (
    FolderCreate,
    FolderOut,
    NoteCreate,
    NoteOperation,
    NoteOut,
    NoteSummary,
    NoteUpdate,
    PresenceOut,
    ShareCreate,
    ShareLinkAccess,
    ShareLinkCreate,
    ShareLinkOut,
)
from app.services.note_service import NoteService
from app.services.sharing_service import SharingService

router = APIRouter(prefix="/organizations/{org_id}", tags=["notes"])


def _notes(container: Container, session: AsyncSession) -> NoteService:
    return NoteService(session, container.settings, container.encryptor,
                       container.note_cache)


def _sharing(container: Container, session: AsyncSession) -> SharingService:
    return SharingService(session, container.settings, container.security)


# --- Folders ---------------------------------------------------------------


@router.post("/folders", response_model=FolderOut,
             status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(rate_limit("write"))])
async def create_folder(
    org_id: str,
    body: FolderCreate,
    ctx: TenantContext = Depends(get_tenant_context),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> FolderOut:
    folder = await _notes(container, session).create_folder(
        org_id, ctx.user_id, name=body.name, parent_id=body.parent_id
    )
    return FolderOut(id=folder.id, name=body.name, parent_id=folder.parent_id,
                     created_at=folder.created_at)


@router.get("/folders", response_model=list[FolderOut])
async def list_folders(
    org_id: str,
    parent_id: str | None = Query(default=None),
    ctx: TenantContext = Depends(get_tenant_context),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> list[FolderOut]:
    folders = await _notes(container, session).list_folders(
        org_id, ctx.user_id, parent_id
    )
    return [
        FolderOut(id=f.id, name=name, parent_id=f.parent_id, created_at=f.created_at)
        for f, name in folders
    ]


# --- Notes -----------------------------------------------------------------


@router.post("/notes", response_model=NoteOut, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(rate_limit("write"))])
async def create_note(
    org_id: str,
    body: NoteCreate,
    ctx: TenantContext = Depends(get_tenant_context),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> NoteOut:
    n = await _notes(container, session).create_note(
        org_id, ctx.user_id, title=body.title, body=body.body,
        folder_id=body.folder_id,
    )
    return _note_out(n)


@router.get("/notes", response_model=list[NoteSummary],
            dependencies=[Depends(rate_limit("read"))])
async def list_notes(
    org_id: str,
    folder_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ctx: TenantContext = Depends(get_tenant_context),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> list[NoteSummary]:
    rows = await _notes(container, session).list_notes(
        org_id, ctx.user_id, folder_id=folder_id, limit=limit, offset=offset
    )
    return [
        NoteSummary(id=n.id, title=title, folder_id=n.folder_id,
                    version=n.version, updated_at=n.updated_at)
        for n, title in rows
    ]


@router.get("/notes/{note_id}", response_model=NoteOut,
            dependencies=[Depends(rate_limit("read"))])
async def get_note(
    org_id: str,
    note_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> NoteOut:
    return _note_out(
        await _notes(container, session).get_note(org_id, ctx.user_id, note_id)
    )


@router.patch("/notes/{note_id}", response_model=NoteOut,
              dependencies=[Depends(rate_limit("write"))])
async def update_note(
    org_id: str,
    note_id: str,
    body: NoteUpdate,
    ctx: TenantContext = Depends(get_tenant_context),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> NoteOut:
    return _note_out(
        await _notes(container, session).update_note(
            org_id, ctx.user_id, note_id, title=body.title, body=body.body,
            expected_version=body.expected_version,
        )
    )


@router.delete("/notes/{note_id}", status_code=status.HTTP_204_NO_CONTENT,
               dependencies=[Depends(rate_limit("write"))])
async def delete_note(
    org_id: str,
    note_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> Response:
    await _notes(container, session).delete_note(org_id, ctx.user_id, note_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Sharing ---------------------------------------------------------------


@router.post("/notes/{note_id}/shares", status_code=status.HTTP_204_NO_CONTENT,
             dependencies=[Depends(rate_limit("write"))])
async def share_note(
    org_id: str,
    note_id: str,
    body: ShareCreate,
    ctx: TenantContext = Depends(get_tenant_context),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> Response:
    await _sharing(container, session).share_note_with_user(
        org_id, ctx.user_id, note_id, body.grantee_user_id, body.permission
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/notes/{note_id}/share-links", response_model=ShareLinkOut,
             status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(rate_limit("write"))])
async def create_share_link(
    org_id: str,
    note_id: str,
    body: ShareLinkCreate,
    ctx: TenantContext = Depends(get_tenant_context),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> ShareLinkOut:
    issued = await _sharing(container, session).create_share_link(
        org_id, ctx.user_id, note_id, permission=body.permission,
        password=body.password, expires_in_seconds=body.expires_in_seconds,
    )
    return ShareLinkOut(url_token=issued.token, permission=issued.permission,
                        expires_at=issued.expires_at)


# --- Collaboration (presence + simplified OT) ------------------------------


@router.post("/notes/{note_id}/presence", response_model=PresenceOut,
             dependencies=[Depends(rate_limit("read"))])
async def heartbeat_presence(
    org_id: str,
    note_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> PresenceOut:
    # Ensure the caller can at least read the note before registering presence.
    await _notes(container, session).get_note(org_id, ctx.user_id, note_id)
    container.collab.heartbeat(note_id, ctx.user_id)
    return PresenceOut(note_id=note_id,
                       active_user_ids=container.collab.active_users(note_id))


@router.post("/notes/{note_id}/operations", response_model=NoteOut,
             dependencies=[Depends(rate_limit("write"))])
async def apply_operation(
    org_id: str,
    note_id: str,
    op: NoteOperation,
    ctx: TenantContext = Depends(get_tenant_context),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> NoteOut:
    notes = _notes(container, session)
    current = await notes.get_note(org_id, ctx.user_id, note_id)
    transformed = container.collab.transform(note_id, current.version, op)
    new_body = container.collab.apply(current.body, transformed)
    updated = await notes.update_note(
        org_id, ctx.user_id, note_id, title=None, body=new_body,
        expected_version=None,
    )
    container.collab.record(note_id, transformed)
    container.collab.heartbeat(note_id, ctx.user_id)
    return _note_out(updated)


def _note_out(n) -> NoteOut:
    return NoteOut(id=n.id, title=n.title, body=n.body, folder_id=n.folder_id,
                   owner_id=n.owner_id, version=n.version,
                   created_at=n.created_at, updated_at=n.updated_at)


# --- Public share-link access (unauthenticated) ----------------------------
# Mounted without the tenant prefix; access is gated only by the opaque token
# (and optional link password), never by a session.
public_router = APIRouter(prefix="/shared", tags=["sharing"])


@public_router.post("/{token}", response_model=NoteOut,
                    dependencies=[Depends(rate_limit("read"))])
async def access_shared_note(
    token: str,
    body: ShareLinkAccess,
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> NoteOut:
    sharing = _sharing(container, session)
    org_id, resource_type, resource_id = await sharing.resolve_share_link(
        token, body.password
    )
    if resource_type != "note":
        raise NotFoundError("shared resource is not a note")
    # Read the note directly (link grants access; bypasses membership check).
    from app.repositories import NoteRepository, OrganizationRepository
    note = await NoteRepository(session).get(org_id, resource_id)
    if note is None:
        raise NotFoundError("shared note not found")
    org = await OrganizationRepository(session).get(org_id)
    from app.services.note_service import _note_aad
    title_b, body_b = container.encryptor.decrypt_many(
        org.wrapped_master_key, note.wrapped_dek,
        [note.title_ciphertext, note.body_ciphertext], _note_aad(org_id, note.id),
    )
    return NoteOut(id=note.id, title=title_b.decode(), body=body_b.decode(),
                   folder_id=note.folder_id, owner_id=note.owner_id,
                   version=note.version, created_at=note.created_at,
                   updated_at=note.updated_at)
