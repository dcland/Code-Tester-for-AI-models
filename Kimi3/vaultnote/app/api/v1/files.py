"""File upload/download endpoints.

Uploads use a raw binary request body (no multipart form parsing), so the
application has no dependency on python-multipart. The filename travels in
the ``X-File-Name`` header and the declared content type in the standard
``Content-Type`` header; the service validates it against the actual magic
bytes. The body is read asynchronously in chunks with a hard size cap, and
all disk I/O happens off the event loop.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import WorkspaceContext, get_workspace_context
from app.core.compliance import AuditLog
from app.core.config import settings
from app.core.privacy import pseudonymize
from app.models.database import get_db
from app.models.entities import Role
from app.services.file_service import FileService
from app.utils.exceptions import AuthorizationError, ValidationError

router = APIRouter(prefix="/workspaces/{workspace_id}/files", tags=["files"])

_CHUNK_SIZE = 1024 * 1024  # 1 MiB


def _require_not_viewer(wctx: WorkspaceContext) -> None:
    if wctx.role is Role.VIEWER:
        raise AuthorizationError("Viewers have read-only access")


async def _read_body_capped(request: Request) -> bytes:
    """Read the request body in chunks, aborting early if it exceeds the cap."""
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > settings.MAX_FILE_SIZE_BYTES:
            raise ValidationError("File too large")
        chunks.append(chunk)
    return b"".join(chunks)


@router.post("", status_code=201)
async def upload_file(
    request: Request,
    wctx: WorkspaceContext = Depends(get_workspace_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    _require_not_viewer(wctx)
    filename = request.headers.get("X-File-Name", "file")
    declared_mime = request.headers.get("Content-Type")
    data = await _read_body_capped(request)
    svc = FileService(db)
    asset = await svc.upload_file(wctx.organization_id, wctx.workspace.id, wctx.user.id,
                                  filename, data, declared_mime=declared_mime)
    await AuditLog.record(db, "file_uploaded", actor_id=pseudonymize(wctx.user.id),
                          tenant_id=wctx.organization_id, resource_type="file", resource_id=asset.id,
                          metadata={"size_bytes": asset.size_bytes})
    return {"id": asset.id, "size_bytes": asset.size_bytes, "mime_type": asset.mime_type}


@router.get("/{file_id}")
async def get_file_metadata(
    file_id: str,
    wctx: WorkspaceContext = Depends(get_workspace_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    svc = FileService(db)
    return await svc.get_file_meta(wctx.organization_id, file_id)


@router.delete("/{file_id}", status_code=204)
async def delete_file(
    file_id: str,
    wctx: WorkspaceContext = Depends(get_workspace_context),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Delete a file: only the uploader or an org owner/admin may do this."""
    svc = FileService(db)
    meta_owner = await svc.files.get_by_id_and_org(file_id, wctx.organization_id)
    if meta_owner is not None and meta_owner.deleted_at is None:
        is_uploader = meta_owner.uploaded_by == wctx.user.id
        is_admin = wctx.role in (Role.OWNER, Role.ADMIN)
        if not (is_uploader or is_admin):
            raise AuthorizationError("Only the uploader or an admin can delete this file")
    await svc.delete_file(wctx.organization_id, file_id)
    await AuditLog.record(db, "file_deleted", actor_id=pseudonymize(wctx.user.id),
                          tenant_id=wctx.organization_id, resource_type="file", resource_id=file_id)
    return Response(status_code=204)


@router.post("/{file_id}/download-token", status_code=201)
async def create_download_token(
    file_id: str,
    wctx: WorkspaceContext = Depends(get_workspace_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    svc = FileService(db)
    token = await svc.create_download_token(wctx.organization_id, file_id)
    return {"download_token": token, "expires_in_seconds": 300}


@router.get("/{file_id}/download")
async def download_file(
    file_id: str, token: str,
    wctx: WorkspaceContext = Depends(get_workspace_context),
    db: AsyncSession = Depends(get_db),
) -> Response:
    svc = FileService(db)
    filename, data, mime = await svc.download_file(wctx.organization_id, token)
    return Response(
        content=data, media_type=mime,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
