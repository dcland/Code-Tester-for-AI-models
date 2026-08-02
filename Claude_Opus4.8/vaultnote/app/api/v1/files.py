"""File upload/download endpoints (encrypted at rest)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    TenantContext,
    get_container,
    get_session,
    get_tenant_context,
    rate_limit,
)
from app.core.container import Container
from app.core.exceptions import FileValidationError
from app.schemas import DownloadTokenOut, FileOut
from app.services.file_service import FileService

router = APIRouter(prefix="/organizations/{org_id}", tags=["files"])


def _files(container: Container, session: AsyncSession) -> FileService:
    return FileService(session, container.settings, container.encryptor,
                       container.security, container.blob_store)


@router.post("/files", response_model=FileOut, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(rate_limit("upload"))])
async def upload_file(
    org_id: str,
    request: Request,
    x_filename: str = Header(..., alias="X-Filename", max_length=255),
    folder_id: str | None = Query(default=None),
    content_type: str | None = Header(default=None, alias="Content-Type"),
    ctx: TenantContext = Depends(get_tenant_context),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> FileOut:
    """Raw-body upload.

    The client sends the file bytes as the request body with the desired name in
    the ``X-Filename`` header (avoids a multipart dependency). The name is
    sanitized and never used to build a storage path (path-traversal safe).
    """
    max_bytes = container.settings.max_upload_bytes
    data = await request.body()
    if len(data) > max_bytes:
        raise FileValidationError("file exceeds maximum allowed size")

    # Sanitize the declared filename: strip any path components / control chars.
    import os as _os

    filename = _os.path.basename(x_filename).replace("\x00", "").strip() or "upload.bin"
    record = await _files(container, session).upload(
        org_id, ctx.user_id, filename=filename, data=data,
        declared_content_type=content_type, folder_id=folder_id,
    )
    return FileOut(id=record.id, filename=filename,
                   content_type=record.content_type, size_bytes=record.size_bytes,
                   created_at=record.created_at)


@router.get("/files", response_model=list[FileOut])
async def list_files(
    org_id: str,
    folder_id: str | None = Query(default=None),
    ctx: TenantContext = Depends(get_tenant_context),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> list[FileOut]:
    rows = await _files(container, session).list_files(org_id, ctx.user_id, folder_id)
    return [
        FileOut(id=f.id, filename=name, content_type=f.content_type,
                size_bytes=f.size_bytes, created_at=f.created_at)
        for f, name in rows
    ]


@router.post("/files/{file_id}/download-token", response_model=DownloadTokenOut,
             dependencies=[Depends(rate_limit("read"))])
async def create_download_token(
    org_id: str,
    file_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> DownloadTokenOut:
    token, ttl = await _files(container, session).issue_download_token(
        org_id, ctx.user_id, file_id
    )
    return DownloadTokenOut(token=token, expires_in=ttl)


@router.get("/files/download", dependencies=[Depends(rate_limit("read"))])
async def download_file(
    org_id: str,
    token: str = Query(...),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> StreamingResponse:
    result = await _files(container, session).download_with_token(token)
    import io

    # Content-Disposition uses a fixed ASCII-safe name to avoid header injection;
    # the true (possibly sensitive) name is exposed via a custom header value.
    headers = {
        "Content-Disposition": f'attachment; filename="{result.id}.bin"',
        "X-Content-Type-Options": "nosniff",
    }
    return StreamingResponse(io.BytesIO(result.data),
                             media_type=result.content_type, headers=headers)


@router.delete("/files/{file_id}", status_code=status.HTTP_204_NO_CONTENT,
               dependencies=[Depends(rate_limit("write"))])
async def delete_file(
    org_id: str,
    file_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> Response:
    await _files(container, session).delete(org_id, ctx.user_id, file_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
