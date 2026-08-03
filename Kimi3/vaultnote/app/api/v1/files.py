"""File upload/download endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Response, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import TenantContext, get_tenant_context
from app.core.compliance import AuditLog
from app.core.privacy import pseudonymize
from app.models.database import get_db
from app.services.file_service import FileService
from app.utils.exceptions import ValidationError

router = APIRouter(prefix="/workspaces/{workspace_id}/files", tags=["files"])


@router.post("", status_code=201)
async def upload_file(
    workspace_id: str, file: UploadFile,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    data = await file.read()
    svc = FileService(db)
    asset = await svc.upload_file(ctx.organization_id, workspace_id, ctx.user.id,
                                  file.filename or "file", data)
    AuditLog.record("file_uploaded", actor_id=pseudonymize(ctx.user.id),
                    tenant_id=ctx.organization_id, resource_type="file", resource_id=asset.id,
                    metadata={"size_bytes": asset.size_bytes})
    return {"id": asset.id, "size_bytes": asset.size_bytes, "mime_type": asset.mime_type}


@router.get("/{file_id}")
async def get_file_metadata(
    workspace_id: str, file_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    svc = FileService(db)
    return await svc.get_file_meta(ctx.organization_id, file_id)


@router.post("/{file_id}/download-token", status_code=201)
async def create_download_token(
    workspace_id: str, file_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    svc = FileService(db)
    token = await svc.create_download_token(ctx.organization_id, file_id)
    return {"download_token": token, "expires_in_seconds": 300}


@router.get("/{file_id}/download")
async def download_file(
    workspace_id: str, file_id: str, token: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> Response:
    svc = FileService(db)
    filename, data, mime = await svc.download_file(ctx.organization_id, token)
    return Response(
        content=data, media_type=mime,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
