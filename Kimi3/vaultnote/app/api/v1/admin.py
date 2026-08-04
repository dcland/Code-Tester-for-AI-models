"""Admin & compliance endpoints (GDPR/CCPA/retention/key rotation/audit)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import TenantContext, get_tenant_context, require_role
from app.core.compliance import AuditLog
from app.core.privacy import pseudonymize
from app.models.database import get_db
from app.models.entities import Role
from app.schemas.requests import ConsentUpdate
from app.services.compliance_service import ComplianceService
from app.services.note_service import NoteService

router = APIRouter(prefix="/admin", tags=["admin"])


# ---- GDPR Art. 17 - Right to Erasure ---------------------------------------

@router.delete("/users/me", status_code=200)
async def erase_my_account(
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """GDPR Art. 17 / CCPA - user self-erasure (including stored file blobs)."""
    svc = ComplianceService(db)
    return await svc.erase_user(ctx.user.id, ctx.organization_id)


@router.delete("/organization", status_code=200)
async def erase_organization(
    ctx: TenantContext = Depends(require_role(Role.OWNER)),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """GDPR Art. 17 - cascading deletion of entire tenant (rows + blobs)."""
    svc = ComplianceService(db)
    return await svc.erase_organization(ctx.organization_id)


# ---- GDPR Art. 15 / CCPA - Data Export ------------------------------------

@router.get("/export")
async def export_my_data(
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """GDPR Art. 15 - machine-readable data export."""
    svc = ComplianceService(db)
    return await svc.export_user_data(ctx.user.id, ctx.organization_id)


@router.get("/export/zip")
async def export_my_data_zip(
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> Response:
    svc = ComplianceService(db)
    data = await svc.export_user_data_zip(ctx.user.id, ctx.organization_id)
    return Response(content=data, media_type="application/zip",
                    headers={"Content-Disposition": "attachment; filename=export.zip"})


# ---- GDPR Art. 7 - Consent --------------------------------------------------

@router.post("/consent", status_code=201)
async def record_consent(
    body: ConsentUpdate,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    svc = ComplianceService(db)
    rec = await svc.record_consent(ctx.user.id, body.purpose, body.granted)
    return {"id": rec.id, "purpose": rec.purpose, "granted": rec.granted}


@router.get("/consent")
async def list_consents(
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    svc = ComplianceService(db)
    return await svc.list_consents(ctx.user.id)


# ---- Retention purge ---------------------------------------------------------

@router.post("/retention/purge", status_code=200)
async def purge_expired(
    ctx: TenantContext = Depends(require_role(Role.OWNER, Role.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """GDPR Art. 5(1)(e) - tenant-scoped purge with the caller's own plan
    window. Cross-tenant enforcement runs automatically as a scheduled
    system job (see app lifespan), never via a tenant admin."""
    svc = ComplianceService(db)
    return await svc.purge_expired_data(ctx.organization_id)


# ---- Key rotation -----------------------------------------------------------

@router.post("/keys/rotate", status_code=200)
async def rotate_keys(
    ctx: TenantContext = Depends(require_role(Role.OWNER, Role.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """GDPR Art. 32 - cryptographic key rotation (notes, folders, files)."""
    svc = NoteService(db)
    count = await svc.rotate_tenant_key(ctx.organization_id)
    await AuditLog.record(db, "key_rotated", actor_id=pseudonymize(ctx.user.id),
                          tenant_id=ctx.organization_id, resource_type="organization",
                          resource_id=ctx.organization_id, metadata={"rewrapped": count})
    return {"rewrapped_items": count}


# ---- Audit log (durable, HMAC-signed, tamper-evident) -----------------------

@router.get("/audit")
async def get_audit_log(
    ctx: TenantContext = Depends(require_role(Role.OWNER, Role.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """SOC 2 CC7.2 - durable signed audit trail (no PII)."""
    return await AuditLog.events_for_tenant(db, ctx.organization_id)


@router.get("/audit/verify")
async def verify_audit_chain(
    ctx: TenantContext = Depends(require_role(Role.OWNER, Role.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Verify the integrity of the audit chain (tamper check)."""
    return {"valid": await AuditLog.verify_chain(db)}
