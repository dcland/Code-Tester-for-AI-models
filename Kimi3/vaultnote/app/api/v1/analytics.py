"""Privacy-preserving analytics endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import TenantContext, get_tenant_context
from app.models.database import get_db
from app.services.analytics_service import AnalyticsService

router = APIRouter(prefix="/analytics", tags=["analytics"])


@router.get("/dashboard")
async def dashboard(
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Differentially-private org-level usage dashboard.

    GDPR Art. 89(1): no individual user can be re-identified.
    """
    svc = AnalyticsService(db)
    return await svc.dashboard(ctx.organization_id)
