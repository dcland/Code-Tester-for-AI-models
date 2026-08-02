"""Privacy-preserving analytics endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    TenantContext,
    get_container,
    get_session,
    get_tenant_context,
    rate_limit,
)
from app.core.container import Container
from app.schemas import AnalyticsOut
from app.services.analytics_service import AnalyticsService

router = APIRouter(prefix="/organizations/{org_id}/analytics", tags=["analytics"])


@router.get("", response_model=AnalyticsOut, dependencies=[Depends(rate_limit("read"))])
async def dashboard(
    org_id: str,
    epsilon: float | None = Query(default=None, gt=0, le=10),
    ctx: TenantContext = Depends(get_tenant_context),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> AnalyticsOut:
    svc = AnalyticsService(session, container.settings)
    result = await svc.org_dashboard(org_id, ctx.user_id, epsilon)
    return AnalyticsOut(
        epsilon=result.epsilon, note_count=result.note_count,
        file_count=result.file_count, active_members=result.active_members,
        storage_bytes=result.storage_bytes, note=result.note,
    )
