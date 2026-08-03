"""Billing & subscription endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import TenantContext, get_tenant_context, require_role
from app.models.database import get_db
from app.models.entities import PlanTier, Role
from app.schemas.requests import PlanChange
from app.services.billing_service import BillingService

router = APIRouter(prefix="/billing", tags=["billing"])


@router.get("/subscription")
async def get_subscription(
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    svc = BillingService(db)
    sub = await svc.get_subscription(ctx.organization_id)
    return {"plan": sub.plan.value, "active": sub.active}


@router.post("/plan", status_code=200)
async def change_plan(
    body: PlanChange,
    ctx: TenantContext = Depends(require_role(Role.OWNER, Role.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> dict:
    svc = BillingService(db)
    return await svc.change_plan(ctx.organization_id, PlanTier(body.plan), body.payment_token)


@router.get("/invoices")
async def list_invoices(
    ctx: TenantContext = Depends(require_role(Role.OWNER, Role.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    svc = BillingService(db)
    return await svc.list_invoices(ctx.organization_id)
