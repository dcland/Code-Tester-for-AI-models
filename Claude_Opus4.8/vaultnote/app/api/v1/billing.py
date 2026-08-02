"""Billing endpoints: plan changes, usage, invoices."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    TenantContext,
    get_container,
    get_session,
    get_tenant_context,
    rate_limit,
)
from app.core.container import Container
from app.schemas import (
    InvoiceOut,
    PlanChangeRequest,
    SubscriptionOut,
    UsageOut,
)
from app.services.billing_service import BillingService

router = APIRouter(prefix="/organizations/{org_id}/billing", tags=["billing"])


def _billing(container: Container, session: AsyncSession) -> BillingService:
    return BillingService(session, container.settings)


@router.get("/usage", response_model=UsageOut)
async def get_usage(
    org_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> UsageOut:
    usage = await _billing(container, session).get_usage(org_id, ctx.user_id)
    return UsageOut(**usage)


@router.post("/plan", response_model=SubscriptionOut,
             dependencies=[Depends(rate_limit("write"))])
async def change_plan(
    org_id: str,
    body: PlanChangeRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> SubscriptionOut:
    sub = await _billing(container, session).change_plan(
        org_id, ctx.user_id, plan=body.plan, seats=body.seats,
        payment_token=body.payment_token,
    )
    return SubscriptionOut(plan=sub.plan, seats=sub.seats, status=sub.status,
                           current_period_end=sub.current_period_end)


@router.post("/invoices/run", response_model=InvoiceOut,
             status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(rate_limit("write"))])
async def run_billing(
    org_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> InvoiceOut:
    inv = await _billing(container, session).run_period_billing(org_id, ctx.user_id)
    return _invoice_out(inv)


@router.get("/invoices", response_model=list[InvoiceOut])
async def list_invoices(
    org_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> list[InvoiceOut]:
    invoices = await _billing(container, session).list_invoices(org_id, ctx.user_id)
    return [_invoice_out(i) for i in invoices]


def _invoice_out(i) -> InvoiceOut:
    return InvoiceOut(
        number=i.number, amount_cents=i.amount_cents, currency=i.currency,
        status=i.status, period_start=i.period_start, period_end=i.period_end,
        line_items=json.loads(i.line_items),
    )
