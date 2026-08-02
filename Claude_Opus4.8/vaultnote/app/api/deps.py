"""FastAPI dependencies: DB session, authentication, tenant context, rate limits."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass

import jwt
from fastapi import Depends, Header, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.container import Container
from app.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    InvalidTokenError,
    RateLimitedError,
)
from app.db.base import utcnow
from app.repositories import MembershipRepository, SessionRepository, UserRepository


def get_container(request: Request) -> Container:
    return request.app.state.container


async def get_session(
    container: Container = Depends(get_container),
) -> AsyncIterator[AsyncSession]:
    async with container.database.session_factory() as session:
        yield session


@dataclass
class CurrentUser:
    user_id: str
    org_id: str | None
    role: str | None
    session_id: str


async def get_current_user(
    request: Request,
    authorization: str | None = Header(default=None),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> CurrentUser:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise AuthenticationError("missing bearer token")
    token = authorization[7:].strip()
    try:
        payload = container.security.decode_access_token(token)
    except jwt.ExpiredSignatureError as exc:
        raise InvalidTokenError("token expired") from exc
    except jwt.PyJWTError as exc:
        raise InvalidTokenError("invalid token") from exc
    if payload.get("type") != "access":
        raise InvalidTokenError("wrong token type")

    users = UserRepository(session)
    user = await users.get_active(payload["sub"])
    if user is None:
        raise InvalidTokenError("account is inactive")

    # Session-bound access tokens: revoking the session (logout, logout-all,
    # password change/reset) invalidates the access token immediately, not just
    # at its 15-minute expiry.
    sid = payload.get("sid", "")
    session_row = await SessionRepository(session).get(sid)
    if (
        session_row is None
        or session_row.user_id != user.id
        or session_row.revoked_at is not None
        or session_row.expires_at <= utcnow()
    ):
        raise InvalidTokenError("session is no longer valid")

    return CurrentUser(
        user_id=user.id,
        org_id=payload.get("org"),
        role=payload.get("role"),
        session_id=payload.get("sid", ""),
    )


@dataclass
class TenantContext:
    user_id: str
    org_id: str
    role: str
    session_id: str


async def get_tenant_context(
    org_id: str,
    current: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> TenantContext:
    """Resolve and VERIFY the caller's membership in the path's org.

    This is the per-request tenant-isolation gate: the org in the URL must be
    one the caller actually belongs to; the role comes from the DB, not the JWT.
    """
    members = MembershipRepository(session)
    role = await members.get_role(org_id, current.user_id)
    if role is None:
        raise AuthorizationError("not a member of this organization")

    # Usage metering: count one API call for the tenant (billing). Committed by
    # the route's own transaction (same session instance within the request).
    from datetime import datetime, timezone

    from app.repositories import BillingRepository

    await BillingRepository(session).increment_usage(
        org_id, "api_calls", datetime.now(timezone.utc).strftime("%Y-%m"), 1
    )
    return TenantContext(
        user_id=current.user_id, org_id=org_id, role=str(role),
        session_id=current.session_id,
    )


def rate_limit(bucket: str):
    """Dependency factory enforcing a named rate-limit bucket.

    Keyed by authenticated user when available, otherwise by client host, plus
    the tenant in the path — giving per-user AND per-tenant budgets.
    """

    async def _dep(
        request: Request,
        container: Container = Depends(get_container),
        authorization: str | None = Header(default=None),
    ) -> None:
        identity = "anon"
        if authorization and authorization.lower().startswith("bearer "):
            try:
                payload = container.security.decode_access_token(authorization[7:])
                identity = f"u:{payload['sub']}"
            except jwt.PyJWTError:
                identity = f"ip:{request.client.host if request.client else 'unknown'}"
        else:
            identity = f"ip:{request.client.host if request.client else 'unknown'}"

        org_id = request.path_params.get("org_id")
        scope = f"{identity}:{org_id}" if org_id else identity
        result = await container.rate_limiter.check(bucket=bucket, identity=scope)
        if not result.allowed:
            raise RateLimitedError(retry_after=result.retry_after)

    return _dep
