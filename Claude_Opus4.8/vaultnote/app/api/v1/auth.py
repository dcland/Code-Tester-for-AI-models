"""Authentication endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    CurrentUser,
    get_container,
    get_current_user,
    get_session,
    rate_limit,
)
from app.core.container import Container
from app.schemas import (
    LoginRequest,
    PasswordChangeRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    TotpEnableResponse,
    TotpVerifyRequest,
)
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["auth"])


def _auth_service(container: Container, session: AsyncSession) -> AuthService:
    return AuthService(session, container.settings, container.security,
                       container.encryptor)


@router.post("/register", response_model=TokenResponse,
             status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(rate_limit("auth"))])
async def register(
    body: RegisterRequest,
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> TokenResponse:
    svc = _auth_service(container, session)
    outcome = await svc.register(
        email=body.email, password=body.password,
        display_name=body.display_name, organization_name=body.organization_name,
    )
    t = outcome.tokens
    return TokenResponse(access_token=t.access_token, refresh_token=t.refresh_token,
                         expires_in=t.expires_in)


@router.post("/login", response_model=TokenResponse,
             dependencies=[Depends(rate_limit("auth"))])
async def login(
    body: LoginRequest,
    request: Request,
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
    user_agent: str | None = Header(default=None),
) -> TokenResponse:
    svc = _auth_service(container, session)
    outcome = await svc.login(
        email=body.email, password=body.password, totp_code=body.totp_code,
        user_agent=user_agent,
    )
    t = outcome.tokens
    return TokenResponse(access_token=t.access_token, refresh_token=t.refresh_token,
                         expires_in=t.expires_in)


@router.post("/refresh", response_model=TokenResponse,
             dependencies=[Depends(rate_limit("auth"))])
async def refresh(
    body: RefreshRequest,
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> TokenResponse:
    svc = _auth_service(container, session)
    t = await svc.refresh(body.refresh_token)
    return TokenResponse(access_token=t.access_token, refresh_token=t.refresh_token,
                         expires_in=t.expires_in)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    current: CurrentUser = Depends(get_current_user),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> Response:
    svc = _auth_service(container, session)
    await svc.logout(current.session_id, current.user_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
async def logout_all(
    current: CurrentUser = Depends(get_current_user),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> Response:
    svc = _auth_service(container, session)
    await svc.logout_all(current.user_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/password/change", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    body: PasswordChangeRequest,
    current: CurrentUser = Depends(get_current_user),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> Response:
    svc = _auth_service(container, session)
    await svc.change_password(current.user_id, body.current_password, body.new_password)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/password/reset-request", status_code=status.HTTP_202_ACCEPTED,
             dependencies=[Depends(rate_limit("auth_strict"))])
async def request_password_reset(
    body: PasswordResetRequest,
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> dict:
    svc = _auth_service(container, session)
    token = await svc.request_password_reset(body.email)
    # Always the same response regardless of account existence (no enumeration).
    # In production the token is emailed; for the demo we expose it only in
    # non-production so flows can be exercised end-to-end.
    response: dict = {"status": "accepted"}
    if token and container.settings.environment != "production":
        response["debug_reset_token"] = token
    return response


@router.post("/password/reset-confirm", status_code=status.HTTP_204_NO_CONTENT,
             dependencies=[Depends(rate_limit("auth_strict"))])
async def confirm_password_reset(
    body: PasswordResetConfirm,
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> Response:
    svc = _auth_service(container, session)
    await svc.confirm_password_reset(body.token, body.new_password)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/2fa/enroll", response_model=TotpEnableResponse)
async def enroll_totp(
    current: CurrentUser = Depends(get_current_user),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> TotpEnableResponse:
    svc = _auth_service(container, session)
    secret, uri = await svc.begin_totp_enrollment(current.user_id,
                                                  container.settings.app_name)
    return TotpEnableResponse(secret=secret, otpauth_uri=uri)


@router.post("/2fa/confirm", status_code=status.HTTP_204_NO_CONTENT)
async def confirm_totp(
    body: TotpVerifyRequest,
    current: CurrentUser = Depends(get_current_user),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> Response:
    svc = _auth_service(container, session)
    await svc.confirm_totp(current.user_id, body.code)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/2fa/disable", status_code=status.HTTP_204_NO_CONTENT)
async def disable_totp(
    body: TotpVerifyRequest,
    current: CurrentUser = Depends(get_current_user),
    container: Container = Depends(get_container),
    session: AsyncSession = Depends(get_session),
) -> Response:
    svc = _auth_service(container, session)
    await svc.disable_totp(current.user_id, body.code)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
