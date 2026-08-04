"""Authentication endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import CurrentUser, get_current_user
from app.core.compliance import AuditLog
from app.core.privacy import pseudonymize
from app.models.database import get_db
from app.repositories.repositories import UserRepository
from app.schemas.requests import (
    ChangePasswordRequest,
    Enable2FAResponse,
    LoginRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
    RefreshRequest,
    RegisterRequest,
    TokenPair,
    Verify2FARequest,
)
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=TokenPair, status_code=201)
async def register(body: RegisterRequest, db: AsyncSession = Depends(get_db)) -> TokenPair:
    svc = AuthService(db)
    user, org = await svc.register(body.email, body.password, body.full_name, body.organization_name)
    access, refresh, _ = await svc.login(body.email, body.password)
    await AuditLog.record(db, "user_registered", actor_id=pseudonymize(user.id), tenant_id=org.id,
                          resource_type="user", resource_id=pseudonymize(user.id))
    return TokenPair(access_token=access, refresh_token=refresh, expires_in=900)


@router.post("/login", response_model=TokenPair)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)) -> TokenPair:
    svc = AuthService(db)
    access, refresh, user = await svc.login(body.email, body.password, body.totp_code)
    await AuditLog.record(db, "login", actor_id=pseudonymize(user.id), tenant_id="",
                          resource_type="user", resource_id=pseudonymize(user.id))
    return TokenPair(access_token=access, refresh_token=refresh, expires_in=900)


@router.post("/refresh", response_model=TokenPair)
async def refresh(body: RefreshRequest, db: AsyncSession = Depends(get_db)) -> TokenPair:
    svc = AuthService(db)
    access, new_refresh = await svc.refresh(body.refresh_token)
    return TokenPair(access_token=access, refresh_token=new_refresh, expires_in=900)


@router.post("/logout", status_code=204)
async def logout(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    svc = AuthService(db)
    await svc.logout_all(user.id)
    # 204 responses must not carry a body - return an explicit empty Response.
    return Response(status_code=204)


@router.post("/password-reset", status_code=202)
async def password_reset_request(body: PasswordResetRequest, db: AsyncSession = Depends(get_db)) -> dict:
    """Request a password reset.

    Always returns the same 202 response whether or not the email exists,
    and never includes the token: the raw token is only sent by email and
    only its hash is stored. This prevents account enumeration and token
    disclosure to unauthenticated callers.
    """
    svc = AuthService(db)
    await svc.request_password_reset(body.email)
    return {"message": "If the email exists, a reset link has been sent."}


@router.post("/password-reset/confirm", status_code=200)
async def password_reset_confirm(body: PasswordResetConfirm, db: AsyncSession = Depends(get_db)) -> dict:
    """Complete a password reset.

    Validates the token (expiry + single use), updates the password, and
    revokes all existing sessions. Invalid tokens are rejected - this route
    never reports success without changing a password.
    """
    svc = AuthService(db)
    await svc.confirm_password_reset(body.token, body.new_password)
    return {"message": "Password has been reset."}


@router.post("/change-password", status_code=200)
async def change_password(
    body: ChangePasswordRequest,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    svc = AuthService(db)
    db_user = await UserRepository(db).get_by_id(user.id)
    assert db_user is not None
    await svc.change_password(db_user, body.current_password, body.new_password)
    return {"message": "Password changed. All sessions revoked."}


@router.post("/2fa/setup", response_model=Enable2FAResponse)
async def setup_2fa(user: CurrentUser = Depends(get_current_user), db: AsyncSession = Depends(get_db)) -> Enable2FAResponse:
    svc = AuthService(db)
    db_user = await UserRepository(db).get_by_id(user.id)
    assert db_user is not None
    secret = await svc.setup_2fa(db_user)
    uri = f"otpauth://totp/VaultNote:{user.email}?secret={secret}&issuer=VaultNote"
    return Enable2FAResponse(secret=secret, uri=uri)


@router.post("/2fa/enable", status_code=200)
async def enable_2fa(
    body: Verify2FARequest,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    svc = AuthService(db)
    db_user = await UserRepository(db).get_by_id(user.id)
    assert db_user is not None
    await svc.enable_2fa(db_user, body.code)
    return {"message": "2FA enabled"}
