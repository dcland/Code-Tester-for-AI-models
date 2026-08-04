"""
Authentication service - registration, login, token lifecycle, 2FA.
"""
from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.encryption import encryption_service
from app.core.security import (
    create_access_token,
    generate_refresh_token,
    generate_secure_token,
    generate_totp_secret,
    hash_password,
    hash_token,
    verify_password,
    verify_totp,
)
from app.models.entities import (
    Membership,
    Organization,
    PasswordReset,
    PlanTier,
    RefreshToken,
    Role,
    Subscription,
    User,
)
from app.repositories.repositories import (
    MembershipRepository,
    OrganizationRepository,
    PasswordResetRepository,
    RefreshTokenRepository,
    UserRepository,
)
from app.utils.exceptions import AuthenticationError, ConflictError, ValidationError
from app.utils.mailer import Mailer


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "org"


class AuthService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.users = UserRepository(session)
        self.orgs = OrganizationRepository(session)
        self.memberships = MembershipRepository(session)
        self.refresh_tokens = RefreshTokenRepository(session)
        self.resets = PasswordResetRepository(session)

    async def register(self, email: str, password: str, full_name: str, org_name: str) -> tuple[User, Organization]:
        email = email.lower()
        existing = await self.users.get_by_email(email)
        if existing:
            raise ConflictError("Email already registered")

        user = User(email=email, hashed_password=hash_password(password), full_name=full_name)
        await self.users.create(user)

        # Create organization with a fresh tenant KEK wrapped by master key
        kek = encryption_service.generate_tenant_kek()
        wrapped = encryption_service.encrypt_kek(kek)
        slug = _slugify(org_name)
        # Ensure unique slug
        base_slug, n = slug, 1
        while await self.orgs.get_by_slug(slug):
            n += 1
            slug = f"{base_slug}-{n}"
        org = Organization(name=org_name, slug=slug, kek_ciphertext=wrapped.ciphertext, kek_nonce=wrapped.nonce)
        await self.orgs.create(org)

        membership = Membership(user_id=user.id, organization_id=org.id, role=Role.OWNER)
        await self.memberships.create(membership)

        subscription = Subscription(organization_id=org.id, plan=PlanTier.FREE)
        self.session.add(subscription)
        await self.session.flush()
        return user, org

    async def login(self, email: str, password: str, totp_code: str | None = None) -> tuple[str, str, User]:
        """Authenticate user and return (access_token, refresh_token, user).

        Anti-enumeration: identical error for unknown email / wrong password.
        Brute-force protection: argon2 cost + rate limiting at middleware.
        """
        user = await self.users.get_by_email(email.lower())
        if user is None or not user.is_active or user.deleted_at is not None:
            # Perform a dummy verify to equalize timing (timing-attack defense)
            verify_password(password, "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            raise AuthenticationError("Invalid credentials")
        if not verify_password(password, user.hashed_password):
            raise AuthenticationError("Invalid credentials")

        if user.totp_enabled:
            if not totp_code or not user.totp_secret:
                raise AuthenticationError("2FA code required")
            if not verify_totp(user.totp_secret, totp_code):
                raise AuthenticationError("Invalid 2FA code")

        access = create_access_token(user.id)
        refresh = generate_refresh_token()
        rt = RefreshToken(
            user_id=user.id,
            token_hash=hash_token(refresh),
            expires_at=datetime.now(UTC) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        )
        await self.refresh_tokens.create(rt)
        return access, refresh, user

    async def refresh(self, refresh_token: str) -> tuple[str, str]:
        """Rotate refresh token (OWASP: refresh token rotation)."""
        token_hash = hash_token(refresh_token)
        rt = await self.refresh_tokens.get_by_hash(token_hash)
        now = datetime.now(UTC)
        # SQLite returns naive datetimes - normalize for comparison
        expires_at = rt.expires_at.replace(tzinfo=UTC) if rt and rt.expires_at.tzinfo is None else (rt.expires_at if rt else None)
        if rt is None or rt.revoked or (expires_at is not None and expires_at < now):
            raise AuthenticationError("Invalid refresh token")

        # Rotate: revoke old, issue new
        rt.revoked = True
        new_refresh = generate_refresh_token()
        new_rt = RefreshToken(
            user_id=rt.user_id,
            token_hash=hash_token(new_refresh),
            expires_at=now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        )
        await self.refresh_tokens.create(new_rt)
        access = create_access_token(rt.user_id)
        return access, new_refresh

    async def logout_all(self, user_id: str) -> None:
        """Revoke all refresh tokens (logout from all devices)."""
        await self.refresh_tokens.revoke_all_for_user(user_id)

    async def change_password(self, user: User, current: str, new: str) -> None:
        if not verify_password(current, user.hashed_password):
            raise AuthenticationError("Current password is incorrect")
        user.hashed_password = hash_password(new)
        # GDPR/Security: revoke all sessions on password change
        await self.refresh_tokens.revoke_all_for_user(user.id)
        await self.session.flush()

    async def setup_2fa(self, user: User) -> str:
        secret = generate_totp_secret()
        user.totp_secret = secret
        await self.session.flush()
        return secret

    async def enable_2fa(self, user: User, code: str) -> None:
        if not user.totp_secret:
            raise ValidationError("2FA not initialized")
        if not verify_totp(user.totp_secret, code):
            raise ValidationError("Invalid code")
        user.totp_enabled = True
        await self.session.flush()

    async def request_password_reset(self, email: str) -> None:
        """Issue a reset token for an existing account and send it by email.

        Only the SHA-256 hash of the token is persisted. The raw token is
        delivered out-of-band via the mailer and is never exposed through
        the API, so responses are identical for existing and non-existing
        accounts (no account enumeration, no token disclosure).
        """
        user = await self.users.get_by_email(email.lower())
        if user is None or not user.is_active or user.deleted_at is not None:
            return
        raw = generate_secure_token(32)
        self.session.add(PasswordReset(
            user_id=user.id,
            token_hash=hash_token(raw),
            expires_at=datetime.now(UTC)
            + timedelta(seconds=settings.PASSWORD_RESET_TTL_SECONDS),
        ))
        await self.session.flush()
        Mailer.send_password_reset(user.email, raw)

    async def confirm_password_reset(self, token: str, new_password: str) -> None:
        """Validate a reset token, set the new password, revoke all sessions.

        Raises AuthenticationError for invalid/expired/used tokens so the
        endpoint never reports success without actually changing a password.
        """
        row = await self.resets.get_valid(hash_token(token))
        if row is None:
            raise AuthenticationError("Reset token is invalid or expired")
        user = await self.users.get_by_id(row.user_id)
        if user is None:
            raise AuthenticationError("Reset token is invalid or expired")
        user.hashed_password = hash_password(new_password)
        await self.resets.mark_used(row)
        # Security: any existing sessions must not survive a password reset.
        await self.refresh_tokens.revoke_all_for_user(user.id)
        await self.session.flush()

    async def reset_password(self, user: User, new_password: str) -> None:
        user.hashed_password = hash_password(new_password)
        await self.refresh_tokens.revoke_all_for_user(user.id)
        await self.session.flush()
