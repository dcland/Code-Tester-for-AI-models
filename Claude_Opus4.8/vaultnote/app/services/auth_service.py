"""Authentication & session management service.

Implements registration, login (with lockout + timing-attack resistance),
refresh-token rotation, password reset/change, logout(-all), and TOTP 2FA.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.compliance import AuditAction
from app.core.config import Settings
from app.core.encryption import EnvelopeEncryptor
from app.core.exceptions import (
    AccountLockedError,
    AuthenticationError,
    ConflictError,
    InvalidTokenError,
    TwoFactorRequiredError,
    ValidationError,
)
from app.core.security import SecurityService
from app.db.base import utcnow
from app.models.organization import Membership, Organization, Role
from app.models.user import PasswordReset, Session, User
from app.repositories import (
    MembershipRepository,
    OrganizationRepository,
    PasswordResetRepository,
    SessionRepository,
    UserRepository,
)
from app.services.audit_service import AuditService


@dataclass
class IssuedTokens:
    access_token: str
    refresh_token: str
    expires_in: int


@dataclass
class LoginOutcome:
    tokens: IssuedTokens
    user_id: str


class AuthService:
    def __init__(self, session: AsyncSession, settings: Settings,
                 security: SecurityService, encryptor: EnvelopeEncryptor) -> None:
        self._s = session
        self._settings = settings
        self._sec = security
        self._enc = encryptor
        self._users = UserRepository(session)
        self._sessions = SessionRepository(session)
        self._resets = PasswordResetRepository(session)
        self._orgs = OrganizationRepository(session)
        self._members = MembershipRepository(session)
        self._audit = AuditService(session, settings)

    # --- Registration ------------------------------------------------------
    async def register(self, *, email: str, password: str, display_name: str,
                       organization_name: str) -> LoginOutcome:
        if await self._users.get_by_email(email):
            # Same generic error whether or not the email exists is preferable,
            # but a 409 on register is standard UX; enumeration risk is mitigated
            # elsewhere. Return conflict without echoing the email.
            raise ConflictError("an account with these details already exists")

        user = User(
            email=email,
            password_hash=self._sec.hash_password(password),
            display_name=display_name[:120],
        )
        await self._users.add(user)

        # First org for this user; they become OWNER.
        org = Organization(
            name=organization_name,
            plan="free",
            wrapped_master_key=self._enc.create_tenant_master_key(),
            retention_days=self._settings.retention_days_free,
        )
        await self._orgs.add(org)
        await self._members.add(
            Membership(org_id=org.id, user_id=user.id, role=Role.OWNER)
        )

        await self._audit.record(
            action=AuditAction.USER_REGISTERED, org_id=org.id, actor_user_id=user.id
        )
        await self._audit.record(
            action=AuditAction.ORG_CREATED, org_id=org.id, actor_user_id=user.id,
            resource_type="organization", resource_id=org.id,
        )
        tokens = await self._issue_session(user, org.id, Role.OWNER)
        await self._s.commit()
        return LoginOutcome(tokens=tokens, user_id=user.id)

    # --- Login -------------------------------------------------------------
    async def login(self, *, email: str, password: str,
                    totp_code: str | None, user_agent: str | None = None) -> LoginOutcome:
        user = await self._users.get_by_email(email)

        # Lockout check (brute-force / credential-stuffing defense).
        if user and user.locked_until and user.locked_until > utcnow():
            raise AccountLockedError()

        # Constant-time verification; verify_password hashes a dummy when the
        # user is unknown so timing does not reveal account existence (OWASP).
        password_ok = self._sec.verify_password(
            password, user.password_hash if user else None
        )

        if not user or not password_ok:
            if user:
                await self._users.register_failed_login(
                    user,
                    max_failures=self._settings.max_failed_logins,
                    lockout_seconds=self._settings.lockout_seconds,
                )
                await self._audit.record(
                    action=AuditAction.LOGIN_FAILED, org_id=None,
                    actor_user_id=user.id, outcome="failure",
                )
                await self._s.commit()
            raise AuthenticationError("invalid credentials")

        # 2FA gate.
        if user.totp_enabled:
            if not totp_code:
                raise TwoFactorRequiredError()
            if not self._sec.verify_totp(user.totp_secret or "", totp_code):
                await self._audit.record(
                    action=AuditAction.LOGIN_FAILED, org_id=None,
                    actor_user_id=user.id, outcome="failure",
                    context={"reason": "totp"},
                )
                await self._s.commit()
                raise AuthenticationError("invalid credentials")

        await self._users.reset_failed_login(user)

        # Opportunistic rehash if Argon2 params were strengthened.
        if self._sec.needs_rehash(user.password_hash):
            user.password_hash = self._sec.hash_password(password)

        # Default active org = first membership (users may switch later).
        memberships = await self._members.list_for_user(user.id)
        org_id = memberships[0].org_id if memberships else None
        role = Role(memberships[0].role) if memberships else None

        await self._audit.record(
            action=AuditAction.LOGIN_SUCCEEDED, org_id=org_id, actor_user_id=user.id
        )
        tokens = await self._issue_session(user, org_id, role, user_agent)
        await self._s.commit()
        return LoginOutcome(tokens=tokens, user_id=user.id)

    # --- Token issuance / refresh -----------------------------------------
    async def _issue_session(self, user: User, org_id: str | None,
                             role: Role | None, user_agent: str | None = None) -> IssuedTokens:
        refresh = self._sec.generate_refresh_token()
        session_row = Session(
            user_id=user.id,
            org_id=org_id,
            token_hash=self._sec.hash_token(refresh),
            expires_at=self._sec.refresh_expiry(),
            user_agent_hash=self._sec.hash_token(user_agent) if user_agent else None,
        )
        await self._sessions.add(session_row)
        access = self._sec.issue_access_token(
            user_id=user.id, org_id=org_id,
            role=str(role) if role else None, session_id=session_row.id,
        )
        return IssuedTokens(
            access_token=access, refresh_token=refresh,
            expires_in=self._settings.access_token_ttl_seconds,
        )

    async def refresh(self, refresh_token: str) -> IssuedTokens:
        token_hash = self._sec.hash_token(refresh_token)
        session_row = await self._sessions.get_by_token_hash(token_hash)
        if (
            session_row is None
            or session_row.revoked_at is not None
            or session_row.expires_at <= utcnow()
        ):
            raise InvalidTokenError()
        user = await self._users.get_active(session_row.user_id)
        if user is None:
            raise InvalidTokenError()

        # Rotation: revoke the presented token and issue a fresh one. Reuse of a
        # rotated token (theft) fails because it is now revoked.
        await self._sessions.revoke(session_row)
        role = await self._members.get_role(session_row.org_id, user.id) \
            if session_row.org_id else None
        tokens = await self._issue_session(user, session_row.org_id, role,
                                           session_row.user_agent_hash)
        await self._s.commit()
        return tokens

    # --- Logout ------------------------------------------------------------
    async def logout(self, session_id: str, user_id: str) -> None:
        session_row = await self._sessions.get(session_id)
        if session_row and session_row.user_id == user_id:
            await self._sessions.revoke(session_row)
        await self._audit.record(
            action=AuditAction.LOGOUT, org_id=None, actor_user_id=user_id
        )
        await self._s.commit()

    async def logout_all(self, user_id: str) -> None:
        # Session revocation on logout-from-all-devices: bump token epoch to
        # invalidate outstanding access tokens too.
        await self._sessions.revoke_all_for_user(user_id)
        await self._users.bump_token_epoch(user_id)
        await self._audit.record(
            action=AuditAction.LOGOUT_ALL, org_id=None, actor_user_id=user_id
        )
        await self._s.commit()

    # --- Password change / reset ------------------------------------------
    async def change_password(self, user_id: str, current_password: str,
                              new_password: str) -> None:
        user = await self._users.get_active(user_id)
        if user is None or not self._sec.verify_password(
            current_password, user.password_hash
        ):
            raise AuthenticationError("invalid credentials")
        user.password_hash = self._sec.hash_password(new_password)
        # Invalidate all sessions on credential change (session revocation).
        await self._sessions.revoke_all_for_user(user_id)
        await self._users.bump_token_epoch(user_id)
        await self._audit.record(
            action=AuditAction.PASSWORD_CHANGED, org_id=None, actor_user_id=user_id
        )
        await self._s.commit()

    async def request_password_reset(self, email: str) -> str | None:
        """Create a reset token. Returns the raw token for the caller to deliver
        out-of-band (email). Always returns without revealing if the user exists.
        """
        user = await self._users.get_by_email(email)
        if user is None:
            # Do not disclose account existence.
            await self._s.commit()
            return None
        raw = self._sec.generate_opaque_secret()
        self._s.add(  # via repo
            PasswordReset(
                user_id=user.id,
                token_hash=self._sec.hash_token(raw),
                expires_at=utcnow() + timedelta(
                    seconds=self._settings.password_reset_ttl_seconds
                ),
            )
        )
        await self._audit.record(
            action=AuditAction.PASSWORD_RESET_REQUESTED, org_id=None,
            actor_user_id=user.id,
        )
        await self._s.commit()
        return raw

    async def confirm_password_reset(self, token: str, new_password: str) -> None:
        row = await self._resets.get_valid(self._sec.hash_token(token))
        if row is None:
            raise InvalidTokenError("reset token is invalid or expired")
        user = await self._users.get_active(row.user_id)
        if user is None:
            raise InvalidTokenError()
        user.password_hash = self._sec.hash_password(new_password)
        await self._resets.mark_used(row)
        await self._sessions.revoke_all_for_user(user.id)
        await self._users.bump_token_epoch(user.id)
        await self._audit.record(
            action=AuditAction.PASSWORD_RESET_COMPLETED, org_id=None,
            actor_user_id=user.id,
        )
        await self._s.commit()

    # --- TOTP 2FA ----------------------------------------------------------
    async def begin_totp_enrollment(self, user_id: str, issuer: str) -> tuple[str, str]:
        user = await self._users.get_active(user_id)
        if user is None:
            raise AuthenticationError()
        secret = self._sec.generate_totp_secret()
        user.totp_secret = secret  # not yet enabled until verified
        user.totp_enabled = False
        await self._s.commit()
        # otpauth URI uses an opaque account label (user id), not the email.
        uri = (
            f"otpauth://totp/{issuer}:{user_id}?secret={secret}"
            f"&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
        )
        return secret, uri

    async def confirm_totp(self, user_id: str, code: str) -> None:
        user = await self._users.get_active(user_id)
        if user is None or not user.totp_secret:
            raise ValidationError("2FA enrollment not started")
        if not self._sec.verify_totp(user.totp_secret, code):
            raise AuthenticationError("invalid 2FA code")
        user.totp_enabled = True
        await self._audit.record(
            action=AuditAction.TWO_FACTOR_ENABLED, org_id=None, actor_user_id=user_id
        )
        await self._s.commit()

    async def disable_totp(self, user_id: str, code: str) -> None:
        user = await self._users.get_active(user_id)
        if user is None or not user.totp_enabled:
            raise ValidationError("2FA is not enabled")
        if not self._sec.verify_totp(user.totp_secret or "", code):
            raise AuthenticationError("invalid 2FA code")
        user.totp_enabled = False
        user.totp_secret = None
        await self._audit.record(
            action=AuditAction.TWO_FACTOR_DISABLED, org_id=None, actor_user_id=user_id
        )
        await self._s.commit()
