"""User, session, password-reset and consent repositories."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import utcnow
from app.models.user import Consent, PasswordReset, Session, User


class UserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def get(self, user_id: str) -> User | None:
        return await self._s.get(User, user_id)

    async def get_active(self, user_id: str) -> User | None:
        user = await self._s.get(User, user_id)
        if user is None or user.deleted_at is not None or not user.is_active:
            return None
        return user

    async def get_by_email(self, email: str) -> User | None:
        # Parameterized query; email is normalized lowercase by the schema.
        stmt = select(User).where(User.email == email, User.deleted_at.is_(None))
        return (await self._s.execute(stmt)).scalar_one_or_none()

    async def add(self, user: User) -> User:
        self._s.add(user)
        await self._s.flush()
        return user

    async def bump_token_epoch(self, user_id: str) -> None:
        await self._s.execute(
            update(User).where(User.id == user_id).values(token_epoch=User.token_epoch + 1)
        )

    async def register_failed_login(self, user: User, *, max_failures: int,
                                    lockout_seconds: int) -> None:
        user.failed_login_count += 1
        if user.failed_login_count >= max_failures:
            from datetime import timedelta
            user.locked_until = utcnow() + timedelta(seconds=lockout_seconds)
            user.failed_login_count = 0
        await self._s.flush()

    async def reset_failed_login(self, user: User) -> None:
        if user.failed_login_count or user.locked_until:
            user.failed_login_count = 0
            user.locked_until = None
            await self._s.flush()


class SessionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(self, session_row: Session) -> Session:
        self._s.add(session_row)
        await self._s.flush()
        return session_row

    async def get_by_token_hash(self, token_hash: str) -> Session | None:
        stmt = select(Session).where(Session.token_hash == token_hash)
        return (await self._s.execute(stmt)).scalar_one_or_none()

    async def get(self, session_id: str) -> Session | None:
        return await self._s.get(Session, session_id)

    async def revoke(self, session_row: Session) -> None:
        session_row.revoked_at = utcnow()
        await self._s.flush()

    async def revoke_all_for_user(self, user_id: str) -> None:
        await self._s.execute(
            update(Session)
            .where(Session.user_id == user_id, Session.revoked_at.is_(None))
            .values(revoked_at=utcnow())
        )

    async def list_active(self, user_id: str) -> list[Session]:
        stmt = select(Session).where(
            Session.user_id == user_id,
            Session.revoked_at.is_(None),
            Session.expires_at > utcnow(),
        )
        return list((await self._s.execute(stmt)).scalars())


class PasswordResetRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(self, row: PasswordReset) -> PasswordReset:
        self._s.add(row)
        await self._s.flush()
        return row

    async def get_valid(self, token_hash: str) -> PasswordReset | None:
        stmt = select(PasswordReset).where(
            PasswordReset.token_hash == token_hash,
            PasswordReset.used_at.is_(None),
            PasswordReset.expires_at > utcnow(),
        )
        return (await self._s.execute(stmt)).scalar_one_or_none()

    async def mark_used(self, row: PasswordReset) -> None:
        row.used_at = utcnow()
        await self._s.flush()


class ConsentRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def set(self, user_id: str, consent_type: str, granted: bool) -> Consent:
        row = Consent(user_id=user_id, consent_type=consent_type, granted=granted)
        self._s.add(row)
        await self._s.flush()
        return row

    async def latest(self, user_id: str) -> dict[str, tuple[bool, datetime]]:
        stmt = (
            select(Consent)
            .where(Consent.user_id == user_id)
            .order_by(Consent.created_at.asc())
        )
        latest: dict[str, tuple[bool, datetime]] = {}
        for row in (await self._s.execute(stmt)).scalars():
            latest[row.consent_type] = (row.granted, row.created_at)
        return latest
