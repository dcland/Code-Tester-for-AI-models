"""Async engine / session management."""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import Settings
from app.db.base import Base


def create_engine(settings: Settings) -> AsyncEngine:
    connect_args: dict = {}
    engine_kwargs: dict = {"echo": False, "future": True, "pool_pre_ping": True}
    if settings.database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
        if ":memory:" in settings.database_url:
            # A single shared connection so an in-memory DB (and its schema) is
            # visible across all sessions — required for tests.
            from sqlalchemy.pool import StaticPool

            engine_kwargs["poolclass"] = StaticPool
            engine_kwargs.pop("pool_pre_ping", None)
    engine = create_async_engine(
        settings.database_url,
        connect_args=connect_args,
        **engine_kwargs,
    )

    # Enforce referential integrity on SQLite (needed for cascading deletes —
    # GDPR Art. 17). SQLite disables FK enforcement by default.
    if settings.database_url.startswith("sqlite"):

        @event.listens_for(engine.sync_engine, "connect")
        def _fk_pragma(dbapi_conn, _record):  # type: ignore[no-untyped-def]
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA journal_mode=WAL")
            cur.close()

    return engine


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def init_models(engine: AsyncEngine) -> None:
    # Import models so they register on the metadata before create_all.
    import app.models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


class Database:
    """Owns the engine + session factory for the app lifetime."""

    def __init__(self, settings: Settings) -> None:
        self.engine = create_engine(settings)
        self.session_factory = create_session_factory(self.engine)

    async def init(self) -> None:
        await init_models(self.engine)

    async def dispose(self) -> None:
        await self.engine.dispose()

    async def session(self) -> AsyncIterator[AsyncSession]:
        async with self.session_factory() as session:
            yield session
