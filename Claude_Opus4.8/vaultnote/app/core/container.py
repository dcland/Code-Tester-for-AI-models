"""Composition root: builds and owns long-lived singletons.

Explicit dependency injection (no global service locator inside business logic).
The container is created once at startup and attached to ``app.state``.
"""

from __future__ import annotations

from app.core.cache import LRUCache
from app.core.config import Settings, get_settings
from app.core.encryption import EnvelopeEncryptor
from app.core.ratelimit import RateLimiter
from app.core.security import SecurityService
from app.db.session import Database
from app.services.collab_service import CollaborationEngine
from app.utils.files import BlobStore


class Container:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.database = Database(self.settings)
        self.security = SecurityService(self.settings)
        self.encryptor = EnvelopeEncryptor(self.settings.master_kek_bytes)
        self.rate_limiter = RateLimiter.create(self.settings.redis_url)
        self.note_cache: LRUCache = LRUCache(capacity=2048, ttl_seconds=60.0)
        self.blob_store = BlobStore(self.settings.storage_dir)
        self.collab = CollaborationEngine()

    async def startup(self) -> None:
        await self.database.init()

    async def shutdown(self) -> None:
        await self.database.dispose()
