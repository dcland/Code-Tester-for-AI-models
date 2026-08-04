"""
Compliance toolkit: durable tamper-evident audit logging, retention helpers.

References:
  - GDPR Art. 17 (Right to Erasure)
  - GDPR Art. 15 / CCPA (Right of Access / Data Portability)
  - GDPR Art. 30 (Records of processing)
  - SOC 2 CC7.2 (monitoring) - immutable audit trail

Design notes:
  * Events are persisted to the ``audit_events`` table, so the trail is
    durable across restarts (unlike the previous in-memory chain).
  * Each event is HMAC-SHA256 signed with a server-side key and chained to
    the hash of the previous event, so modification, deletion, or
    reordering of historical rows is detectable. Without the key, an
    attacker cannot forge a valid entry even with full database access.
  * Metadata is redacted before persistence: no PII or secrets are stored.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.privacy import redact_dict
from app.models.entities import AuditEventRecord

logger = logging.getLogger("vaultnote.audit")
logger.setLevel(logging.INFO)

_GENESIS_HASH = "0" * 64


def _signing_key() -> bytes:
    # Derive a fixed-length key from the configured audit secret.
    return hashlib.sha256((settings.AUDIT_HMAC_KEY or "").encode()).digest()


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True).encode()


def _sign(payload: dict[str, Any]) -> str:
    return hmac.new(_signing_key(), _canonical(payload), hashlib.sha256).hexdigest()


class AuditLog:
    """Durable, append-only, HMAC-chained audit log (SOC 2 / GDPR Art. 30).

    A per-event-loop lock serializes chain-head reads and appends so
    concurrent requests cannot fork the chain.
    """

    _lock: asyncio.Lock | None = None
    _lock_loop: asyncio.AbstractEventLoop | None = None

    @classmethod
    def _get_lock(cls) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        if cls._lock is None or cls._lock_loop is not loop:
            cls._lock = asyncio.Lock()
            cls._lock_loop = loop
        return cls._lock

    @staticmethod
    async def _last_hash(session: AsyncSession) -> str:
        result = await session.execute(
            select(AuditEventRecord.hash).order_by(AuditEventRecord.seq.desc()).limit(1)
        )
        return result.scalar_one_or_none() or _GENESIS_HASH

    @classmethod
    async def record(
        cls,
        session: AsyncSession,
        action: str,
        actor_id: str,
        tenant_id: str,
        resource_type: str,
        resource_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Persist a signed, chained audit event. Never stores PII."""
        async with cls._get_lock():
            prev_hash = await cls._last_hash(session)
            payload = {
                "timestamp": datetime.now(UTC).isoformat(),
                "action": action,
                "actor_id": actor_id,  # already pseudonymized by callers
                "tenant_id": tenant_id,
                "resource_type": resource_type,
                "resource_id": resource_id,
                # GDPR: never store PII/secrets in audit metadata
                "metadata": redact_dict(metadata or {}),
                "prev_hash": prev_hash,
            }
            digest = _sign(payload)
            row = AuditEventRecord(
                timestamp=datetime.fromisoformat(payload["timestamp"]),
                action=action,
                actor_id=actor_id,
                tenant_id=tenant_id,
                resource_type=resource_type,
                resource_id=resource_id,
                metadata_json=json.dumps(payload["metadata"], sort_keys=True),
                prev_hash=prev_hash,
                hash=digest,
            )
            session.add(row)
            await session.flush()
        event = {**payload, "hash": digest}
        logger.info("audit %s", json.dumps(event))
        return event

    @classmethod
    async def verify_chain(cls, session: AsyncSession) -> bool:
        """Verify the integrity of the whole chain (tamper-evidence)."""
        result = await session.execute(
            select(AuditEventRecord).order_by(AuditEventRecord.seq)
        )
        rows = result.scalars().all()
        expected_prev = _GENESIS_HASH
        for row in rows:
            if row.prev_hash != expected_prev:
                return False
            ts = row.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=UTC)
            payload = {
                "timestamp": ts.isoformat(),
                "action": row.action,
                "actor_id": row.actor_id,
                "tenant_id": row.tenant_id,
                "resource_type": row.resource_type,
                "resource_id": row.resource_id,
                "metadata": json.loads(row.metadata_json),
                "prev_hash": row.prev_hash,
            }
            if _sign(payload) != row.hash:
                return False
            expected_prev = row.hash
        return True

    @classmethod
    async def events_for_tenant(
        cls, session: AsyncSession, tenant_id: str
    ) -> list[dict[str, Any]]:
        result = await session.execute(
            select(AuditEventRecord)
            .where(AuditEventRecord.tenant_id == tenant_id)
            .order_by(AuditEventRecord.seq)
        )
        out: list[dict[str, Any]] = []
        for row in result.scalars().all():
            ts = row.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=UTC)
            out.append({
                "timestamp": ts.isoformat(),
                "action": row.action,
                "actor_id": row.actor_id,
                "tenant_id": row.tenant_id,
                "resource_type": row.resource_type,
                "resource_id": row.resource_id,
                "metadata": json.loads(row.metadata_json),
                "prev_hash": row.prev_hash,
                "hash": row.hash,
            })
        return out


def retention_days_for_plan(plan: str) -> int:
    """GDPR Art. 5(1)(e) - storage limitation based on plan."""
    return settings.RETENTION_DAYS_FREE if plan.lower() == "free" else settings.RETENTION_DAYS_PAID
