"""Audit logging service.

Writes tamper-evident, PII-free audit entries. The actor is pseudonymized
(HMAC keyed by a secret salt) and any string context values are passed through
``redact`` before storage, so the audit trail can never contain PII or secrets.
"""

from __future__ import annotations

import hashlib
import json

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.compliance import AuditAction
from app.core.config import Settings
from app.core.privacy import pseudonymize, redact
from app.models.audit import AuditLog
from app.repositories import AuditRepository


class AuditService:
    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._repo = AuditRepository(session)
        self._salt = settings.analytics_pseudonym_salt

    def _sanitize_context(self, context: dict | None) -> dict:
        """Keep only short scalar values, redact strings, drop anything risky."""
        clean: dict = {}
        for key, value in (context or {}).items():
            if not isinstance(key, str) or len(key) > 40:
                continue
            if isinstance(value, bool) or isinstance(value, (int, float)):
                clean[key] = value
            elif isinstance(value, str):
                clean[key] = redact(value[:200])
        return clean

    @staticmethod
    def _entry_hash(prev_hash: str | None, canonical: str) -> str:
        h = hashlib.sha256()
        h.update((prev_hash or "").encode())
        h.update(b"\x1f")
        h.update(canonical.encode())
        return h.hexdigest()

    async def record(
        self,
        *,
        action: AuditAction,
        org_id: str | None,
        actor_user_id: str | None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        outcome: str = "success",
        context: dict | None = None,
    ) -> AuditLog:
        actor = (
            pseudonymize(actor_user_id, self._salt) if actor_user_id else None
        )
        clean_context = self._sanitize_context(context)
        prev = await self._repo.last_hash(org_id)
        canonical = json.dumps(
            {
                "action": str(action),
                "org": org_id,
                "actor": actor,
                "rt": resource_type,
                "rid": resource_id,
                "outcome": outcome,
                "ctx": clean_context,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        entry = AuditLog(
            org_id=org_id,
            actor_pseudonym=actor,
            action=str(action),
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            context=json.dumps(clean_context, sort_keys=True),
            prev_hash=prev,
            entry_hash=self._entry_hash(prev, canonical),
        )
        return await self._repo.append(entry)

    async def verify_chain(self, org_id: str) -> bool:
        """Re-derive the hash chain to detect tampering (integrity check)."""
        prev: str | None = None
        for row in await self._repo.all_for_org_chrono(org_id):
            canonical = json.dumps(
                {
                    "action": row.action,
                    "org": row.org_id,
                    "actor": row.actor_pseudonym,
                    "rt": row.resource_type,
                    "rid": row.resource_id,
                    "outcome": row.outcome,
                    "ctx": json.loads(row.context),
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            if row.prev_hash != prev:
                return False
            if row.entry_hash != self._entry_hash(prev, canonical):
                return False
            prev = row.entry_hash
        return True
