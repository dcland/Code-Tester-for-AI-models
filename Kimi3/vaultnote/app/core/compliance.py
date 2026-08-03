"""
Compliance toolkit: immutable audit logging, data retention, erasure helpers.

References:
  - GDPR Art. 17 (Right to Erasure)
  - GDPR Art. 15 / CCPA (Right of Access / Data Portability)
  - GDPR Art. 30 (Records of processing)
  - SOC 2 CC7.2 (monitoring) - immutable audit trail
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

from app.core.privacy import redact_dict

logger = logging.getLogger("vaultnote.audit")
logger.setLevel(logging.INFO)


class AuditEvent:
    """A single immutable, PII-free audit record."""

    def __init__(
        self,
        action: str,
        actor_id: str,
        tenant_id: str,
        resource_type: str,
        resource_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.action = action
        self.actor_id = actor_id  # already a UUID (pseudonymous)
        self.tenant_id = tenant_id
        self.resource_type = resource_type
        self.resource_id = resource_id
        # GDPR: never store PII/secrets in audit metadata
        self.metadata = redact_dict(metadata or {})
        # Immutability: chained hash links each record to the previous one
        self.prev_hash = AuditLog.last_hash()
        self.hash = self._compute_hash()

    def _compute_hash(self) -> str:
        payload = json.dumps(
            {
                "timestamp": self.timestamp,
                "action": self.action,
                "actor_id": self.actor_id,
                "tenant_id": self.tenant_id,
                "resource_type": self.resource_type,
                "resource_id": self.resource_id,
                "metadata": self.metadata,
                "prev_hash": self.prev_hash,
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "action": self.action,
            "actor_id": self.actor_id,
            "tenant_id": self.tenant_id,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "metadata": self.metadata,
            "prev_hash": self.prev_hash,
            "hash": self.hash,
        }


class AuditLog:
    """Append-only, hash-chained audit log (SOC 2 / GDPR Art. 30).

    In production this would write to WORM storage (e.g. S3 Object Lock).
    Here we keep an in-memory chain and log each event.
    """

    _chain: list[str] = []
    _events: list[dict[str, Any]] = []

    @classmethod
    def last_hash(cls) -> str:
        return cls._chain[-1] if cls._chain else "0" * 64

    @classmethod
    def record(
        cls,
        action: str,
        actor_id: str,
        tenant_id: str,
        resource_type: str,
        resource_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        event = AuditEvent(action, actor_id, tenant_id, resource_type, resource_id, metadata)
        cls._chain.append(event.hash)
        cls._events.append(event.to_dict())
        logger.info("audit %s", json.dumps(event.to_dict()))
        return event.to_dict()

    @classmethod
    def verify_chain(cls) -> bool:
        """Verify integrity of the audit chain (tamper-evidence)."""
        for i, ev in enumerate(cls._events):
            expected_prev = cls._chain[i - 1] if i > 0 else "0" * 64
            if ev["prev_hash"] != expected_prev:
                return False
            recalced = hashlib.sha256(
                json.dumps(
                    {k: ev[k] for k in
                     ("timestamp", "action", "actor_id", "tenant_id",
                      "resource_type", "resource_id", "metadata", "prev_hash")},
                    sort_keys=True,
                ).encode()
            ).hexdigest()
            if recalced != ev["hash"]:
                return False
        return True

    @classmethod
    def events_for_tenant(cls, tenant_id: str) -> list[dict[str, Any]]:
        return [e for e in cls._events if e["tenant_id"] == tenant_id]

    @classmethod
    def reset(cls) -> None:
        """Testing helper - clears the chain."""
        cls._chain.clear()
        cls._events.clear()


def retention_days_for_plan(plan: str) -> int:
    """GDPR Art. 5(1)(e) - storage limitation based on plan."""
    from app.core.config import settings
    return settings.RETENTION_DAYS_FREE if plan.lower() == "free" else settings.RETENTION_DAYS_PAID
