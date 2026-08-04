"""
Transactional mailer abstraction.

In production this would integrate with an email provider (SES, SendGrid,
...). For development and tests, messages are captured in an in-memory
outbox instead of being sent, and only the redacted recipient is logged
(GDPR Art. 5(1)(c) - data minimization in logs).

The outbox is the ONLY way a raw password-reset token leaves the service;
it is never returned in an API response.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field

from app.core.privacy import redact_pii

logger = logging.getLogger("vaultnote.mailer")


@dataclass
class Outbox:
    """Thread-safe capture of 'sent' messages (dev/test only)."""

    _messages: list[dict] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def append(self, message: dict) -> None:
        with self._lock:
            self._messages.append(message)

    def latest_for(self, to: str) -> dict | None:
        with self._lock:
            for msg in reversed(self._messages):
                if msg.get("to") == to:
                    return msg
        return None

    def clear(self) -> None:
        with self._lock:
            self._messages.clear()


outbox = Outbox()


class Mailer:
    """Pluggable mailer interface. Swap ``send`` for a real provider in prod."""

    @staticmethod
    def send(to: str, subject: str, body: str) -> None:
        outbox.append({"to": to, "subject": subject, "body": body})
        # Never log the body (it contains secrets); log redacted recipient only.
        logger.info("email queued to=%s subject=%s", redact_pii(to), subject)

    @staticmethod
    def send_password_reset(to: str, token: str) -> None:
        Mailer.send(
            to,
            "VaultNote password reset",
            f"Your password reset token is: {token}\nIt expires shortly.",
        )
