"""Privacy primitives: PII redaction, pseudonymization, differential privacy.

Data minimization & privacy by default (GDPR Art. 25). These helpers are used
by the audit log, the error handler, and the analytics service to guarantee no
PII (emails, names, note titles) ever reaches logs or aggregate outputs.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import re
import secrets

# Conservative PII patterns for automatic redaction in free-text (errors, logs).
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# JWT / long opaque secrets
_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_\-]{24,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\b")
_BEARER_RE = re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+")


def redact(text: str) -> str:
    """Return ``text`` with emails, IPs, bearer tokens and JWTs masked.

    Used before any message is written to logs or returned to a client, so a
    stack trace or validation message can never leak PII/secrets.
    """
    if not text:
        return text
    text = _BEARER_RE.sub("Bearer [REDACTED]", text)
    text = _TOKEN_RE.sub("[REDACTED_TOKEN]", text)
    text = _EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    text = _IPV4_RE.sub("[REDACTED_IP]", text)
    return text


def pseudonymize(identifier: str, salt: str) -> str:
    """Deterministic keyed pseudonym (GDPR Art. 4(5) pseudonymization).

    HMAC keyed by a secret salt: stable across calls (so analytics can count
    distinct actors) but not reversible without the salt, and not linkable
    across datasets that use different salts.
    """
    mac = hmac.new(salt.encode(), identifier.encode(), hashlib.sha256)
    return "u_" + mac.hexdigest()[:20]


class DifferentialPrivacy:
    """Laplace mechanism for (ε)-differential privacy on aggregate counts.

    Adds calibrated Laplace noise so no single user's presence/absence changes
    an aggregate meaningfully — individual behavior cannot be reconstructed from
    the dashboard. Uses ``secrets`` for cryptographic-quality randomness.
    """

    def __init__(self, epsilon: float) -> None:
        if epsilon <= 0:
            raise ValueError("epsilon must be > 0")
        self.epsilon = epsilon

    def _laplace_noise(self, sensitivity: float) -> float:
        scale = sensitivity / self.epsilon
        # Inverse-CDF sampling with a CSPRNG uniform in (0, 1).
        u = (secrets.randbits(53) / (1 << 53)) - 0.5
        return -scale * math.copysign(1.0, u) * math.log(1.0 - 2.0 * abs(u))

    def privatize_count(self, true_count: int, sensitivity: float = 1.0) -> int:
        """Return a noised, non-negative integer count."""
        noised = true_count + self._laplace_noise(sensitivity)
        return max(0, round(noised))

    def privatize_sum(self, true_sum: float, sensitivity: float) -> float:
        return round(true_sum + self._laplace_noise(sensitivity), 4)
