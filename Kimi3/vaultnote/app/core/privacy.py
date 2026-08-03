"""
Privacy utilities: PII redaction, pseudonymization, differential privacy.

GDPR Art. 5 (data minimization), Art. 25 (data protection by design),
Art. 32 (pseudonymization as a security measure).
"""
from __future__ import annotations

import hashlib
import math
import re
import secrets
from typing import Any

from app.core.config import settings

# Regex patterns for common PII - used to redact logs and error messages
_EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
_PHONE_RE = re.compile(r"\b\+?\d[\d\s().-]{7,}\d\b")
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def redact_pii(text: str) -> str:
    """Remove PII from free text before it is logged or returned in errors.

    GDPR Art. 5(1)(c) - data minimization.
    IPs are redacted before phone numbers so dotted quads are not
    misclassified as phone numbers.
    """
    text = _EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    text = _IP_RE.sub("[REDACTED_IP]", text)
    text = _PHONE_RE.sub("[REDACTED_PHONE]", text)
    return text


def redact_dict(data: dict[str, Any], sensitive_keys: set[str] | None = None) -> dict[str, Any]:
    """Redact values of sensitive keys in a dictionary (shallow)."""
    sensitive = sensitive_keys or {
        "email", "name", "password", "token", "secret", "phone",
        "first_name", "last_name", "address", "ip", "note_title",
    }
    out: dict[str, Any] = {}
    for k, v in data.items():
        if k.lower() in sensitive:
            out[k] = "[REDACTED]"
        elif isinstance(v, str):
            out[k] = redact_pii(v)
        else:
            out[k] = v
    return out


def pseudonymize(identifier: str, salt: str | None = None) -> str:
    """Irreversible pseudonym of an identifier for analytics.

    GDPR Art. 4(5) pseudonymization - allows analytics without
    re-identifying individuals.
    """
    salt = salt or settings.JWT_SECRET_KEY[:16]
    return hashlib.sha256(f"{salt}:{identifier}".encode()).hexdigest()[:24]


# ---------------------------------------------------------------------------
# Differential Privacy (Laplace mechanism)
# ---------------------------------------------------------------------------

def laplace_noise(scale: float) -> float:
    """Draw one sample from Laplace(0, scale) using inverse CDF."""
    u = secrets.SystemRandom().random() - 0.5
    return -scale * math.copysign(math.log(1 - 2 * abs(u)), u)


def dp_count(true_count: int, epsilon: float | None = None, sensitivity: float = 1.0) -> float:
    """Differentially-private count query.

    GDPR Art. 89(1) - appropriate safeguards for statistical purposes.
    Lower epsilon => more noise => stronger privacy.
    """
    eps = epsilon if epsilon is not None else settings.DP_EPSILON
    eps = max(eps, 0.01)  # prevent division by zero
    return true_count + laplace_noise(sensitivity / eps)


def dp_sum(true_sum: float, epsilon: float | None = None, sensitivity: float = 1.0) -> float:
    """Differentially-private sum query."""
    eps = epsilon if epsilon is not None else settings.DP_EPSILON
    eps = max(eps, 0.01)
    return true_sum + laplace_noise(sensitivity / eps)
