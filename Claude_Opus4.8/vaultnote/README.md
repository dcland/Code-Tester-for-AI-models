# VaultNote

**End-to-End Encrypted, Multi-Tenant Collaborative Workspace Platform** — a secure
alternative to Notion + Dropbox. Organizations create workspaces, invite members,
store envelope-encrypted notes and files, collaborate in real time, manage billing,
and view privacy-preserving analytics — GDPR, CCPA, and SOC 2 aware by design.

Built with FastAPI, Pydantic v2, SQLAlchemy 2.0 (async), `cryptography`,
`argon2-cffi`, and PyJWT. SQLite for the demo; swap the URL for Postgres in prod.

---

## Quick start (single command after install)

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 1) Seed two demo orgs with users, notes, and files:
python -m scripts.seed_demo

# 2) Run the API:
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000/docs for the interactive OpenAPI UI, or
http://127.0.0.1:8000/health for a liveness check.

Demo accounts (all share password `Demo!Password123`):
`founder@acme.test`, `eng@acme.test`, `owner@globex.test`, `ops@globex.test`.

No secrets or Redis are required for local runs — development secrets are derived
deterministically and rate limiting falls back to a pure-Python limiter.

## Run the tests

```bash
pip install -r requirements.txt
pytest            # 67 tests: happy paths, security, privacy, compliance, perf
```

---

## Architecture

Clean layered architecture with explicit dependency injection (no service
locator, no God classes). Each layer depends only on the one below it.

```
app/
├── main.py                 # app factory, router wiring, lifespan
├── core/                   # framework-agnostic primitives
│   ├── config.py           # env-only settings; prod secret enforcement
│   ├── security.py         # Argon2id + pepper, JWT, TOTP, constant-time cmp
│   ├── encryption.py       # 3-tier envelope encryption (AES-256-GCM)
│   ├── privacy.py          # PII redaction, pseudonymization, diff. privacy
│   ├── compliance.py       # audit taxonomy, retention rules
│   ├── cache.py            # O(1) LRU + TTL cache for hot notes
│   ├── ratelimit.py        # sliding-window limiter (Redis or in-memory)
│   ├── container.py        # composition root (singletons)
│   └── exceptions.py       # typed exception hierarchy
├── db/                     # engine, session factory, declarative base
├── models/                 # SQLAlchemy ORM (tenant-scoped, indexed)
├── schemas/                # Pydantic v2 request/response contracts
├── repositories/           # data access; every query tenant-scoped + parameterized
├── services/               # business logic (auth, notes, files, billing, …)
├── api/                    # FastAPI deps, error handlers, versioned routers
├── middleware/             # security headers + request id
└── utils/                  # file validation & encrypted blob storage
```

**Request flow:** middleware (security headers) → router → dependencies
(`get_session`, `get_current_user`, `get_tenant_context`, `rate_limit`) →
service → repository → DB. Services own transactions; repositories never commit.

---

## Security model (OWASP Top 10)

| Control | Implementation |
|---|---|
| **Password storage** | Argon2id (`argon2-cffi`) with a **server-side pepper** applied via HMAC before hashing, so a DB leak alone is not brute-forceable. Opportunistic rehash on login. |
| **Sessions** | 15-min JWT access tokens **bound to a server session** + 7-day **rotating** refresh tokens stored only as SHA-256 hashes. Revoking a session (logout / logout-all / password change) invalidates the access token immediately. |
| **Brute force / stuffing** | Per-account lockout after N failures + sliding-window rate limits (stricter buckets for auth). Unknown-user logins still perform a dummy Argon2 verify (timing-attack & enumeration resistance). |
| **2FA** | Optional TOTP (RFC 6238), verified in constant time with a drift window. |
| **Encryption at rest** | Three-tier envelope encryption (see below), AES-256-GCM with per-object AAD binding (tenant+object id) to prevent ciphertext replay. |
| **Injection** | 100% parameterized SQLAlchemy; no string SQL. Pydantic `extra="forbid"` blocks mass-assignment. |
| **Broken access control** | Central `AccessService` computes least-privilege effective permission (role ∨ ownership ∨ shares, capped by role). Every resource lookup is tenant-scoped. |
| **Path traversal** | Uploaded file names never build a path; blobs use random opaque storage keys; the blob store re-validates the resolved path stays inside its root. |
| **Malicious uploads** | Magic-byte sniffing (client type ignored), executable/script signatures rejected, size limits, EICAR virus-scan hook. |
| **Secure headers** | `nosniff`, `DENY` framing, strict CSP, `no-store`, HSTS, referrer/permissions policy, `Server` masked. |
| **Secrets** | Loaded from environment only; production refuses to boot without them. |
| **SSRF/CSRF** | No server-side fetching of user URLs; token-in-header auth (not cookies) sidesteps CSRF. |

### Envelope encryption

```
MASTER KEK  (env only, 32 bytes)
  └─ wraps each TENANT MASTER KEY (TMK, per organization)
       └─ wraps each DATA ENCRYPTION KEY (DEK, per note/file)
            └─ encrypts the note body / file bytes / file name
```

Only DEKs touch plaintext, and DEKs are stored wrapped. **Key rotation**
(`rotate_tenant_key`) re-wraps DEKs without re-encrypting payloads — an O(objects)
metadata operation. The design is zero-knowledge-friendly: if a client submits
ciphertext, the server stores and serves it without ever seeing plaintext.

---

## Privacy model (Privacy by Design — GDPR Art. 25)

- **Data minimization:** the DB stores the minimum needed; note titles/bodies,
  file names, and folder names are all ciphertext.
- **No PII in logs or audit:** `privacy.redact()` masks emails/IPs/tokens in every
  error and log line; the audit log stores a **pseudonymized** actor (keyed HMAC)
  and PII-free context only.
- **Differential privacy:** the analytics dashboard perturbs every aggregate with
  the Laplace mechanism (configurable ε) so individual behavior can't be
  reconstructed; no per-user breakdowns are ever exposed.
- **Pseudonymization:** analytics/audit identifiers are keyed HMACs — stable for
  counting, non-reversible without the salt.

---

## Compliance toolkit

| Regulation | Feature | Endpoint |
|---|---|---|
| **GDPR Art. 15 / CCPA** | Machine-readable data export (JSON manifest + ZIP of encrypted file blobs) | `GET /api/v1/me/export` |
| **GDPR Art. 17** | Cascading erasure of a user (and orphaned orgs) | `DELETE /api/v1/me` |
| **GDPR Art. 17** | Full tenant erasure (owner only) | `DELETE /api/v1/organizations/{org_id}` |
| **GDPR Art. 7** | Consent ledger (grant/withdraw, demonstrable) | `PUT/GET /api/v1/me/consents` |
| **GDPR Art. 5(1)(e)** | Retention purge of soft-deleted content (30d free / 365d paid) | `POST /api/v1/organizations/{org_id}/retention/purge` |
| **SOC 2 CC7 / Art. 30** | Immutable, tamper-evident (hash-chained), PII-free audit trail | `GET /api/v1/organizations/{org_id}/audit[/verify]` |

Erasure retains only the pseudonymized, PII-free audit entries (permitted under
Art. 17(3)(b)). Every sensitive action (login, share, delete, export, key
rotation, plan change) is audited with a named action code.

---

## Performance

- **Envelope AES-256-GCM** uses hardware AES-NI: a 10 MB round trip is well under
  budget (see `tests/test_performance.py`).
- **Hot-note LRU cache** (O(1) get/put, TTL + capacity bound) avoids repeated
  decryption of frequently read notes.
- **Rate limiter / cache lookups** are O(1) amortized.
- **Query hygiene:** targeted indexes (`org_id`, `updated_at`, token hashes),
  tenant-scoped predicates, no N+1 in list endpoints (titles decrypted in a single
  pass; list views avoid decrypting bodies).

---

## Billing

Plans **Free / Pro / Business / Enterprise** with per-seat pricing, storage &
seat limits, and API-call metering. Plan changes are **prorated** and generate
invoices. **PCI-DSS:** only opaque processor tokens are ever accepted or stored —
raw card numbers are rejected at validation; no PAN/CVV touches the system.

---

## Real-time collaboration

`CollaborationEngine` provides presence (heartbeat + TTL) and a simplified
operational-transform interface: edits are expressed against a base version and
transformed against concurrent operations before applying. The surface is
CRDT/OT-ready — a Redis/websocket fan-out layer plugs in without changing the API.

---

## Configuration

All configuration is environment-driven (`VAULTNOTE_*`, see `.env.example`).
Production requires `JWT_SECRET`, `PASSWORD_PEPPER`, `MASTER_KEK` (base64 of 32
bytes), and `ANALYTICS_PSEUDONYM_SALT`, or the app refuses to start.

Generate a master KEK:

```bash
python -c "import os,base64;print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
```

## Notes & limitations (demo scope)

- SQLite + local disk blob storage are used for a single-command demo; the
  repository/session abstractions target Postgres and object storage unchanged.
- Presence and the OT op-log are in-process (single node); production would move
  them to Redis. Email delivery (password reset) is stubbed — in non-production
  the reset token is returned in the API response for end-to-end testing.
- The virus scanner is an interface with an EICAR-detecting stub, ready to wire
  to ClamAV/ICAP.
