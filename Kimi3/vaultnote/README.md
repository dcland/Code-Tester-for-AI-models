# VaultNote

**End-to-End Encrypted Multi-Tenant Collaborative Workspace Platform**
GDPR · CCPA · SOC 2 ready. Built with FastAPI, SQLAlchemy 2.0 (async), AES-256-GCM envelope encryption, and Argon2id.

---

## Quick Start

```bash
# 1. Install dependencies (Python 3.12+)
pip install -r requirements.txt

# 2. (Optional in dev, REQUIRED in production) configure secrets.
#     With VAULTNOTE_ENVIRONMENT=production the server refuses to boot
#     unless every secret below is explicitly set (fail-closed).
export VAULTNOTE_JWT_SECRET_KEY="$(openssl rand -base64 48)"
export VAULTNOTE_PASSWORD_PEPPER="$(openssl rand -base64 32)"
export VAULTNOTE_MASTER_ENCRYPTION_KEY="$(openssl rand -base64 32)"
export VAULTNOTE_PSEUDONYM_SALT="$(openssl rand -base64 32)"
export VAULTNOTE_AUDIT_HMAC_KEY="$(openssl rand -base64 32)"

# 3. Seed demo data (two orgs, users, notes, a file)
python -m scripts.seed_demo

# 4. Run the server
uvicorn app.main:app --reload
```

API is at `http://localhost:8000`. Interactive docs (dev only): `http://localhost:8000/docs` (set `VAULTNOTE_DEBUG=true`).

Run tests:

```bash
pytest -v
```

---

## Architecture

```
app/
├── core/            # config, security (Argon2/JWT/TOTP), encryption, privacy, compliance
├── models/          # SQLAlchemy 2.0 ORM + async engine
├── schemas/         # Pydantic v2 request validation
├── api/v1/          # auth, workspaces, notes, files, billing, analytics, admin
├── services/        # business logic (auth, notes, files, billing, collab, compliance, analytics)
├── repositories/    # data access (parameterized, tenant-scoped)
├── middleware/      # security headers, rate limiting, request IDs
└── utils/           # exceptions, LRU cache, rate limiter
```

Clean layered architecture: **API → Service → Repository → Model**. Dependency injection via FastAPI `Depends`. No God classes.

---

## Security Model

| Control | Implementation |
|---|---|
| Password hashing | **Argon2id** (64 MiB, t=3, p=4) + server-side pepper |
| Access tokens | JWT, 15 min expiry, HS256 |
| Refresh tokens | 7-day, **rotating**, stored as SHA-256 hashes |
| 2FA | TOTP (RFC 6238), pure-Python, constant-time verify |
| Encryption | **AES-256-GCM** envelope: DEK per item → tenant KEK → master key |
| Key rotation | Re-wraps DEKs without touching plaintext |
| Resource authorization | Centralized `AccessService`: role ceilings (viewer=read), ownership, share grants, workspace↔tenant binding on every route |
| Sharing | Requires admin on the resource; grantee must be a member of the **same** organization (cross-tenant grants rejected) |
| Password reset | Hashed, expiring, single-use tokens; delivered by email only; sessions revoked on confirm |
| Rate limiting | Sliding window, per-IP/per-user, O(1); Redis or pure-Python |
| Headers | CSP, HSTS, X-Frame-Options, nosniff, etc. |
| SQL injection | SQLAlchemy parameterized queries only |
| Path traversal | Filename sanitization + random storage names + path confinement |
| Timing attacks | Constant-time compare, dummy verify for unknown users |
| File validation | Magic-byte sniffing + declared-MIME cross-check, size limits, pluggable virus-scan interface |
| Secrets | Fail-closed in production; ephemeral random defaults in dev only |

All secrets are loaded **only** from environment variables.

---

## Privacy Model

* **Data minimization** - only essential fields are collected.
* **PII redaction** - emails/IPs/phones are scrubbed from logs and errors.
* **Pseudonymization** - user IDs are HMAC-SHA256 pseudonymized (dedicated salt) before entering analytics/audit.
* **Differential privacy** - all dashboard aggregates include Laplace noise (configurable ε).
* **No PII in audit logs** - only pseudonymous IDs and actions.

---

## Compliance

| Regulation | Feature |
|---|---|
| GDPR Art. 15 / CCPA | Data export (JSON + ZIP) |
| GDPR Art. 17 | Cascading user & org erasure - **including physical file blobs** |
| GDPR Art. 7 | Consent management |
| GDPR Art. 5(1)(e) | Plan-aware retention + automatic scheduled purge (tenant-scoped endpoint for manual runs) |
| GDPR Art. 25 | Privacy by design/default |
| GDPR Art. 30 / SOC 2 | **Durable** (DB-persisted), HMAC-signed, hash-chained audit log (tamper-evident) |
| GDPR Art. 32 | Encryption at rest, key rotation |
| GDPR Art. 89 | Differential privacy for statistics |
| PCI-DSS | Only payment **tokens** stored, never card data |

---

## Multi-Tenancy

Every tenant-scoped row carries `organization_id`. The `X-Organization-ID` header is validated against the user's memberships on every request. Cross-tenant access returns `403` (or `404` to avoid existence leaks).

---

## Performance

* O(1) rate limiter and LRU cache lookups.
* Cached note reads (<80 ms p95 target).
* AES-GCM encrypts 10 MB in well under 120 ms.
* Indexed foreign keys and composite indexes on hot query paths.

---

## API Overview

| Area | Endpoint |
|---|---|
| Auth | `POST /api/v1/auth/register`, `/login`, `/refresh`, `/logout`, `/2fa/*` |
| Workspaces | `GET/POST /api/v1/workspaces` |
| Notes | `GET/POST/PATCH/DELETE /api/v1/workspaces/{id}/notes` |
| Folders | `GET/POST /api/v1/workspaces/{id}/folders` |
| Sharing | `POST .../notes/{id}/share`, `/share-link` |
| Collab | `POST/GET .../notes/{id}/operations`, `/presence` |
| Files | `POST/GET/DELETE /api/v1/workspaces/{id}/files`, `/download-token`, `/download` |
| Billing | `GET /api/v1/billing/subscription`, `POST /plan`, `GET /invoices` |
| Analytics | `GET /api/v1/analytics/dashboard` |
| Admin | `/api/v1/admin/export`, `/users/me`, `/organization`, `/consent`, `/retention/purge`, `/keys/rotate`, `/audit`, `/audit/verify` |

### File upload protocol

Uploads use a **raw binary request body** (no multipart form parsing, so no
`python-multipart` dependency):

```bash
curl -X POST "http://localhost:8000/api/v1/workspaces/{ws_id}/files" \
  -H "Authorization: Bearer $TOKEN" -H "X-Organization-ID: $ORG" \
  -H "X-File-Name: logo.png" -H "Content-Type: image/png" \
  --data-binary @logo.png
```

The declared `Content-Type` is cross-checked against the detected magic
bytes; mismatches are rejected with `422`.

### Authorization model

Effective permission = max(tenant role, resource ownership, share grant on
the note or its folder), capped by the role ceiling (a `viewer` never
exceeds read). Notes are private by default: creators and org
owners/admins have full control; members and viewers only see notes shared
with them. Share grants may only target members of the same organization.
