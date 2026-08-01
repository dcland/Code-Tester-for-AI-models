You are a Principal Software Engineer and Security Architect with 15+ years of experience building high-scale, regulated SaaS platforms. You write clean, production-ready, highly secure, privacy-first, and compliance-aware code. You never cut corners on security, privacy, or performance.

Your task is to design and implement a complete, runnable backend for a complex multi-tenant SaaS product called:

**"VaultNote" – End-to-End Encrypted Multi-Tenant Collaborative Workspace Platform**

VaultNote is a secure alternative to Notion + Dropbox. Organizations (tenants) can create workspaces, invite members, create encrypted notes and folders, upload encrypted files, collaborate in real time (simulated), manage billing, and view privacy-preserving analytics — all while being fully GDPR, CCPA, and SOC 2 ready.

### High-Level Requirements

Build a complete Python 3.12 backend using only the following allowed libraries:
- FastAPI
- Pydantic v2
- SQLAlchemy 2.0 (async)
- asyncpg or aiosqlite (for simplicity use SQLite in-memory + file for demo)
- cryptography
- argon2-cffi
- redis (or a pure-Python in-memory fallback if Redis is not available)
- python-jose / PyJWT
- httpx
- pytest + pytest-asyncio
- uvicorn

No other third-party libraries are allowed unless they are pure security utilities from the cryptography ecosystem.

The system must be structured as a clean, modular monorepo with the following top-level structure:

vaultnote/
├── app/
│   ├── main.py
│   ├── core/
│   │   ├── config.py
│   │   ├── security.py
│   │   ├── encryption.py
│   │   ├── privacy.py
│   │   └── compliance.py
│   ├── models/
│   ├── schemas/
│   ├── api/
│   │   ├── v1/
│   │   │   ├── auth.py
│   │   │   ├── workspaces.py
│   │   │   ├── notes.py
│   │   │   ├── files.py
│   │   │   ├── billing.py
│   │   │   ├── analytics.py
│   │   │   └── admin.py
│   ├── services/
│   ├── repositories/
│   ├── middleware/
│   └── utils/
├── tests/
├── scripts/
├── docker-compose.yml (optional)
├── README.md
├── requirements.txt
└── pyproject.toml

### Functional Requirements (must all be fully implemented)

1. Multi-tenant architecture
   - Every resource belongs to an Organization (tenant).
   - Strict tenant isolation at the database and application level.
   - Users can belong to multiple organizations with different roles (Owner, Admin, Member, Viewer).

2. Authentication & Session Management
   - Email + password registration and login.
   - Argon2id password hashing with a server-side pepper.
   - JWT access tokens (15 min) + rotating refresh tokens (7 days) stored hashed.
   - Secure password reset flow.
   - Optional TOTP 2FA.
   - Protection against timing attacks, credential stuffing, and brute force.
   - Session revocation on password change or logout from all devices.

3. End-to-End Encrypted Notes & Files
   - Notes and files are encrypted client-side in a real system, but for this backend you must implement server-side envelope encryption using AES-256-GCM.
   - Each note/file has a unique data encryption key (DEK) that is itself encrypted with a tenant master key.
   - Support for key rotation.
   - Zero-knowledge design where possible (server never sees plaintext if the client sends ciphertext).

4. Hierarchical Folders & Sharing
   - Nested folders.
   - Share notes/folders with specific users or roles inside the tenant with fine-grained permissions (read, write, admin).
   - Public share links with optional password and expiration (encrypted).

5. Real-time collaboration simulation
   - Presence and simple operational transformation or CRDT-ready interface for notes (you can implement a simplified version).

6. File Upload Service
   - Secure file upload with magic-byte validation, size limits, virus-scan interface (stub), path-traversal protection.
   - Files stored encrypted at rest.
   - Generate short-lived download tokens.

7. Rate Limiting
   - Sliding-window rate limiter per user and per tenant.
   - Different limits for different endpoints.
   - Redis-backed (with pure Python fallback).

8. Billing & Subscription Engine
   - Plans: Free, Pro, Business, Enterprise.
   - Usage metering (storage, number of seats, API calls).
   - Invoice generation.
   - Never store full payment card data (PCI-DSS aware – only tokens).
   - Proration and plan changes.

9. Privacy-Preserving Analytics
   - Dashboard showing usage statistics.
   - Must apply differential privacy (configurable ε) on aggregate metrics.
   - No individual user behavior can be reconstructed.

10. Full Compliance Toolkit
    - GDPR Article 17 (Right to Erasure) – complete, cascading deletion of a user or entire organization.
    - GDPR Article 15 / CCPA – data export in machine-readable format (JSON + ZIP of encrypted files).
    - Consent management.
    - Data retention policies with automatic purge jobs.
    - Immutable audit log that never contains PII or secrets.
    - Data Protection by Design and by Default (GDPR Art. 25).

### Non-Functional Requirements (these are critical for scoring)

#### Performance
- All core endpoints (get note, list notes, upload small file) must respond in < 80 ms p95 under load of 200 concurrent users on a single machine.
- File encryption/decryption of 10 MB must complete in < 120 ms.
- Rate limiter and cache lookups must be O(1).
- Database queries must be optimized (proper indexes, no N+1).
- Memory usage must stay reasonable; implement an LRU cache for hot notes with TTL.

#### Security
- Follow OWASP Top 10 strictly.
- No SQL injection, XSS, CSRF, SSRF, path traversal, insecure deserialization.
- All secrets (JWT secret, encryption master keys, pepper) loaded from environment variables only.
- Use constant-time comparisons.
- Secure headers middleware.
- Input validation with Pydantic on every endpoint.
- Principle of least privilege for database roles (simulated).

#### Privacy
- Strict data minimization.
- Never log emails, names, note titles, or any PII.
- Automatic redaction of PII in error messages and audit logs.
- Support for pseudonymization of user identifiers in analytics.

#### Compliance
- Explicit comments in code referencing the relevant regulation when a control is implemented (e.g. “# GDPR Art. 17 – cascading delete”).
- Configurable data retention (default 30 days for free tier, 365 for paid).
- Audit trail of every sensitive action (login, share, delete, export, key rotation) without storing sensitive content.

### Deliverables you must produce

1. Complete, working source code for the entire application as described.
2. A comprehensive README.md explaining architecture, how to run, security model, privacy model, and compliance features.
3. At least 40 high-quality pytest tests covering:
   - Happy paths
   - Security attacks (injection, broken access control, etc.)
   - Privacy (no PII leakage)
   - Compliance (erasure, export)
   - Performance smoke tests
   - Multi-tenancy isolation
4. A `scripts/seed_demo.py` that creates two organizations with users, notes, and files so the system can be demoed immediately.
5. Clear type hints everywhere, docstrings, and meaningful comments only where they add security/privacy/compliance value.
6. The code must be production-quality: clean architecture, dependency injection where appropriate, no God classes, proper error handling with custom exception hierarchy.

### Constraints & Rules
- Single response only. Deliver the full solution in one go.
- Do not use placeholder comments such as “# TODO: implement security”. Everything must be fully implemented.
- Prefer pure Python implementations for rate limiting and LRU when Redis is unavailable.
- The system must start with a single command after installing requirements.
- Prioritize correctness, then security, then privacy, then compliance, then performance, then beauty of code.

Begin by outputting the full project structure, then the content of every file. Make the implementation as complete and battle-tested as possible.
