# VaultNote

**End-to-End Encrypted Multi-Tenant Collaborative Workspace Platform**

VaultNote is a production-grade, privacy-first alternative to Notion + Dropbox.  
Organizations can create secure workspaces, manage members with fine-grained roles, write encrypted notes, upload encrypted files, share content safely, track usage with differential privacy, and handle billing — all while meeting strict GDPR, CCPA, and SOC 2 requirements.

> Built as a rigorous test case for AI code-generation benchmarks (AICGB v2.0).  
> The entire codebase is designed to be evaluated on correctness, performance, security, privacy, compliance, and engineering quality.

---

## Features

- **Multi-tenant architecture** with strict data isolation
- **End-to-end style encryption** (AES-256-GCM envelope encryption + key rotation)
- **Secure authentication** (Argon2id + pepper, rotating refresh tokens, optional TOTP)
- **Hierarchical folders & fine-grained sharing**
- **Secure file upload** with magic-byte validation and encrypted storage
- **Sliding-window rate limiting** (per user + per tenant)
- **Subscription billing engine** (Free / Pro / Business / Enterprise) – PCI-DSS aware
- **Privacy-preserving analytics** with configurable differential privacy
- **Full compliance toolkit**:
  - GDPR Art. 15 / 17 / 25 / 32
  - CCPA data export & deletion
  - Immutable audit logs (no PII)
  - Automatic data retention & purge jobs
- High-performance design (target < 80 ms p95 on core endpoints)
- Comprehensive test suite (> 40 tests)

---

## Tech Stack

| Component          | Technology                          |
|--------------------|-------------------------------------|
| Language           | Python 3.12                         |
| Framework          | FastAPI                             |
| Validation         | Pydantic v2                         |
| ORM                | SQLAlchemy 2.0 (async)              |
| Database           | SQLite (dev) / PostgreSQL ready     |
| Encryption         | `cryptography` (AES-256-GCM)        |
| Password Hashing   | `argon2-cffi`                       |
| Auth               | JWT (access + rotating refresh)     |
| Caching / Rate Limit | Redis (with pure-Python fallback) |
| Testing            | pytest + pytest-asyncio             |

---

## Project Structure# Code-Tester-for-AI-models
