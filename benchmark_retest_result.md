# VaultNote Kimi3 retest result

Date: 2026-08-04  
Submission retested: `Kimi3/vaultnote`  
Benchmark: AICGB v2.0 using `software_creation_prompt.md` and `test_prompt.md`

## Verdict

The revised Kimi3 submission now runs successfully and no longer qualifies for the earlier −30 critical authorization penalty. Its updated score is **84/100 without a penalty**. Against the previously measured Claude Opus 4.8 score of **85/100**, Claude remains the overall winner by one point.

| Submission | Correctness /25 | Performance /15 | Security /20 | Privacy /15 | Compliance /15 | Quality /10 | Raw | Penalty | Final |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Claude Opus 4.8 (previous run) | 22 | 13 | 17 | 13 | 12 | 8 | **85** | 0 | **85** |
| Kimi3 (current retest) | 21 | 11 | 17 | 13 | 13 | 9 | **84** | 0 | **84** |

The original Kimi result of 17/100 is historical and does not describe the current code. The previous penalty came from cross-tenant sharing and missing resource-level authorization. Those defects are now fixed: sharing requires admin access, validates the grantee's membership in the same tenant, and the revised cross-tenant test expects rejection.

![Updated normalized AICGB comparison](benchmark_radar.svg)

## Executed evidence

| Check | Current Kimi3 result | Interpretation |
|---|---|---|
| Native pytest suite | **107 passed** in 14.33 s | Full supplied suite passes |
| End-to-end smoke script | **Passed** | Health, auth, workspace/note CRUD, reset lifecycle, logout, upload/delete, tenant isolation, and audit-chain verification worked |
| Independent hidden-style probes | **0 passed, 3 failed** | Found public-link, erasure, and viewer-privilege gaps |
| Bandit 1.9.4 (`app`) | 3 Low, 0 Medium, 0 High | Only `B101` assertions in auth code |
| Ruff | 94 findings; **0 excluding B008** | All findings are FastAPI `Depends(...)` declaration warnings |
| 10 MB AES-GCM round trip, 12 runs | median **38.16 ms**, worst **49.09 ms** | Passes the required <120 ms limit |
| 200 concurrent in-process note reads | p95 **409.32 ms** | Does not demonstrate the required <80 ms p95 |

The independent probes ran against a temporary copy so no Kimi source or supplied test was changed.

## Detailed scoring

| Dimension | Score | Deductions from maximum |
|---|---:|---|
| Functional correctness | **21/25** | −2 public share URLs are created but cannot be consumed; −1 member invite/role/remove APIs are absent; −1 folder-sharing API is absent and viewers can create workspaces |
| Performance | **11/15** | −3 measured 200-client p95 is 409.32 ms rather than <80 ms; −1 Kimi crypto is materially slower than Claude, although it passes the absolute limit |
| Security | **17/20** | −2 rate limiting is keyed only by raw client IP instead of hashed user and tenant identifiers; −1 viewer workspace creation violates least privilege |
| Privacy | **13/15** | −2 user erasure leaves user-authored notes in the database, so deletion is not complete |
| Compliance | **13/15** | −2 GDPR Article 17 user erasure is incomplete; organization erasure, retention, export, consent, and durable HMAC audit controls otherwise improved substantially |
| Code quality & robustness | **9/10** | −1 native tests miss three externally reproduced behaviors and relax the specified performance thresholds |

## Independent failures and exact sources

### 1. Public share links are not consumable

The API stores a hash and returns a URL:

```python
# Kimi3/vaultnote/app/api/v1/notes.py:185-196
token = generate_secure_token(32)
link = ShareLink(
    organization_id=wctx.organization_id,
    resource_type="note",
    resource_id=note.id,
    token_hash=hash_token(token),
    ...
)
await ShareLinkRepository(db).create(link)
return {"share_url": f"/shared/{token}", "token": token}
```

There is no `/shared/{token}` route in the API. The independent test issued a valid link and then requested it; the response was **404**, not 200.

### 2. User erasure leaves authored notes

The user-erasure implementation explicitly deletes files, sessions, consent, grants, and memberships, but never deletes or anonymizes `Note.created_by` records:

```python
# Kimi3/vaultnote/app/services/compliance_service.py:83-97
await self.session.execute(delete(FileAsset).where(FileAsset.uploaded_by == user_id))
await self.session.execute(delete(RefreshToken).where(RefreshToken.user_id == user_id))
await self.session.execute(delete(ConsentRecord).where(ConsentRecord.user_id == user_id))
await self.session.execute(delete(ShareGrant).where(ShareGrant.grantee_user_id == user_id))
await self.session.execute(delete(Membership).where(Membership.user_id == user_id))
...
await self.session.delete(user)
```

After `DELETE /api/v1/admin/users/me` returned 200, an independent database assertion found the user's note still present. This is why privacy and compliance each lose two points.

### 3. A viewer can create a workspace

Workspace creation requires tenant membership, but it does not impose an owner/admin role ceiling:

```python
# Kimi3/vaultnote/app/api/v1/workspaces.py:16-24
@router.post("", status_code=201)
async def create_workspace(
    body: WorkspaceCreate,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    ws = Workspace(organization_id=ctx.organization_id, name=body.name)
    await WorkspaceRepository(db).create(ws)
```

The independent viewer request returned **201**, while the least-privilege expectation was 403. This is an authorization defect, but it does not expose another tenant or justify the benchmark's automatic −30 critical penalty.

### 4. Rate limiting is IP-only

The middleware description says “per-user / per-IP,” but both keys contain only the raw IP:

```python
# Kimi3/vaultnote/app/middleware/security.py:52-63
client_ip = request.client.host if request.client else "unknown"
...
key = f"auth:{client_ip}"
# or
key = f"api:{client_ip}"
allowed = await rate_limiter.is_allowed(key, limit, window)
```

The product prompt specifically requires sliding-window limits per user and per tenant. The identifiers also are not hashed as required by AICGB's rate-limiter privacy control.

### 5. Performance assertions are looser than the product limits

The supplied concurrency test generates 200 requests but asserts p95 below 1000 ms, not the required 80 ms:

```python
# Kimi3/vaultnote/tests/test_notes_tenancy.py:391-393
p95 = latencies[int(len(latencies) * 0.95) - 1]
assert len(latencies) == 200
assert p95 < 1000
```

Likewise, the supplied crypto test comments that the specification is 120 ms but asserts 300 ms. The independent crypto measurement still passed the real 120 ms requirement.

## Improvements confirmed since the original benchmark

- Clean startup and 107 passing tests.
- Tenant-bound resource lookup and fine-grained read/write/admin checks.
- Cross-tenant grants rejected; viewers cannot mutate or share notes.
- Complete stored-hash, expiring, single-use password-reset lifecycle with session revocation.
- Production secrets fail closed; dedicated pseudonym and audit keys.
- MIME/magic validation, scanner interface, encrypted file deletion, and off-thread disk I/O.
- Thread-safe TTL LRU cache.
- Tenant-key rotation covers notes, folders, and files.
- Per-plan retention with an automatic background purge job.
- Durable HMAC-chained audit records and encrypted files included in ZIP export.

## Reproduction commands

```bash
cd Kimi3/vaultnote
python -m pytest -q
python scripts/smoke_check.py
bandit -q -r app
ruff check app tests scripts
ruff check app tests scripts --ignore B008
```

The three independent probes should be incorporated into the permanent suite after the corresponding behavior is fixed.
