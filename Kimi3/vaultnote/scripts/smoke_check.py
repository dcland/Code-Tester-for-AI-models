"""Ad-hoc smoke check of the reworked flows (not part of the test suite)."""
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ["VAULTNOTE_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["VAULTNOTE_JWT_SECRET_KEY"] = "smoke-secret-key-for-jwt-32bytes!!"
os.environ["VAULTNOTE_PASSWORD_PEPPER"] = "smoke-pepper-32-bytes-long-enough!"
os.environ["VAULTNOTE_MASTER_ENCRYPTION_KEY"] = "smoke-master-key-32-bytes-long!!"
os.environ["VAULTNOTE_PSEUDONYM_SALT"] = "smoke-pseudonym-salt-32-bytes!!!"
os.environ["VAULTNOTE_AUDIT_HMAC_KEY"] = "smoke-audit-hmac-key-32-bytes!!!"


async def main() -> None:
    from httpx import ASGITransport, AsyncClient
    from sqlalchemy import text

    from app.main import app
    from app.models.database import Base, async_session_factory, engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/health")
        print("health:", r.status_code)

        r = await c.post("/api/v1/auth/register", json={
            "email": "s@x.example", "password": "SecurePass1!x",
            "full_name": "S", "organization_name": "SmokeOrg"})
        print("register:", r.status_code)
        tok = r.json()["access_token"]

        async with async_session_factory() as s:
            org_id = (await s.execute(text("SELECT organization_id FROM memberships"))).scalar()
        h = {"Authorization": f"Bearer {tok}", "X-Organization-ID": org_id}

        r2 = await c.post("/api/v1/workspaces", json={"name": "w"}, headers=h)
        print("workspace:", r2.status_code)
        ws = r2.json()["id"]

        r3 = await c.post(f"/api/v1/workspaces/{ws}/notes", json={"title": "T", "content": "C"}, headers=h)
        print("create note:", r3.status_code)
        nid = r3.json()["id"]

        r4 = await c.get(f"/api/v1/workspaces/{ws}/notes/{nid}", headers=h)
        print("get note:", r4.status_code, r4.json().get("title"))

        # password reset flow via dev outbox
        r5 = await c.post("/api/v1/auth/password-reset", json={"email": "s@x.example"})
        print("reset request:", r5.status_code, "token_in_response:", "reset_token" in r5.json())
        from app.utils.mailer import outbox
        msg = outbox.latest_for("s@x.example")
        token = msg["body"].split("token is: ")[1].splitlines()[0]
        r6 = await c.post("/api/v1/auth/password-reset/confirm",
                          json={"token": token, "new_password": "NewSecurePass2@"})
        print("reset confirm:", r6.status_code)
        r7 = await c.post("/api/v1/auth/login", json={"email": "s@x.example", "password": "NewSecurePass2@"})
        print("login with new pw:", r7.status_code)
        r8 = await c.post("/api/v1/auth/password-reset/confirm",
                          json={"token": token, "new_password": "AnotherPass3#x"})
        print("reuse used token (expect 401):", r8.status_code)

        r9 = await c.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {tok}"})
        print("logout (expect 204):", r9.status_code)

        png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50
        r10 = await c.post(f"/api/v1/workspaces/{ws}/files", content=png,
                           headers={**h, "Content-Type": "image/png", "X-File-Name": "a.png"})
        print("upload:", r10.status_code, r10.json())
        fid = r10.json()["id"]

        r11 = await c.delete(f"/api/v1/workspaces/{ws}/files/{fid}", headers=h)
        print("file delete (expect 204):", r11.status_code)

        # cross-tenant workspace binding
        r12 = await c.post("/api/v1/auth/register", json={
            "email": "t@y.example", "password": "SecurePass1!x",
            "full_name": "T", "organization_name": "OtherOrg"})
        tok2 = r12.json()["access_token"]
        h2 = {"Authorization": f"Bearer {tok2}", "X-Organization-ID": org_id}  # foreign org
        r13 = await c.get(f"/api/v1/workspaces/{ws}/notes/{nid}", headers=h2)
        print("cross-tenant org header (expect 403):", r13.status_code)

        # audit chain verification
        async with async_session_factory() as s:
            from app.core.compliance import AuditLog
            print("audit chain valid:", await AuditLog.verify_chain(s))


asyncio.run(main())
