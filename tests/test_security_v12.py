import os

os.environ["DATABASE_URL"] = "sqlite://"
from fastapi.testclient import TestClient

from app.main import app


def test_permissions_audit_filters_and_api_authorization():
    with TestClient(app) as c:

        def csrf():
            return {"x-csrf-token": c.get("/api/session").json()["csrf"]}

        assert (
            c.post(
                "/api/register",
                json={"username": "owner12", "password": "password12345"},
                headers=csrf(),
            ).status_code
            == 200
        )
        upload = lambda name, policy, role="": c.post(
            "/api/objects",
            data={"policy": policy, "allowed_role": role},
            files={"file": (name, b"synthetic sample", "text/plain")},
            headers=csrf(),
        )
        private = upload("private.txt", "PRIVATE").json()["id"]
        public = upload("public.txt", "PUBLIC_READ").json()["id"]
        restricted = upload("role.txt", "ROLE_RESTRICTED", "VIEWER").json()["id"]
        assert c.post("/api/logout", headers=csrf()).status_code == 200
        assert (
            c.post(
                "/api/register",
                json={"username": "viewer12", "password": "password12345"},
                headers=csrf(),
            ).status_code
            == 200
        )
        objs = {x["id"]: x for x in c.get("/api/objects").json()}
        assert objs[private]["permissions"] == {
            "READ": False,
            "WRITE": False,
            "DELETE": False,
        }
        assert objs[public]["permissions"]["READ"] is True
        assert objs[restricted]["permissions"]["READ"] is True
        assert c.get(f"/api/objects/{private}/download").status_code == 403
        assert c.get(f"/api/objects/{public}/download").status_code == 200
        assert c.get(f"/api/objects/{restricted}/download").status_code == 200
        assert c.delete(f"/api/objects/{private}", headers=csrf()).status_code == 403
        assert (
            c.patch(
                f"/api/objects/{private}/policy",
                json={"policy": "PUBLIC_READ"},
                headers=csrf(),
            ).status_code
            == 403
        )
        assert c.get("/api/audits").status_code == 403
        assert c.get("/api/verify").status_code == 403
        assert c.post("/api/logout", headers=csrf()).status_code == 200
        assert (
            c.post(
                "/api/login",
                json={"username": "owner12", "password": "password12345"},
                headers=csrf(),
            ).status_code
            == 200
        )
        denied = c.get("/api/audits?decision=DENY").json()
        assert len(denied) >= 3 and all(not x["allowed"] for x in denied)
        assert all(
            x["action"] == "READ" for x in c.get("/api/audits?action=READ").json()
        )
        assert c.get("/api/audits?decision=INVALID").status_code == 400
        verification = c.get("/api/verify").json()
        assert verification["failed"] == 0 and verification["total"] == 27
