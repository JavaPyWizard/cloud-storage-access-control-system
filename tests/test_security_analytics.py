from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from app.db import SessionLocal
from app.main import app
from app.models import Audit
from app.services.security_analytics import get_security_analytics


def test_empty_security_analytics():
    with SessionLocal() as db:
        result = get_security_analytics(db)

    assert result["total_events"] == 0
    assert result["allowed_events"] == 0
    assert result["denied_events"] == 0
    assert result["denial_rate"] == 0
    assert result["suspicious_actor_count"] == 0


def test_security_analytics_counts():
    with SessionLocal() as db:
        db.add_all(
            [
                Audit(
                    actor_id=1,
                    object_id=1,
                    action="READ",
                    allowed=True,
                    reason="Allowed",
                    simulated=False,
                ),
                Audit(
                    actor_id=2,
                    object_id=1,
                    action="READ",
                    allowed=False,
                    reason="Denied",
                    simulated=False,
                ),
                Audit(
                    actor_id=2,
                    object_id=1,
                    action="WRITE",
                    allowed=False,
                    reason="Denied",
                    simulated=True,
                ),
            ]
        )
        db.commit()

        result = get_security_analytics(db)

    assert result["total_events"] == 3
    assert result["allowed_events"] == 1
    assert result["denied_events"] == 2
    assert result["denial_rate"] == 66.67
    assert result["real_events"] == 2
    assert result["simulated_events"] == 1
    assert result["actions"]["READ"] == 2
    assert result["actions"]["WRITE"] == 1


def test_suspicious_activity_detection():
    with SessionLocal() as db:
        db.add_all(
            [
                Audit(
                    actor_id=7,
                    object_id=1,
                    action="READ",
                    allowed=False,
                    reason="Unauthorized",
                    simulated=False,
                    created_at=datetime.now(UTC) - timedelta(minutes=i),
                )
                for i in range(3)
            ]
        )
        db.commit()

        result = get_security_analytics(db)

    assert result["suspicious_actor_count"] == 1
    assert result["suspicious_activity"][0]["actor"] == "7"
    assert result["suspicious_activity"][0]["severity"] == "MEDIUM"


def test_viewer_cannot_access_security_analytics():
    with TestClient(app) as client:

        def csrf():
            return {"x-csrf-token": client.get("/api/session").json()["csrf"]}

        assert (
            client.post(
                "/api/register",
                json={
                    "username": "adminanalytics",
                    "password": "password12345",
                },
                headers=csrf(),
            ).status_code
            == 200
        )

        assert client.get("/api/security/analytics").status_code == 200

        assert (
            client.post(
                "/api/logout",
                headers=csrf(),
            ).status_code
            == 200
        )

        assert (
            client.post(
                "/api/register",
                json={
                    "username": "vieweranalytics",
                    "password": "password12345",
                },
                headers=csrf(),
            ).status_code
            == 200
        )

        assert client.get("/api/security/analytics").status_code == 403
