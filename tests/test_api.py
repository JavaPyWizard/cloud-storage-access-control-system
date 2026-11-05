from fastapi.testclient import TestClient

from app.main import app


def test_health_and_auth():
    with TestClient(app) as client:

        assert client.get("/health").json()["status"] == "healthy"

        assert client.get("/api/objects").status_code == 401

        token = client.get("/api/session").json()["csrf"]

        response = client.post(
            "/api/register",
            json={
                "username": "testuser",
                "password": "longpassword123"
            },
            headers={
                "x-csrf-token": token
            }
        )

        assert response.status_code == 200

        assert client.get("/api/objects").status_code == 200