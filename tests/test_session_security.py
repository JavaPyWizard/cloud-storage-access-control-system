
from fastapi.testclient import TestClient

from app.main import app


def test_security_headers():
    with TestClient(app) as client:
        response = client.get("/")

        assert response.status_code == 200
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert "default-src 'self'" in response.headers[
            "content-security-policy"
        ]
        assert response.headers["referrer-policy"] == (
            "strict-origin-when-cross-origin"
        )


def test_api_cache_control():
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200

        response = client.get("/api/session")
        assert response.headers["cache-control"] == "no-store"


def test_session_cookie_security():
    with TestClient(app) as client:
        response = client.get("/api/session")

        cookie = response.headers.get("set-cookie", "").lower()

        assert "aegisvault_session=" in cookie
        assert "httponly" in cookie
        assert "samesite=lax" in cookie
        assert "max-age=1800" in cookie


def test_invalid_csrf_rejected():
    with TestClient(app) as client:
        client.get("/api/session")

        response = client.post(
            "/api/register",
            json={
                "username": "csrf_test",
                "password": "SecurePassword123!",
            },
            headers={"x-csrf-token": "invalid-token"},
        )

        assert response.status_code == 403


def test_logout_invalidates_session():
    with TestClient(app) as client:
        csrf = client.get("/api/session").json()["csrf"]

        response = client.post(
            "/api/register",
            json={
                "username": "sessiontest",
                "password": "SecurePassword123!",
            },
            headers={"x-csrf-token": csrf},
        )

        assert response.status_code == 200
        assert client.get("/api/objects").status_code == 200

        csrf = client.get("/api/session").json()["csrf"]

        response = client.post(
            "/api/logout",
            headers={"x-csrf-token": csrf},
        )

        assert response.status_code == 200
        assert client.get("/api/objects").status_code == 401
