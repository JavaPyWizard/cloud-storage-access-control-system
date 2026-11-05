from fastapi.testclient import TestClient

from app.main import app
from app.security_rate_limit import login_limiter


def test_login_rate_limit_http_429():
    username = "ratelimittest"
    password = "SecureTestPassword123!"

    with TestClient(app) as client:
        def csrf():
            token = client.get("/api/session").json()["csrf"]
            return {"x-csrf-token": token}

        response = client.post(
            "/api/register",
            json={
                "username": username,
                "password": password,
            },
            headers=csrf(),
        )

        assert response.status_code == 200

        response = client.post(
            "/api/logout",
            headers=csrf(),
        )

        assert response.status_code == 200

        for _ in range(5):
            response = client.post(
                "/api/login",
                json={
                    "username": username,
                    "password": "IncorrectPassword123!",
                },
                headers=csrf(),
            )

            assert response.status_code == 401

        response = client.post(
            "/api/login",
            json={
                "username": username,
                "password": password,
            },
            headers=csrf(),
        )

        assert response.status_code == 429
        assert response.headers["retry-after"] == "300"

    login_limiter.reset(f"testclient:{username}")