"""Authentication over the real HTTP stack: registration, login, throttling,
token verification, refresh rotation with reuse detection, logout and
password change."""

import uuid
from datetime import UTC, datetime, timedelta

import jwt
from fastapi.testclient import TestClient

from app.core.config import get_settings

ORIGIN = {"Origin": "http://localhost:3000"}
PASSWORD = "correct horse battery"


def _register(client: TestClient, email: str = "alice@example.test") -> dict:
    response = client.post(
        "/api/v1/auth/register", json={"email": email, "password": PASSWORD}
    )
    assert response.status_code == 201, response.text
    return response.json()["data"]


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


class TestRegistration:
    def test_register_returns_access_token_and_sets_refresh_cookie(
        self, anonymous_client
    ):
        response = anonymous_client.post(
            "/api/v1/auth/register",
            json={"email": " Alice@Example.TEST ", "password": PASSWORD},
        )

        assert response.status_code == 201
        data = response.json()["data"]
        assert data["token_type"] == "bearer"
        assert data["expires_in"] == 15 * 60
        assert data["user"]["email"] == "alice@example.test"
        cookie = response.headers["set-cookie"].lower()
        assert "avap_refresh=" in cookie
        assert "httponly" in cookie
        assert "samesite=strict" in cookie
        assert "secure" in cookie
        assert "path=/api/v1/auth" in cookie
        assert "refresh_token" not in data

    def test_duplicate_email_is_rejected(self, anonymous_client):
        _register(anonymous_client)
        response = anonymous_client.post(
            "/api/v1/auth/register",
            json={"email": "ALICE@example.test", "password": PASSWORD},
        )
        assert response.status_code == 409

    def test_short_password_is_rejected_without_echoing_it(self, anonymous_client):
        response = anonymous_client.post(
            "/api/v1/auth/register",
            json={"email": "bob@example.test", "password": "short-pw"},
        )
        assert response.status_code == 422
        assert "short-pw" not in response.text

    def test_password_equal_to_email_is_rejected(self, anonymous_client):
        email = "longaddress@example.test"
        response = anonymous_client.post(
            "/api/v1/auth/register", json={"email": email, "password": email}
        )
        assert response.status_code == 422


class TestLogin:
    def test_login_succeeds_with_correct_password(self, anonymous_client):
        _register(anonymous_client)
        response = anonymous_client.post(
            "/api/v1/auth/login",
            json={"email": "alice@example.test", "password": PASSWORD},
        )
        assert response.status_code == 200
        assert response.json()["data"]["access_token"]

    def test_wrong_password_and_unknown_email_get_the_same_answer(
        self, anonymous_client
    ):
        _register(anonymous_client)
        wrong = anonymous_client.post(
            "/api/v1/auth/login",
            json={"email": "alice@example.test", "password": "wrong password!"},
        )
        unknown = anonymous_client.post(
            "/api/v1/auth/login",
            json={"email": "nobody@example.test", "password": PASSWORD},
        )
        assert wrong.status_code == unknown.status_code == 401
        assert wrong.json()["error"] == unknown.json()["error"]

    def test_repeated_failures_are_throttled(self, anonymous_client):
        _register(anonymous_client)
        bad = {"email": "alice@example.test", "password": "wrong password!"}
        for _ in range(get_settings().login_max_failures):
            assert (
                anonymous_client.post("/api/v1/auth/login", json=bad).status_code == 401
            )

        good = {"email": "alice@example.test", "password": PASSWORD}
        response = anonymous_client.post("/api/v1/auth/login", json=good)
        assert response.status_code == 429


class TestAccessTokens:
    def test_protected_route_requires_a_token(self, anonymous_client):
        response = anonymous_client.get("/api/v1/targets")
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "UNAUTHORIZED"

    def test_me_returns_the_token_owner(self, anonymous_client):
        token = _register(anonymous_client)["access_token"]
        response = anonymous_client.get("/api/v1/auth/me", headers=_bearer(token))
        assert response.status_code == 200
        assert response.json()["data"]["email"] == "alice@example.test"

    def test_tampered_token_is_rejected(self, anonymous_client):
        token = _register(anonymous_client)["access_token"]
        tampered = token[:-2] + ("AA" if not token.endswith("AA") else "BB")
        response = anonymous_client.get("/api/v1/targets", headers=_bearer(tampered))
        assert response.status_code == 401

    def test_expired_token_is_rejected(self, anonymous_client):
        user_id = _register(anonymous_client)["user"]["id"]
        past = datetime.now(UTC) - timedelta(hours=1)
        expired = jwt.encode(
            {"sub": user_id, "type": "access", "iat": past, "exp": past},
            get_settings().jwt_secret_key.get_secret_value(),
            algorithm="HS256",
        )
        response = anonymous_client.get("/api/v1/targets", headers=_bearer(expired))
        assert response.status_code == 401

    def test_unsigned_alg_none_token_is_rejected(self, anonymous_client):
        user_id = _register(anonymous_client)["user"]["id"]
        now = datetime.now(UTC)
        forged = jwt.encode(
            {
                "sub": user_id,
                "type": "access",
                "iat": now,
                "exp": now + timedelta(hours=1),
            },
            key="",
            algorithm="none",
        )
        response = anonymous_client.get("/api/v1/targets", headers=_bearer(forged))
        assert response.status_code == 401

    def test_token_for_unknown_user_is_rejected(self, anonymous_client):
        now = datetime.now(UTC)
        token = jwt.encode(
            {
                "sub": str(uuid.uuid4()),
                "type": "access",
                "iat": now,
                "exp": now + timedelta(minutes=5),
            },
            get_settings().jwt_secret_key.get_secret_value(),
            algorithm="HS256",
        )
        response = anonymous_client.get("/api/v1/targets", headers=_bearer(token))
        assert response.status_code == 401


class TestRefreshAndLogout:
    def test_refresh_rotates_the_cookie_and_issues_a_new_access_token(
        self, anonymous_client
    ):
        _register(anonymous_client)
        first_cookie = anonymous_client.cookies.get("avap_refresh")

        response = anonymous_client.post("/api/v1/auth/refresh", headers=ORIGIN)

        assert response.status_code == 200
        assert response.json()["data"]["access_token"]
        assert anonymous_client.cookies.get("avap_refresh") != first_cookie

    def test_refresh_requires_an_allowed_origin(self, anonymous_client):
        _register(anonymous_client)
        no_origin = anonymous_client.post("/api/v1/auth/refresh")
        evil = anonymous_client.post(
            "/api/v1/auth/refresh", headers={"Origin": "https://evil.example"}
        )
        assert no_origin.status_code == evil.status_code == 401

    def test_reusing_a_spent_refresh_token_revokes_the_whole_family(
        self, anonymous_client
    ):
        _register(anonymous_client)
        stolen = anonymous_client.cookies.get("avap_refresh")
        assert (
            anonymous_client.post("/api/v1/auth/refresh", headers=ORIGIN).status_code
            == 200
        )

        anonymous_client.cookies.set("avap_refresh", stolen, path="/api/v1/auth")
        replay = anonymous_client.post("/api/v1/auth/refresh", headers=ORIGIN)
        assert replay.status_code == 401

        # The legitimate, rotated token was revoked along with the family.
        assert (
            anonymous_client.post("/api/v1/auth/refresh", headers=ORIGIN).status_code
            == 401
        )

    def test_logout_ends_the_session(self, anonymous_client):
        _register(anonymous_client)
        cookie = anonymous_client.cookies.get("avap_refresh")
        response = anonymous_client.post("/api/v1/auth/logout", headers=ORIGIN)
        assert response.status_code == 204

        anonymous_client.cookies.set("avap_refresh", cookie, path="/api/v1/auth")
        assert (
            anonymous_client.post("/api/v1/auth/refresh", headers=ORIGIN).status_code
            == 401
        )


class TestPasswordChange:
    def test_wrong_current_password_is_rejected(self, anonymous_client):
        token = _register(anonymous_client)["access_token"]
        response = anonymous_client.post(
            "/api/v1/users/me/password",
            json={"current_password": "not my password", "new_password": "x" * 14},
            headers=_bearer(token),
        )
        assert response.status_code == 422

    def test_change_signs_out_other_sessions_and_new_password_works(
        self, anonymous_client
    ):
        token = _register(anonymous_client)["access_token"]
        new_password = "a brand new passphrase"
        response = anonymous_client.post(
            "/api/v1/users/me/password",
            json={"current_password": PASSWORD, "new_password": new_password},
            headers=_bearer(token),
        )
        assert response.status_code == 204

        assert (
            anonymous_client.post("/api/v1/auth/refresh", headers=ORIGIN).status_code
            == 401
        )
        login = anonymous_client.post(
            "/api/v1/auth/login",
            json={"email": "alice@example.test", "password": new_password},
        )
        assert login.status_code == 200
