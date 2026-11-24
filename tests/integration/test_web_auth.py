import pytest

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.responses import HTMLResponse
from starlette.websockets import WebSocketDisconnect

from src.api import web_auth
from src.api.routes import websocket
from src.api.web_auth import WebAuthMiddleware
from src.services.web_auth_service import WebSessionSettings


def _build_auth_client(monkeypatch) -> TestClient:
    web_auth.reset_login_rate_limiter()
    settings = WebSessionSettings(
        username="admin",
        password="secret",
        signing_key="test-signing-key",
        ttl_seconds=3600,
    )
    monkeypatch.setattr(web_auth, "resolve_session_settings", lambda: settings)

    app = FastAPI()
    app.add_middleware(WebAuthMiddleware)
    app.include_router(web_auth.router)
    app.include_router(websocket.router)

    @app.get("/api/protected")
    async def protected(request: Request):
        return {"username": request.state.web_username}

    @app.get("/docs")
    async def docs():
        return HTMLResponse("<html><body>docs</body></html>")

    @app.api_route(
        "/api/protected-write",
        methods=["POST", "PUT", "PATCH", "DELETE"],
    )
    async def protected_write(request: Request):
        return {"username": request.state.web_username, "method": request.method}

    return TestClient(app)


def _login(
    client: TestClient,
    headers: dict[str, str] | None = None,
    *,
    username: str = "admin",
    password: str = "secret",
):
    return client.post(
        "/auth/status",
        json={"username": username, "password": password},
        headers=headers,
    )


def test_api_requires_session_cookie(monkeypatch):
    client = _build_auth_client(monkeypatch)

    response = client.get("/api/protected")

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Session"


def test_login_session_and_logout_flow(monkeypatch):
    client = _build_auth_client(monkeypatch)

    bad_login = client.post(
        "/auth/status",
        json={"username": "admin", "password": "wrong"},
    )
    assert bad_login.status_code == 401

    login = client.post(
        "/auth/status",
        json={"username": "admin", "password": "secret"},
    )
    assert login.status_code == 200
    assert login.json() == {"authenticated": True, "username": "admin"}
    assert "HttpOnly" in login.headers["set-cookie"]
    assert "SameSite=lax" in login.headers["set-cookie"]

    session = client.get("/auth/session")
    assert session.status_code == 200
    assert session.json() == {"authenticated": True, "username": "admin"}

    protected = client.get("/api/protected")
    assert protected.status_code == 200
    assert protected.json() == {"username": "admin"}
    assert protected.headers["cache-control"] == "no-store"

    logout = client.post("/auth/logout")
    assert logout.status_code == 200
    assert client.get("/api/protected").status_code == 401


def test_websocket_requires_authenticated_session(monkeypatch):
    client = _build_auth_client(monkeypatch)

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws"):
            pass

    client.post(
        "/auth/status",
        json={"username": "admin", "password": "secret"},
    )
    with client.websocket_connect("/ws") as connection:
        connection.close()


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_same_origin_write_requests_are_allowed(monkeypatch, method):
    client = _build_auth_client(monkeypatch)
    assert _login(client).status_code == 200

    response = client.request(
        method,
        "/api/protected-write",
        headers={"Origin": "http://testserver"},
    )

    assert response.status_code == 200
    assert response.json()["method"] == method


def test_write_request_without_origin_or_referer_is_allowed(monkeypatch):
    client = _build_auth_client(monkeypatch)

    response = _login(client)

    assert response.status_code == 200


@pytest.mark.parametrize(
    "origin",
    [
        "https://evil.example",
        "https://testserver",
        "http://testserver:8000",
        "http://sub.testserver",
        "null",
        "file://testserver",
        "not-a-url",
        "http://user:pass@testserver",
    ],
)
def test_cross_site_login_origin_is_rejected(monkeypatch, origin):
    client = _build_auth_client(monkeypatch)

    response = _login(client, headers={"Origin": origin})

    assert response.status_code == 403
    assert response.json()["detail"] == "跨站请求被拒绝"
    assert response.headers["cache-control"] == "no-store"
    assert "set-cookie" not in response.headers


def test_cross_site_protected_write_is_rejected(monkeypatch):
    client = _build_auth_client(monkeypatch)
    assert _login(client).status_code == 200

    response = client.post(
        "/api/protected-write",
        headers={"Origin": "https://evil.example"},
    )

    assert response.status_code == 403
    assert response.headers["cache-control"] == "no-store"


def test_cross_site_logout_is_rejected(monkeypatch):
    client = _build_auth_client(monkeypatch)
    assert _login(client).status_code == 200

    response = client.post(
        "/auth/logout",
        headers={"Origin": "https://evil.example"},
    )

    assert response.status_code == 403
    assert client.get("/api/protected").status_code == 200


def test_referer_is_used_when_origin_is_absent(monkeypatch):
    client = _build_auth_client(monkeypatch)

    allowed = _login(
        client,
        headers={"Referer": "http://testserver/login?redirect=/tasks"},
    )
    rejected = _login(
        client,
        headers={"Referer": "https://evil.example/login"},
    )

    assert allowed.status_code == 200
    assert rejected.status_code == 403


def test_forwarded_host_and_proto_are_supported(monkeypatch):
    client = _build_auth_client(monkeypatch)
    proxy_headers = {
        "X-Forwarded-Host": "monitor.example.com",
        "X-Forwarded-Proto": "https",
    }

    allowed = _login(
        client,
        headers={
            **proxy_headers,
            "Origin": "https://monitor.example.com",
        },
    )
    rejected = _login(
        client,
        headers={
            **proxy_headers,
            "Origin": "https://evil.example",
        },
    )

    assert allowed.status_code == 200
    assert rejected.status_code == 403


def test_missing_session_takes_priority_over_origin_rejection(monkeypatch):
    client = _build_auth_client(monkeypatch)

    response = client.post(
        "/api/protected-write",
        headers={"Origin": "https://evil.example"},
    )

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Session"


def test_websocket_rejects_cross_site_origin(monkeypatch):
    client = _build_auth_client(monkeypatch)
    assert _login(client).status_code == 200

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(
            "/ws",
            headers={"Origin": "https://evil.example"},
        ):
            pass

    with client.websocket_connect(
        "/ws",
        headers={"Origin": "http://testserver"},
    ) as connection:
        connection.close()


def test_login_failures_are_rate_limited(monkeypatch):
    client = _build_auth_client(monkeypatch)

    for _ in range(web_auth.LOGIN_MAX_FAILURES):
        response = _login(client, password="wrong")
        assert response.status_code == 401

    limited = _login(client, password="wrong")

    assert limited.status_code == 429
    assert limited.json()["detail"] == "登录尝试过于频繁，请稍后再试"
    assert 1 <= int(limited.headers["retry-after"]) <= web_auth.LOGIN_FAILURE_WINDOW_SECONDS
    assert limited.headers["cache-control"] == "no-store"


def test_successful_login_resets_failure_counter(monkeypatch):
    client = _build_auth_client(monkeypatch)

    for _ in range(web_auth.LOGIN_MAX_FAILURES - 1):
        assert _login(client, password="wrong").status_code == 401
    assert _login(client).status_code == 200

    for _ in range(web_auth.LOGIN_MAX_FAILURES):
        assert _login(client, password="wrong").status_code == 401
    assert _login(client, password="wrong").status_code == 429


def test_login_rate_limit_is_isolated_by_username(monkeypatch):
    client = _build_auth_client(monkeypatch)

    for _ in range(web_auth.LOGIN_MAX_FAILURES):
        assert _login(client, password="wrong").status_code == 401
    assert _login(client, password="wrong").status_code == 429

    other_user = _login(client, username="other", password="wrong")

    assert other_user.status_code == 401
    assert other_user.json()["detail"] == "认证失败"


def test_security_headers_cover_success_and_error_responses(monkeypatch):
    client = _build_auth_client(monkeypatch)

    unauthorized = client.get("/api/protected")
    blocked_login = _login(client, headers={"Origin": "https://evil.example"})
    login = _login(client)

    for response in (unauthorized, blocked_login, login):
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "same-origin"
        assert "camera=()" in response.headers["permissions-policy"]
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        assert "strict-transport-security" not in response.headers


def test_hsts_is_added_for_https_proxy_requests(monkeypatch):
    client = _build_auth_client(monkeypatch)

    response = _login(client, headers={"X-Forwarded-Proto": "https"})

    assert response.status_code == 200
    assert response.headers["strict-transport-security"] == "max-age=31536000"
    assert "Secure" in response.headers["set-cookie"]


def test_docs_keeps_security_headers_without_restrictive_csp(monkeypatch):
    client = _build_auth_client(monkeypatch)
    assert _login(client).status_code == 200

    response = client.get("/docs")

    assert response.status_code == 200
    assert "content-security-policy" not in response.headers
    assert response.headers["x-frame-options"] == "DENY"
