"""
Web 管理界面的认证路由与 HTTP 鉴权中间件。
"""
from __future__ import annotations

import math
import threading
import time
from collections.abc import Mapping
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.websockets import WebSocket

from src.services.web_auth_service import (
    SESSION_COOKIE_NAME,
    WebSessionSettings,
    authenticate_session_token,
    create_session_token,
    resolve_session_settings,
    verify_credentials,
)


router = APIRouter(tags=["auth"])

PROTECTED_EXACT_PATHS = {"/api", "/docs", "/redoc", "/openapi.json"}
PROTECTED_PREFIXES = ("/api/",)
UNSAFE_HTTP_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_HTTP_SCHEMES = frozenset({"http", "https"})
_SCHEME_ALIASES = {"ws": "http", "wss": "https"}
_DEFAULT_PORTS = {"http": 80, "https": 443}
_MAX_SOURCE_URL_LENGTH = 4096

LOGIN_MAX_FAILURES = 5
LOGIN_FAILURE_WINDOW_SECONDS = 300
_MAX_LOGIN_TRACKING_ENTRIES = 10_000
_login_failure_lock = threading.Lock()
_login_failures: dict[tuple[str, str], list[float]] = {}

_APP_CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'self'",
        "base-uri 'self'",
        "object-src 'none'",
        "frame-ancestors 'none'",
        "form-action 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: blob: https:",
        "font-src 'self' data:",
        "media-src 'self' data: blob:",
        "connect-src 'self'",
    )
)


class LoginRequest(BaseModel):
    username: str
    password: str


def _login_attempt_key(request: Request, username: str) -> tuple[str, str]:
    client_host = request.client.host if request.client else "unknown"
    return client_host, str(username or "")[:256]


def _prune_login_failures_locked(now: float) -> None:
    cutoff = now - LOGIN_FAILURE_WINDOW_SECONDS
    stale_keys = [
        key
        for key, attempts in _login_failures.items()
        if not attempts or attempts[-1] <= cutoff
    ]
    for key in stale_keys:
        _login_failures.pop(key, None)


def _record_login_failure(request: Request, username: str) -> None:
    key = _login_attempt_key(request, username)
    now = time.monotonic()
    cutoff = now - LOGIN_FAILURE_WINDOW_SECONDS
    with _login_failure_lock:
        attempts = [attempt for attempt in _login_failures.get(key, []) if attempt > cutoff]
        attempts.append(now)
        _login_failures[key] = attempts

        if len(_login_failures) > _MAX_LOGIN_TRACKING_ENTRIES:
            _prune_login_failures_locked(now)
        if len(_login_failures) > _MAX_LOGIN_TRACKING_ENTRIES:
            oldest_key = min(_login_failures, key=lambda item: _login_failures[item][-1])
            _login_failures.pop(oldest_key, None)


def _login_retry_after_seconds(request: Request, username: str) -> int:
    key = _login_attempt_key(request, username)
    now = time.monotonic()
    cutoff = now - LOGIN_FAILURE_WINDOW_SECONDS
    with _login_failure_lock:
        attempts = [attempt for attempt in _login_failures.get(key, []) if attempt > cutoff]
        if attempts:
            _login_failures[key] = attempts
        else:
            _login_failures.pop(key, None)
        if len(attempts) < LOGIN_MAX_FAILURES:
            return 0
        return max(1, math.ceil(attempts[0] + LOGIN_FAILURE_WINDOW_SECONDS - now))


def _clear_login_failures(request: Request, username: str) -> None:
    with _login_failure_lock:
        _login_failures.pop(_login_attempt_key(request, username), None)


def reset_login_rate_limiter() -> None:
    """清空内存中的登录失败计数，供测试和运维恢复使用。"""
    with _login_failure_lock:
        _login_failures.clear()


def _apply_security_headers(request: Request, response: Response) -> None:
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")

    path = request.url.path
    if not (path == "/redoc" or path == "/docs" or path.startswith("/docs/")):
        response.headers.setdefault("Content-Security-Policy", _APP_CONTENT_SECURITY_POLICY)

    if _is_secure_request(request):
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")


def _is_secure_request(request: Request) -> bool:
    forwarded_proto = request.headers.get("x-forwarded-proto", "")
    first_forwarded_proto = forwarded_proto.split(",", 1)[0].strip().lower()
    return request.url.scheme == "https" or first_forwarded_proto == "https"


def _header_values(headers: Mapping[str, str], name: str) -> list[str]:
    get_list = getattr(headers, "getlist", None)
    if callable(get_list):
        return list(get_list(name))
    value = headers.get(name)
    return [] if value is None else [value]


def _first_forwarded_value(value: str | None) -> str | None:
    if value is None:
        return None
    first_value = value.split(",", 1)[0].strip()
    return first_value or None


def _normalize_scheme(scheme: str) -> str:
    normalized = (scheme or "").strip().lower()
    return _SCHEME_ALIASES.get(normalized, normalized)


def _origin_context(
    headers: Mapping[str, str],
    fallback_scheme: str,
    fallback_authority: str,
) -> tuple[str, str]:
    forwarded_proto = _first_forwarded_value(headers.get("x-forwarded-proto"))
    scheme = _normalize_scheme(forwarded_proto or fallback_scheme)
    forwarded_host = _first_forwarded_value(headers.get("x-forwarded-host"))
    authority = forwarded_host or headers.get("host") or fallback_authority
    return scheme, authority


def _parse_http_source(
    value: str,
    *,
    allow_path: bool,
    allow_multiple: bool = True,
) -> tuple[str, str, int] | None:
    source = (value or "").strip()
    if not source or len(source) > _MAX_SOURCE_URL_LENGTH:
        return None
    if source.casefold() == "null":
        return None
    if not allow_multiple and "," in source:
        return None

    try:
        parsed = urlsplit(source)
        scheme = _normalize_scheme(parsed.scheme)
        hostname = parsed.hostname
        port = parsed.port
    except (UnicodeError, ValueError):
        return None

    if scheme not in _HTTP_SCHEMES or not hostname:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    if not allow_path and (parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        return None

    return scheme, hostname.casefold(), port if port is not None else _DEFAULT_PORTS[scheme]


def _parse_request_authority(
    authority: str,
    scheme: str,
) -> tuple[str, str, int] | None:
    if not authority or "," in authority:
        return None
    return _parse_http_source(
        f"{scheme}://{authority}",
        allow_path=False,
        allow_multiple=False,
    )


def _source_matches_request(
    source: str,
    scheme: str,
    authority: str,
    *,
    allow_path: bool,
    allow_multiple: bool,
) -> bool:
    parsed_source = _parse_http_source(
        source,
        allow_path=allow_path,
        allow_multiple=allow_multiple,
    )
    parsed_request = _parse_request_authority(authority, scheme)
    return parsed_source is not None and parsed_source == parsed_request


def _request_source_headers_are_allowed(
    headers: Mapping[str, str],
    fallback_scheme: str,
    fallback_authority: str,
) -> bool:
    scheme, authority = _origin_context(headers, fallback_scheme, fallback_authority)
    origin_values = _header_values(headers, "origin")
    if origin_values:
        if len(origin_values) != 1:
            return False
        return _source_matches_request(
            origin_values[0],
            scheme,
            authority,
            allow_path=False,
            allow_multiple=False,
        )

    referer_values = _header_values(headers, "referer")
    if referer_values:
        if len(referer_values) != 1:
            return False
        return _source_matches_request(
            referer_values[0],
            scheme,
            authority,
            allow_path=True,
            allow_multiple=True,
        )

    return True


def http_request_origin_is_allowed(request: Request) -> bool:
    """校验写请求来源；非浏览器客户端可不带 Origin/Referer。"""
    if request.method.upper() not in UNSAFE_HTTP_METHODS:
        return True
    return _request_source_headers_are_allowed(
        request.headers,
        request.url.scheme,
        request.url.netloc,
    )


def _require_authenticated_user(request: Request) -> str:
    settings = resolve_session_settings()
    username = authenticate_session_token(
        request.cookies.get(SESSION_COOKIE_NAME),
        settings,
    )
    if username is None:
        raise HTTPException(status_code=401, detail="未认证或会话已过期")
    return username


def _set_session_cookie(
    response: Response,
    request: Request,
    settings: WebSessionSettings,
) -> None:
    token = create_session_token(
        settings.username,
        settings.signing_key,
        settings.ttl_seconds,
    )
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=settings.ttl_seconds,
        httponly=True,
        secure=_is_secure_request(request),
        samesite="lax",
        path="/",
    )


@router.post("/auth/status")
async def auth_status(payload: LoginRequest, request: Request, response: Response):
    """校验凭据并签发 HttpOnly 会话 Cookie。"""
    retry_after = _login_retry_after_seconds(request, payload.username)
    if retry_after > 0:
        raise HTTPException(
            status_code=429,
            detail="登录尝试过于频繁，请稍后再试",
            headers={
                "Retry-After": str(retry_after),
                "Cache-Control": "no-store",
            },
        )

    settings = resolve_session_settings()
    if not verify_credentials(
        payload.username,
        payload.password,
        settings.username,
        settings.password,
    ):
        _record_login_failure(request, payload.username)
        raise HTTPException(
            status_code=401,
            detail="认证失败",
            headers={"Cache-Control": "no-store"},
        )

    _clear_login_failures(request, payload.username)
    _set_session_cookie(response, request, settings)
    response.headers["Cache-Control"] = "no-store"
    return {"authenticated": True, "username": settings.username}


@router.get("/auth/session")
async def get_auth_session(request: Request, response: Response):
    """返回当前浏览器会话状态，供前端路由守卫恢复登录态。"""
    username = _require_authenticated_user(request)
    response.headers["Cache-Control"] = "no-store"
    return {"authenticated": True, "username": username}


@router.post("/auth/logout")
async def logout(request: Request, response: Response):
    """清除当前浏览器会话 Cookie。"""
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        secure=_is_secure_request(request),
        httponly=True,
        samesite="lax",
    )
    response.headers["Cache-Control"] = "no-store"
    return {"authenticated": False}


def is_protected_api_path(path: str) -> bool:
    return path in PROTECTED_EXACT_PATHS or path.startswith(PROTECTED_PREFIXES)


class WebAuthMiddleware(BaseHTTPMiddleware):
    """统一保护所有 /api 路由和 API 文档，避免新增路由漏加鉴权。"""

    async def dispatch(self, request: Request, call_next):
        is_protected = is_protected_api_path(request.url.path)
        username = None
        if is_protected:
            username = authenticate_session_token(
                request.cookies.get(SESSION_COOKIE_NAME),
                resolve_session_settings(),
            )
            if username is None:
                unauthorized = JSONResponse(
                    status_code=401,
                    content={"detail": "未认证或会话已过期"},
                    headers={
                        "WWW-Authenticate": "Session",
                        "Cache-Control": "no-store",
                    },
                )
                _apply_security_headers(request, unauthorized)
                return unauthorized

        if not http_request_origin_is_allowed(request):
            forbidden = JSONResponse(
                status_code=403,
                content={"detail": "跨站请求被拒绝"},
                headers={
                    "Cache-Control": "no-store",
                    "Pragma": "no-cache",
                },
            )
            _apply_security_headers(request, forbidden)
            return forbidden

        if is_protected:
            request.state.web_username = username
        response = await call_next(request)
        if is_protected:
            response.headers.setdefault("Cache-Control", "no-store")
            response.headers.setdefault("Pragma", "no-cache")
        _apply_security_headers(request, response)
        return response


def websocket_origin_is_allowed(websocket: WebSocket) -> bool:
    """拒绝跨站 WebSocket 连接；非浏览器客户端可不带 Origin。"""
    return _request_source_headers_are_allowed(
        websocket.headers,
        websocket.url.scheme,
        websocket.url.netloc,
    )


def websocket_session_is_authenticated(websocket: WebSocket) -> bool:
    if not websocket_origin_is_allowed(websocket):
        return False
    username = authenticate_session_token(
        websocket.cookies.get(SESSION_COOKIE_NAME),
        resolve_session_settings(),
    )
    return username is not None
