"""
Web 管理界面的会话签名与凭据校验。

会话令牌使用 HMAC-SHA256 签名，默认有效期 7 天。未显式配置
WEB_SESSION_SECRET 时，会在 data/ 下生成一个仅当前用户可读的随机密钥。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from src.infrastructure.config.settings import get_settings


SESSION_COOKIE_NAME = "goofish_monitor_session"
DEFAULT_SESSION_TTL_SECONDS = 7 * 24 * 60 * 60
MIN_SESSION_TTL_SECONDS = 5 * 60
MAX_SESSION_TTL_SECONDS = 30 * 24 * 60 * 60
DEFAULT_SESSION_SECRET_FILE = "data/.web_session_secret"
MAX_SESSION_TOKEN_LENGTH = 4096

_secret_lock = threading.Lock()
_secret_cache: dict[str, str] = {}


@dataclass(frozen=True, repr=False)
class WebSessionSettings:
    username: str
    password: str
    signing_key: str
    ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(f"{value}{padding}")


def verify_credentials(
    username: str,
    password: str,
    expected_username: str,
    expected_password: str,
) -> bool:
    """使用常量时间比较，避免通过响应时间推断账号或密码。"""
    username_ok = hmac.compare_digest(
        str(username or "").encode("utf-8"),
        str(expected_username or "").encode("utf-8"),
    )
    password_ok = hmac.compare_digest(
        str(password or "").encode("utf-8"),
        str(expected_password or "").encode("utf-8"),
    )
    return username_ok and password_ok


def _derive_signing_key(secret: str, username: str, password: str) -> str:
    material = f"{username}\x00{password}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), material, hashlib.sha256).hexdigest()


def _load_or_create_secret() -> str:
    raw_path = os.getenv("WEB_SESSION_SECRET_FILE", DEFAULT_SESSION_SECRET_FILE)
    path = Path(raw_path).expanduser()
    cache_key = str(path.resolve())
    with _secret_lock:
        cached = _secret_cache.get(cache_key)
        if cached:
            return cached

        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            existing = path.read_text(encoding="utf-8").strip()
            if existing:
                _secret_cache[cache_key] = existing
                return existing

        generated = secrets.token_urlsafe(48)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            existing = path.read_text(encoding="utf-8").strip()
            if not existing:
                raise RuntimeError(f"Web 会话密钥文件为空: {path}")
            _secret_cache[cache_key] = existing
            return existing

        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(generated)
            handle.write("\n")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

        _secret_cache[cache_key] = generated
        return generated


def resolve_session_settings() -> WebSessionSettings:
    settings = get_settings()
    configured_secret = (settings.web_session_secret or "").strip()
    base_secret = configured_secret or _load_or_create_secret()
    ttl_seconds = int(settings.web_session_ttl_seconds)
    ttl_seconds = max(MIN_SESSION_TTL_SECONDS, min(ttl_seconds, MAX_SESSION_TTL_SECONDS))
    return WebSessionSettings(
        username=settings.web_username,
        password=settings.web_password,
        signing_key=_derive_signing_key(
            base_secret,
            settings.web_username,
            settings.web_password,
        ),
        ttl_seconds=ttl_seconds,
    )


def create_session_token(
    username: str,
    signing_key: str,
    ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
    *,
    now: Optional[int] = None,
) -> str:
    issued_at = int(time.time() if now is None else now)
    expires_at = issued_at + max(1, int(ttl_seconds))
    payload = {
        "sub": username,
        "iat": issued_at,
        "exp": expires_at,
        "nonce": secrets.token_urlsafe(12),
    }
    encoded_payload = _b64url_encode(
        json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )
    signature = hmac.new(
        signing_key.encode("utf-8"),
        encoded_payload.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return f"{encoded_payload}.{_b64url_encode(signature)}"


def verify_session_token(
    token: Optional[str],
    signing_key: str,
    *,
    now: Optional[int] = None,
) -> Optional[str]:
    if not token or len(token) > MAX_SESSION_TOKEN_LENGTH or "." not in token:
        return None

    encoded_payload, encoded_signature = token.split(".", 1)
    expected_signature = _b64url_encode(
        hmac.new(
            signing_key.encode("utf-8"),
            encoded_payload.encode("ascii"),
            hashlib.sha256,
        ).digest()
    )
    if not hmac.compare_digest(encoded_signature, expected_signature):
        return None

    try:
        payload = json.loads(_b64url_decode(encoded_payload).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None

    if not isinstance(payload, dict):
        return None

    subject = payload.get("sub")
    issued_at = payload.get("iat")
    expires_at = payload.get("exp")
    if not isinstance(subject, str) or not subject:
        return None
    if not isinstance(issued_at, int) or not isinstance(expires_at, int):
        return None

    current_time = int(time.time() if now is None else now)
    if expires_at <= current_time or issued_at > current_time + 300:
        return None
    return subject


def authenticate_session_token(
    token: Optional[str],
    settings: WebSessionSettings,
) -> Optional[str]:
    username = verify_session_token(token, settings.signing_key)
    if username is None:
        return None
    if not hmac.compare_digest(username.encode("utf-8"), settings.username.encode("utf-8")):
        return None
    return username
