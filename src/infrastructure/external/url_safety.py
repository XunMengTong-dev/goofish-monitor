"""外部请求 URL 的 SSRF 防护。"""
from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urljoin, urlsplit


ALLOW_PRIVATE_NETWORKS_ENV = "OUTBOUND_ALLOW_PRIVATE_NETWORKS"
ALLOWED_HOSTS_ENV = "OUTBOUND_ALLOWED_HOSTS"
BLOCKED_METADATA_HOSTS = {
    "metadata",
    "metadata.google.internal",
    "metadata.azure.internal",
}
BLOCKED_METADATA_ADDRESSES = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("fd00:ec2::254"),
}


class OutboundUrlError(ValueError):
    """外部请求 URL 未通过安全校验。"""


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _normalize_host(host: str) -> str:
    return str(host or "").strip().lower().rstrip(".")


def _allowed_host_patterns() -> tuple[str, ...]:
    raw = os.getenv(ALLOWED_HOSTS_ENV, "")
    return tuple(
        pattern
        for pattern in (_normalize_host(item) for item in raw.split(","))
        if pattern
    )


def _host_is_allowlisted(host: str) -> bool:
    normalized = _normalize_host(host)
    for pattern in _allowed_host_patterns():
        if pattern == normalized:
            return True
        if pattern.startswith("*."):
            suffix = pattern[2:]
            if normalized == suffix or normalized.endswith(f".{suffix}"):
                return True
        elif pattern.startswith("."):
            if normalized.endswith(pattern):
                return True
    return False


def _address_is_allowed(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    allow_private: bool,
) -> bool:
    if address.is_unspecified or address.is_multicast:
        return False
    if address.is_global:
        return True
    if allow_private and (address.is_private or address.is_loopback):
        return True
    return False


def _resolve_addresses(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []

    addresses = []
    seen = set()
    for info in infos:
        sockaddr = info[4]
        raw_address = str(sockaddr[0]).split("%", 1)[0]
        try:
            address = ipaddress.ip_address(raw_address)
        except ValueError:
            continue
        key = str(address)
        if key in seen:
            continue
        seen.add(key)
        addresses.append(address)
    return addresses


def validate_outbound_url(
    url: str,
    *,
    field_name: str = "URL",
    resolve_dns: bool = True,
) -> str:
    """校验 HTTP/HTTPS URL，阻止访问本机、私网和云元数据地址。"""
    text = str(url or "").strip()
    if not text:
        raise OutboundUrlError(f"{field_name} 不能为空")

    parsed = urlsplit(text)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise OutboundUrlError(f"{field_name} 必须是合法的 HTTP/HTTPS URL")
    if not parsed.netloc or not parsed.hostname:
        raise OutboundUrlError(f"{field_name} 必须是合法的 HTTP/HTTPS URL")
    if parsed.username or parsed.password:
        raise OutboundUrlError(f"{field_name} 不允许包含用户名或密码")
    try:
        parsed.port
    except ValueError as exc:
        raise OutboundUrlError(f"{field_name} 端口无效") from exc

    host = _normalize_host(parsed.hostname)
    if host in BLOCKED_METADATA_HOSTS:
        raise OutboundUrlError(f"{field_name} 指向受限的元数据地址")

    allowlisted = _host_is_allowlisted(host)
    allow_private = _env_bool(ALLOW_PRIVATE_NETWORKS_ENV, False)
    if allowlisted:
        return text

    if host == "localhost" or host.endswith(".localhost"):
        if not allow_private:
            raise OutboundUrlError(f"{field_name} 不允许访问本机地址")
        return text

    try:
        literal_address = ipaddress.ip_address(host)
    except ValueError:
        literal_address = None

    if literal_address is not None:
        if literal_address in BLOCKED_METADATA_ADDRESSES:
            raise OutboundUrlError(f"{field_name} 指向受限的元数据地址")
        if not _address_is_allowed(literal_address, allow_private=allow_private):
            raise OutboundUrlError(f"{field_name} 不允许访问受限网络地址")
        return text

    if resolve_dns:
        for address in _resolve_addresses(host):
            if address in BLOCKED_METADATA_ADDRESSES:
                raise OutboundUrlError(f"{field_name} 解析到受限的元数据地址")
            if not _address_is_allowed(address, allow_private=allow_private):
                raise OutboundUrlError(f"{field_name} 解析到受限网络地址")
    return text


def ensure_response_not_redirect(response, *, field_name: str = "URL") -> None:
    """拒绝重定向响应，避免绕过目标地址校验。"""
    status_code = int(getattr(response, "status_code", 0) or 0)
    if 300 <= status_code < 400:
        raise OutboundUrlError(f"{field_name} 不允许重定向")


def resolve_validated_redirect_url(
    current_url: str,
    response,
    *,
    field_name: str = "URL",
) -> str | None:
    """返回经校验的重定向目标；非重定向响应返回 None。"""
    status_code = int(getattr(response, "status_code", 0) or 0)
    if not 300 <= status_code < 400:
        return None

    headers = getattr(response, "headers", {}) or {}
    location = headers.get("Location") or headers.get("location")
    if not location:
        raise OutboundUrlError(f"{field_name} 重定向缺少 Location")
    return validate_outbound_url(
        urljoin(current_url, str(location)),
        field_name=field_name,
    )
