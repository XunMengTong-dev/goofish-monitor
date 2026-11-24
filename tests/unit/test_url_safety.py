import socket

import pytest

from src.infrastructure.external.url_safety import (
    OutboundUrlError,
    ensure_response_not_redirect,
    validate_outbound_url,
)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8080/admin",
        "http://[::1]:8080/admin",
        "http://169.254.169.254/latest/meta-data",
        "http://localhost:8080/admin",
        "http://metadata.google.internal/computeMetadata/v1",
    ],
)
def test_validate_outbound_url_rejects_local_and_metadata_targets(url):
    with pytest.raises(OutboundUrlError):
        validate_outbound_url(url, resolve_dns=False)


def test_validate_outbound_url_rejects_unsafe_scheme_and_credentials():
    with pytest.raises(OutboundUrlError):
        validate_outbound_url("ftp://example.com/file", resolve_dns=False)
    with pytest.raises(OutboundUrlError):
        validate_outbound_url("https://user:pass@example.com/v1", resolve_dns=False)


def test_validate_outbound_url_allows_private_targets_when_enabled(monkeypatch):
    monkeypatch.setenv("OUTBOUND_ALLOW_PRIVATE_NETWORKS", "true")

    assert validate_outbound_url("http://127.0.0.1:11434/v1", resolve_dns=False)
    assert validate_outbound_url("http://192.168.1.20:8080/hook", resolve_dns=False)
    with pytest.raises(OutboundUrlError, match="元数据地址"):
        validate_outbound_url("http://169.254.169.254/latest", resolve_dns=False)
    with pytest.raises(OutboundUrlError, match="元数据地址"):
        validate_outbound_url("http://[fd00:ec2::254]/latest", resolve_dns=False)


def test_validate_outbound_url_allows_explicit_host_allowlist(monkeypatch):
    monkeypatch.setenv("OUTBOUND_ALLOWED_HOSTS", "localhost,*.internal.example")

    assert validate_outbound_url("http://localhost:8080/hook", resolve_dns=False)
    assert validate_outbound_url("http://gotify.internal.example/message", resolve_dns=False)


def test_validate_outbound_url_rejects_private_dns_resolution(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.8", 0))
        ],
    )

    with pytest.raises(OutboundUrlError, match="解析到受限网络地址"):
        validate_outbound_url("https://internal-service.example/v1")


def test_validate_outbound_url_allows_public_dns_resolution(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))
        ],
    )

    assert validate_outbound_url("https://example.com/v1") == "https://example.com/v1"


def test_ensure_response_not_redirect_rejects_redirect_statuses():
    class _Response:
        status_code = 302

    with pytest.raises(OutboundUrlError, match="不允许重定向"):
        ensure_response_not_redirect(_Response(), field_name="WEBHOOK_URL")
