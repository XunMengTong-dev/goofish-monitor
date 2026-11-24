import asyncio

import pytest

from src.infrastructure.external.notification_clients.base import NotificationClient
from src.infrastructure.external.notification_clients.pushplus_client import PushPlusClient
from src.infrastructure.external.notification_clients.webhook_client import WebhookClient
from src.infrastructure.external.url_safety import OutboundUrlError
from src.services.notification_service import NotificationService


class _OkClient(NotificationClient):
    channel_key = "ok"
    display_name = "OK"

    async def send(self, product_data, reason):
        return None


class _FailClient(NotificationClient):
    channel_key = "fail"
    display_name = "FAIL"

    async def send(self, product_data, reason):
        raise RuntimeError("boom")


def test_notification_service_collects_success_and_failure_results():
    service = NotificationService([_OkClient(enabled=True), _FailClient(enabled=True)])

    results = asyncio.run(
        service.send_notification({"商品标题": "Sony A7M4"}, "价格合适")
    )

    assert results["ok"]["success"] is True
    assert results["ok"]["message"] == "发送成功"
    assert results["fail"]["success"] is False
    assert results["fail"]["message"] == "boom"


def test_webhook_client_renders_json_templates(monkeypatch):
    captured = {}

    class _FakeResponse:
        def raise_for_status(self):
            return None

    def _fake_post(url, headers=None, json=None, data=None, timeout=None, allow_redirects=True):
        captured["url"] = url
        captured["headers"] = headers
        captured["json"] = json
        captured["data"] = data
        captured["allow_redirects"] = allow_redirects
        return _FakeResponse()

    monkeypatch.setattr("requests.post", _fake_post)

    client = WebhookClient(
        webhook_url="https://hooks.example.com/notify",
        webhook_method="POST",
        webhook_headers='{"Authorization":"Bearer token"}',
        webhook_content_type="JSON",
        webhook_query_parameters='{"task":"{{title}}"}',
        webhook_body='{"message":"{{content}}","link":"{{desktop_link}}"}',
        pcurl_to_mobile=False,
    )

    asyncio.run(
        client.send(
            {
                "商品标题": "Sony A7M4",
                "当前售价": "9999",
                "商品链接": "https://www.goofish.com/item/123",
            },
            "价格合适",
        )
    )

    assert "task=%F0%9F%9A%A8+%E6%96%B0%E6%8E%A8%E8%8D%90%21+Sony+A7M4" in captured["url"]
    assert captured["headers"]["Authorization"] == "Bearer token"
    assert captured["json"]["message"].startswith("价格: 9999")
    assert captured["json"]["link"] == "https://www.goofish.com/item/123"
    assert captured["data"] is None
    assert captured["allow_redirects"] is False


def test_webhook_client_rejects_redirect_responses(monkeypatch):
    class _RedirectResponse:
        status_code = 302

        def raise_for_status(self):
            return None

    def _fake_post(url, headers=None, json=None, data=None, timeout=None, allow_redirects=True):
        return _RedirectResponse()

    monkeypatch.setattr("requests.post", _fake_post)
    client = WebhookClient(
        webhook_url="https://hooks.example.com/notify",
        webhook_method="POST",
        pcurl_to_mobile=False,
    )

    with pytest.raises(OutboundUrlError, match="不允许重定向"):
        asyncio.run(client.send(_product(), "价格合适"))


def test_webhook_client_rejects_private_url_before_sending(monkeypatch):
    called = False

    def _fake_post(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("private URL must not be requested")

    monkeypatch.setattr("requests.post", _fake_post)
    client = WebhookClient(
        webhook_url="http://127.0.0.1:8080/notify",
        webhook_method="POST",
        pcurl_to_mobile=False,
    )

    with pytest.raises(OutboundUrlError, match="受限网络地址"):
        asyncio.run(client.send(_product(), "价格合适"))
    assert called is False


def _product():
    return {
        "商品标题": "Sony A7M4",
        "当前售价": "9999",
        "商品链接": "https://www.goofish.com/item/123",
    }


def test_pushplus_client_sends_text_template_and_requires_business_code(monkeypatch):
    captured = {}

    class _FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"code": 200, "msg": "请求成功"}

    def _fake_post(url, json=None, timeout=None, allow_redirects=True):
        captured["url"] = url
        captured["json"] = json
        captured["timeout"] = timeout
        return _FakeResponse()

    monkeypatch.setattr("requests.post", _fake_post)
    client = PushPlusClient("test-token", "group-code", pcurl_to_mobile=False)

    asyncio.run(client.send(_product(), "价格合适"))

    assert captured["url"] == "https://www.pushplus.plus/send"
    assert captured["json"]["token"] == "test-token"
    assert captured["json"]["topic"] == "group-code"
    assert captured["json"]["template"] == "txt"
    assert captured["json"]["content"].startswith("价格: 9999\n原因: 价格合适")


def test_pushplus_client_rejects_business_error_with_http_200(monkeypatch):
    class _FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"code": 903, "msg": "无效的用户token"}

    monkeypatch.setattr(
        "requests.post",
        lambda *args, **kwargs: _FakeResponse(),
    )
    client = PushPlusClient("bad-token", pcurl_to_mobile=False)

    with pytest.raises(RuntimeError, match="无效的用户token"):
        asyncio.run(client.send(_product(), "价格合适"))
