import asyncio
from pathlib import Path

import pytest

import src.ai_handler as ai_handler
from src.infrastructure.external.url_safety import OutboundUrlError


class _FakeImageResponse:
    def __init__(self, status_code, *, headers=None, content=b""):
        self.status_code = status_code
        self.headers = headers or {}
        self._content = content
        self.closed = False

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def iter_content(self, chunk_size=8192):
        yield self._content

    def close(self):
        self.closed = True


def test_download_single_image_follows_validated_redirect(tmp_path, monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        if len(calls) == 1:
            return _FakeImageResponse(
                302,
                headers={"Location": "https://cdn.example.com/final.jpg"},
            )
        return _FakeImageResponse(200, content=b"image-bytes")

    monkeypatch.setattr(ai_handler.requests, "get", fake_get)
    save_path = tmp_path / "image.jpg"

    result = asyncio.run(
        ai_handler._download_single_image(
            "https://images.example.com/source.jpg",
            str(save_path),
        )
    )

    assert result == str(save_path)
    assert save_path.read_bytes() == b"image-bytes"
    assert [call[0] for call in calls] == [
        "https://images.example.com/source.jpg",
        "https://cdn.example.com/final.jpg",
    ]
    assert all(call[1]["allow_redirects"] is False for call in calls)


def test_download_single_image_rejects_private_redirect_without_retry(tmp_path, monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        return _FakeImageResponse(
            302,
            headers={"Location": "http://127.0.0.1:8080/admin"},
        )

    monkeypatch.setattr(ai_handler.requests, "get", fake_get)

    with pytest.raises(OutboundUrlError, match="受限网络地址"):
        asyncio.run(
            ai_handler._download_single_image(
                "https://images.example.com/source.jpg",
                str(tmp_path / "image.jpg"),
            )
        )

    assert calls == ["https://images.example.com/source.jpg"]


def test_download_all_images_skips_private_urls(tmp_path, monkeypatch):
    monkeypatch.setattr(ai_handler, "IMAGE_SAVE_DIR", str(tmp_path / "images"))
    called = False

    async def fake_download(url, save_path):
        nonlocal called
        called = True
        return save_path

    monkeypatch.setattr(ai_handler, "_download_single_image", fake_download)

    paths = asyncio.run(
        ai_handler.download_all_images(
            "product-1",
            ["http://127.0.0.1/private.jpg"],
            task_name="demo",
        )
    )

    assert paths == []
    assert called is False


def test_download_all_images_runs_with_concurrency(tmp_path, monkeypatch):
    monkeypatch.setattr(ai_handler, "IMAGE_SAVE_DIR", str(tmp_path / "images"))

    active_downloads = 0
    max_active_downloads = 0

    async def fake_download(url, save_path):
        nonlocal active_downloads, max_active_downloads
        active_downloads += 1
        max_active_downloads = max(max_active_downloads, active_downloads)
        await asyncio.sleep(0.02)
        Path(save_path).parent.mkdir(parents=True, exist_ok=True)
        Path(save_path).write_text("ok", encoding="utf-8")
        active_downloads -= 1
        return save_path

    monkeypatch.setattr(ai_handler, "_download_single_image", fake_download)

    async def run():
        return await ai_handler.download_all_images(
            "product-1",
            [
                "https://example.com/1.jpg",
                "https://example.com/2.jpg",
                "https://example.com/3.jpg",
            ],
            task_name="demo",
            concurrency=3,
        )

    paths = asyncio.run(run())
    assert len(paths) == 3
    assert max_active_downloads == 3
