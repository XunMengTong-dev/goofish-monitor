"""
Ntfy 通知客户端
"""
import asyncio
import requests
from typing import Dict

from src.infrastructure.external.url_safety import (
    ensure_response_not_redirect,
    validate_outbound_url,
)
from .base import NotificationClient


class NtfyClient(NotificationClient):
    """Ntfy 通知客户端"""

    channel_key = "ntfy"
    display_name = "Ntfy"

    def __init__(self, topic_url: str = None, pcurl_to_mobile: bool = True):
        super().__init__(enabled=bool(topic_url), pcurl_to_mobile=pcurl_to_mobile)
        self.topic_url = topic_url

    async def send(self, product_data: Dict, reason: str) -> None:
        """发送 Ntfy 通知"""
        if not self.is_enabled():
            raise RuntimeError("Ntfy 未启用")

        message = self._build_message(product_data, reason)
        topic_url = validate_outbound_url(
            str(self.topic_url or ""),
            field_name="NTFY_TOPIC_URL",
        )
        loop = asyncio.get_running_loop()
        response = await loop.run_in_executor(
            None,
            lambda: requests.post(
                topic_url,
                data=message.content.encode('utf-8'),
                headers={
                    "Title": message.notification_title.encode('utf-8'),
                    "Priority": "urgent",
                    "Tags": "bell,vibration"
                },
                timeout=10,
                allow_redirects=False,
            )
        )
        ensure_response_not_redirect(response, field_name="NTFY_TOPIC_URL")
        response.raise_for_status()
