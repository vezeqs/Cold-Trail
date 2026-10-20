from __future__ import annotations

from urllib.parse import quote

from bs4 import BeautifulSoup

from ..http import Fetcher
from ..models import CheckResult, Profile
from ..utils import strip_html
from .base import Source, register


@register
class Telegram(Source):
    name = "telegram"
    label = "Telegram"
    group = "social"
    homepage = "https://t.me"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        status, text = await fetcher.get_text(f"https://t.me/{quote(target)}")
        if status != 200:
            return self.missing(target) if status == 404 else self.failed(target, f"HTTP {status}")
        soup = BeautifulSoup(text, "html.parser")
        title_node = soup.select_one(".tgme_page_title")
        extra_node = soup.select_one(".tgme_page_extra")
        if title_node is None and extra_node is None:
            return self.missing(target)
        title = strip_html(title_node.get_text(" ", strip=True) if title_node else None)
        description = soup.select_one(".tgme_page_description")
        image = soup.select_one("meta[property='og:image']")
        return self.ok(
            target,
            Profile(
                source=self.name,
                username=target,
                url=f"https://t.me/{target}",
                display_name=title,
                bio=strip_html(description.get_text(" ", strip=True) if description else None),
                avatar=str(image["content"]) if image and image.get("content") else None,
                extra={
                    "extra": strip_html(
                        extra_node.get_text(" ", strip=True) if extra_node else None
                    ),
                    "channel": soup.select_one(".tgme_channel_info") is not None,
                },
            ),
        )
