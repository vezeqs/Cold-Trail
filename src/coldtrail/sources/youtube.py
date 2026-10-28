from __future__ import annotations

from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register


@register
class YouTube(Source):
    name = "youtube"
    label = "YouTube"
    group = "social"
    homepage = "https://www.youtube.com"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        handle = target.lstrip("@")
        channel_url = f"https://www.youtube.com/@{quote(handle)}"
        status, data = await fetcher.get_json(
            "https://www.youtube.com/oembed",
            params={"url": channel_url, "format": "json"},
        )
        if status == 200 and isinstance(data, dict) and data.get("author_name"):
            return self.ok(
                target,
                Profile(
                    source=self.name,
                    username=handle,
                    url=data.get("author_url") or channel_url,
                    display_name=data.get("author_name"),
                    avatar=data.get("thumbnail_url"),
                    extra={
                        "title": data.get("title"),
                        "provider": data.get("provider_name"),
                    },
                ),
            )
        if status in (400, 401, 404):
            return self.missing(target)
        if status in (403, 429):
            return self.blocked(target, f"HTTP {status}: rate limited")
        return self.failed(target, f"HTTP {status}")
