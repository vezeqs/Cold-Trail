from __future__ import annotations

import re
from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register
from .declarative import parse_meta

GENERIC_TITLES = {"vk", "vk | vk", "user not found", "page not found"}


@register
class VK(Source):
    name = "vk"
    label = "VK"
    group = "social"
    homepage = "https://vk.com"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        handle = target.strip().lstrip("@")
        url = f"https://vk.com/{quote(handle)}"
        status, text = await fetcher.get_text(url)
        if status == 404:
            return self.missing(target)
        if status in (403, 429):
            return self.blocked(target, f"HTTP {status}: rate limited")
        if status != 200:
            return self.failed(target, f"HTTP {status}")
        meta = parse_meta(text)
        title = (meta.title or "").strip()
        low = title.casefold()
        body_low = text[:20000].casefold()
        if low in GENERIC_TITLES or "user not found" in body_low:
            return self.missing(target, "user not found")
        if not title:
            return self.blocked(target, "no profile metadata (login wall or changed markup)")
        display = re.sub(r"\s*\|\s*VK.*$", "", title, flags=re.IGNORECASE).strip()
        return self.ok(
            target,
            Profile(
                source=self.name,
                username=handle,
                url=url,
                display_name=display or handle,
                bio=meta.description,
                avatar=meta.image,
            ),
        )
