from __future__ import annotations

import re
from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register
from .declarative import parse_meta

GENERIC_TITLES = {"pinterest", "page not found", "pinterest login"}


@register
class Pinterest(Source):
    name = "pinterest"
    label = "Pinterest"
    group = "social"
    homepage = "https://www.pinterest.com"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        handle = target.strip().lstrip("@")
        url = f"https://www.pinterest.com/{quote(handle)}/"
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
        if not title or low in GENERIC_TITLES:
            if "user not found" in text[:20000].casefold():
                return self.missing(target, "user not found")
            return self.blocked(target, "no profile metadata (login wall or changed markup)")
        display = re.sub(r"\s*\([^)]*\)\s*-\s*Profile.*$", "", title, flags=re.IGNORECASE).strip()
        display = re.sub(r"\s*[-|]\s*Pinterest.*$", "", display, flags=re.IGNORECASE).strip()
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
