from __future__ import annotations

import re
from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register
from .declarative import parse_meta

GENERIC_TITLES = {"snapchat", "snapchat - the fastest way to share a moment!", "page not found"}


@register
class Snapchat(Source):
    name = "snapchat"
    label = "Snapchat"
    group = "social"
    homepage = "https://www.snapchat.com"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        handle = target.strip().lstrip("@")
        url = f"https://www.snapchat.com/add/{quote(handle)}"
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
            if "this account does not exist" in text[:20000].casefold():
                return self.missing(target, "account does not exist")
            return self.blocked(target, "no profile metadata (changed markup)")
        display = re.sub(r"\s*[-|]\s*Snapchat.*$", "", title, flags=re.IGNORECASE).strip()
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
