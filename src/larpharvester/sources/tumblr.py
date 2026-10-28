from __future__ import annotations

import re
from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register
from .declarative import parse_meta

HANDLE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$", re.IGNORECASE)
GENERIC_TITLES = {"tumblr", "page not found", "not found"}


@register
class Tumblr(Source):
    name = "tumblr"
    label = "Tumblr"
    group = "social"
    homepage = "https://www.tumblr.com"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        handle = target.strip().lstrip("@").lower()
        if not HANDLE_RE.match(handle):
            return self.missing(target, "not a valid Tumblr blog name")
        url = f"https://{quote(handle)}.tumblr.com/"
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
            if "there's nothing here" in text[:20000].casefold():
                return self.missing(target, "blog not found")
            return self.blocked(target, "no profile metadata (changed markup)")
        display = re.sub(r"\s*[-|]\s*Tumblr.*$", "", title, flags=re.IGNORECASE).strip()
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
