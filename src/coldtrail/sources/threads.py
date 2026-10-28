from __future__ import annotations

import re
from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register
from .declarative import parse_meta

BLOCKED_MARKERS = (
    "log in to threads",
    "login • threads",
    "you must log in",
    "please log in",
)


@register
class Threads(Source):
    name = "threads"
    label = "Threads"
    group = "social"
    homepage = "https://www.threads.net"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        handle = target.strip().lstrip("@")
        url = f"https://www.threads.net/@{quote(handle)}"
        status, text = await fetcher.get_text(url)
        if status == 404:
            return self.missing(target)
        if status in (403, 429):
            return self.blocked(target, f"HTTP {status}: rate limited")
        if status != 200:
            return self.failed(target, f"HTTP {status}")
        low = text[:20000].casefold()
        if any(marker in low for marker in BLOCKED_MARKERS):
            return self.blocked(target, "login wall")
        meta = parse_meta(text)
        title = (meta.title or "").strip()
        title_low = title.casefold()
        if not title or title_low in {"threads", "log in", "threads • log in"}:
            if "page isn't available" in low or "page not found" in low:
                return self.missing(target, "profile page not found")
            return self.blocked(target, "no profile metadata (login wall or changed markup)")
        display = re.sub(r"\s*\(@[^)]+\).*$", "", title).strip()
        display = re.sub(r"\s+on Threads.*$", "", display, flags=re.IGNORECASE).strip()
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
