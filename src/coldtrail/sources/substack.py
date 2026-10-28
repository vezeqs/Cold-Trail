from __future__ import annotations

from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register
from .declarative import parse_meta


@register
class Substack(Source):
    name = "substack"
    label = "Substack"
    group = "social"
    homepage = "https://substack.com"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        handle = target.strip().lstrip("@")
        url = f"https://substack.com/@{quote(handle)}"
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
        if (
            not title
            or low in {"substack", "page not found"}
            or "not found" in low
            or low.startswith("search ")
            or " on substack" in low
        ):
            return self.missing(target)
        display = title.split("|")[0].strip() or handle
        return self.ok(
            target,
            Profile(
                source=self.name,
                username=handle,
                url=url,
                display_name=display,
                bio=meta.description,
                avatar=meta.image,
            ),
        )
