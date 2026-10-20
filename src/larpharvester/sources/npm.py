from __future__ import annotations

from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register
from .declarative import parse_meta


@register
class Npm(Source):
    name = "npm"
    label = "npm"
    group = "dev"
    homepage = "https://www.npmjs.com"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        status, text = await fetcher.get_text(f"https://www.npmjs.com/~{quote(target)}")
        if status != 200:
            return self.missing(target) if status == 404 else self.failed(target, f"HTTP {status}")
        meta = parse_meta(text)
        if not meta.title or meta.title.strip().casefold() == "npm":
            return self.missing(target)
        return self.ok(
            target,
            Profile(
                source=self.name,
                username=target,
                url=f"https://www.npmjs.com/~{target}",
                display_name=meta.title,
                bio=meta.description,
                avatar=meta.image,
            ),
        )
