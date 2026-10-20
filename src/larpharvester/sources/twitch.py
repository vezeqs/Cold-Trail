from __future__ import annotations

from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register
from .declarative import parse_meta


@register
class Twitch(Source):
    name = "twitch"
    label = "Twitch"
    group = "social"
    homepage = "https://www.twitch.tv"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        status, text = await fetcher.get_text(f"https://www.twitch.tv/{quote(target)}")
        if status != 200:
            return (
                self.missing(target)
                if status in (404, 410)
                else self.failed(target, f"HTTP {status}")
            )
        meta = parse_meta(text)
        low_title = (meta.title or "").strip().casefold()
        if not meta.title or low_title in {"twitch", "twitch.tv"}:
            tf = target.casefold()
            if f'"{tf}"' in text.casefold() or f"/{tf}" in text.casefold():
                meta.title = target
            else:
                return self.missing(target)
        return self.ok(
            target,
            Profile(
                source=self.name,
                username=target,
                url=f"https://www.twitch.tv/{target}",
                display_name=meta.title,
                bio=meta.description,
                avatar=meta.image,
            ),
        )
