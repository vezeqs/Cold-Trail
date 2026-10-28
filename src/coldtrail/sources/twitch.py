from __future__ import annotations

import re
from urllib.parse import quote

from bs4 import BeautifulSoup

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
        # Real channels expose og:profile:username; missing handles return the
        # generic SPA shell (title "Twitch", no profile metadata) with HTTP 200.
        soup = BeautifulSoup(text[:32768], "html.parser")
        profile_tag = soup.find("meta", attrs={"property": "og:profile:username"})
        profile_user = profile_tag.get("content") if profile_tag else None
        if not profile_user or str(profile_user).casefold() != target.casefold():
            return self.missing(target)
        meta = parse_meta(text)
        title = (meta.title or "").strip()
        description = meta.description
        if description and "streams live on twitch" in description.casefold():
            description = None
        display = None
        if title and title.casefold() != f"{target.casefold()} - twitch":
            stripped = re.sub(r"\s*[-|]\s*Twitch\s*$", "", title, flags=re.IGNORECASE)
            display = stripped.strip() or None
        return self.ok(
            target,
            Profile(
                source=self.name,
                username=target,
                url=f"https://www.twitch.tv/{target}",
                display_name=display,
                bio=description,
                avatar=meta.image,
                extra={"profile_username": str(profile_user)},
            ),
        )
