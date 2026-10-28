from __future__ import annotations

from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register
from .declarative import parse_meta


@register
class HackerOne(Source):
    name = "hackerone"
    label = "HackerOne"
    group = "dev"
    homepage = "https://hackerone.com"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        status, data = await fetcher.get_json(f"https://hackerone.com/{quote(target)}.json")
        if (
            status == 200
            and isinstance(data, dict)
            and (data.get("username") or data.get("handle"))
        ):
            username = data.get("username") or data.get("handle")
            return self.ok(
                target,
                Profile(
                    source=self.name,
                    username=username,
                    url=f"https://hackerone.com/{username}",
                    display_name=data.get("name"),
                    bio=data.get("bio"),
                    avatar=data.get("profile_picture"),
                    website=data.get("website"),
                    created_at=data.get("joined_at"),
                    extra={
                        "id": data.get("id"),
                        "reputation": data.get("reputation"),
                        "signal": data.get("signal"),
                        "impact": data.get("impact"),
                        "location": data.get("location"),
                    },
                ),
            )
        if status == 404:
            return self.missing(target)
        if status == 200:
            text = ""
            status, text = await fetcher.get_text(f"https://hackerone.com/{quote(target)}")
            meta = parse_meta(text)
            if status == 200 and meta.title and "hackerone" not in meta.title.casefold():
                return self.ok(
                    target,
                    Profile(
                        source=self.name,
                        username=target,
                        url=f"https://hackerone.com/{target}",
                        display_name=meta.title,
                        bio=meta.description,
                        avatar=meta.image,
                    ),
                )
            return self.missing(target)
        if status in (403, 429):
            return self.blocked(target, f"HTTP {status}: rate limited")
        return self.failed(target, f"HTTP {status}")
