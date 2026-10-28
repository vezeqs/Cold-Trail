from __future__ import annotations

from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register


@register
class RubyGems(Source):
    name = "rubygems"
    label = "RubyGems"
    group = "dev"
    homepage = "https://rubygems.org"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        status, data = await fetcher.get_json(
            f"https://rubygems.org/api/v1/profiles/{quote(target)}.json"
        )
        if status == 200 and isinstance(data, dict) and (data.get("handle") or data.get("id")):
            handle = str(data.get("handle") or target)
            extra = {"id": data.get("id")}
            if data.get("twitter"):
                twitter = str(data.get("twitter")).lstrip("@")
                extra["accounts"] = [{"service": "twitter", "username": twitter}]
            return self.ok(
                target,
                Profile(
                    source=self.name,
                    username=handle,
                    url=f"https://rubygems.org/profiles/{handle}",
                    display_name=handle,
                    avatar=data.get("avatar"),
                    extra=extra,
                ),
            )
        if status == 404:
            return self.missing(target)
        if status in (403, 429):
            return self.blocked(target, f"HTTP {status}: rate limited")
        return self.failed(target, f"HTTP {status}")
