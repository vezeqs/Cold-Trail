from __future__ import annotations

from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register


@register
class Codeberg(Source):
    name = "codeberg"
    label = "Codeberg"
    group = "dev"
    homepage = "https://codeberg.org"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        status, data = await fetcher.get_json(f"https://codeberg.org/api/v1/users/{quote(target)}")
        if status == 200 and isinstance(data, dict) and data.get("login"):
            return self.ok(
                target,
                Profile(
                    source=self.name,
                    username=data["login"],
                    url=data.get("html_url") or f"https://codeberg.org/{data['login']}",
                    display_name=data.get("full_name"),
                    bio=data.get("description"),
                    avatar=data.get("avatar_url"),
                    website=data.get("website"),
                    created_at=data.get("created"),
                    followers=data.get("followers_count"),
                    extra={
                        "id": data.get("id"),
                        "location": data.get("location"),
                        "language": data.get("language"),
                        "following": data.get("following_count"),
                        "starred_repos": data.get("starred_repos_count"),
                        "visibility": data.get("visibility"),
                    },
                ),
            )
        if status == 404:
            return self.missing(target)
        if status in (403, 429):
            return self.blocked(target, f"HTTP {status}: rate limited")
        return self.failed(target, f"HTTP {status}")
