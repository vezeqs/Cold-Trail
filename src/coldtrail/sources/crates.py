from __future__ import annotations

from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register


@register
class Crates(Source):
    name = "crates"
    label = "crates.io"
    group = "dev"
    homepage = "https://crates.io"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        status, data = await fetcher.get_json(f"https://crates.io/api/v1/users/{quote(target)}")
        user = data.get("user") if isinstance(data, dict) else None
        if status == 200 and isinstance(user, dict) and user.get("login"):
            login = str(user.get("login"))
            return self.ok(
                target,
                Profile(
                    source=self.name,
                    username=login,
                    url=user.get("url") or f"https://crates.io/users/{login}",
                    display_name=user.get("name") or login,
                    avatar=user.get("avatar"),
                    extra={"id": user.get("id")},
                ),
            )
        if status == 404:
            return self.missing(target)
        if status in (403, 429):
            return self.blocked(target, f"HTTP {status}: rate limited")
        return self.failed(target, f"HTTP {status}")
