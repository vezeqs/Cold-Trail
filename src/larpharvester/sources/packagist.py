from __future__ import annotations

from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register


@register
class Packagist(Source):
    name = "packagist"
    label = "Packagist"
    group = "dev"
    homepage = "https://packagist.org"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        vendor = target.strip().casefold()
        status, data = await fetcher.get_json(
            "https://packagist.org/packages/list.json",
            params={"vendor": vendor},
        )
        if status == 200 and isinstance(data, dict):
            names = data.get("packageNames") or []
            if not names:
                return self.missing(target)
            return self.ok(
                target,
                Profile(
                    source=self.name,
                    username=vendor,
                    url=f"https://packagist.org/users/{quote(target)}/",
                    display_name=target,
                    bio=f"{len(names)} PHP package(s): {', '.join(names[:5])}",
                    extra={"packages": names[:50], "package_count": len(names)},
                ),
            )
        if status == 404:
            return self.missing(target)
        if status in (403, 429):
            return self.blocked(target, f"HTTP {status}: rate limited")
        return self.failed(target, f"HTTP {status}")
