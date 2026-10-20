from __future__ import annotations

import hashlib

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register


@register
class Libravatar(Source):
    name = "libravatar"
    label = "Libravatar"
    kind = "email"
    group = "email"
    homepage = "https://www.libravatar.org"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        normalized = target.strip().casefold()
        digest = hashlib.sha256(normalized.encode()).hexdigest()
        avatar_url = f"https://seccdn.libravatar.org/avatar/{digest}?d=404&s=200"
        response = await fetcher.get(avatar_url)
        if response.status == 200 and response.content:
            return self.ok(
                target,
                Profile(
                    source=self.name,
                    username=normalized,
                    url=f"https://www.libravatar.org/avatar/{digest}",
                    avatar=f"https://seccdn.libravatar.org/avatar/{digest}?s=200",
                    extra={"sha256": digest, "email": normalized},
                ),
            )
        if response.status == 404:
            return self.missing(target)
        if response.status in (403, 429):
            return self.blocked(target, f"HTTP {response.status}: rate limited")
        return self.failed(target, f"HTTP {response.status}")
