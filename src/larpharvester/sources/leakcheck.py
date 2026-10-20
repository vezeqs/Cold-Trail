from __future__ import annotations

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register


@register
class LeakCheck(Source):
    name = "leakcheck"
    label = "LeakCheck (Public)"
    kind = "email"
    group = "email"
    homepage = "https://leakcheck.io"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        status, data = await fetcher.get_json(
            "https://leakcheck.io/api/public",
            params={"check": target.strip()},
        )
        if status == 200 and isinstance(data, dict):
            found = int(data.get("found") or 0)
            if not data.get("success") or found <= 0:
                return self.missing(target, "no public breach records")
            sources = data.get("sources") or []
            fields = data.get("fields") or []
            names = [str(s.get("name")) for s in sources if isinstance(s, dict) and s.get("name")]
            return self.ok(
                target,
                Profile(
                    source=self.name,
                    username=target,
                    url="https://leakcheck.io",
                    bio=f"found in {found} breach record(s): {', '.join(names[:6])}",
                    extra={
                        "found": found,
                        "fields": fields,
                        "sources": sources[:25],
                    },
                ),
            )
        if status == 404:
            return self.missing(target)
        if status in (401, 403, 429):
            return self.blocked(target, f"HTTP {status}: rate limited")
        return self.failed(target, f"HTTP {status}")
