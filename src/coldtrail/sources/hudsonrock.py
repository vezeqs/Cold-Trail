from __future__ import annotations

from ..http import Fetcher
from ..models import CheckResult, Profile
from ..utils import sensitive_cache_key
from .base import Source, register


@register
class HudsonRock(Source):
    name = "hudsonrock"
    label = "HudsonRock Cavalier"
    kind = "email"
    group = "email"
    homepage = "https://cavalier.hudsonrock.com"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        status, data = await fetcher.get_json(
            "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email",
            params={"email": target.strip()},
            cache_key=sensitive_cache_key("hudsonrock", target),
        )
        if status == 200 and isinstance(data, dict):
            stealers = data.get("stealers") or []
            if not stealers:
                return self.missing(target, "not found in infostealer telemetry")
            first = stealers[0] if isinstance(stealers[0], dict) else {}
            date_compromised = first.get("date_compromised")
            computer = first.get("computer_name")
            os_name = first.get("operating_system")
            summary = f"infostealer exposure ({len(stealers)} record(s))"
            if os_name:
                summary += f" · {os_name}"
            return self.ok(
                target,
                Profile(
                    source=self.name,
                    username=target,
                    url="https://cavalier.hudsonrock.com",
                    bio=summary,
                    created_at=date_compromised,
                    extra={
                        "message": data.get("message"),
                        "stealer_count": len(stealers),
                        "computer_name": computer,
                        "operating_system": os_name,
                        "stealers": stealers[:10],
                    },
                ),
            )
        if status == 404:
            return self.missing(target)
        if status in (401, 403, 429):
            return self.blocked(target, f"HTTP {status}: rate limited")
        return self.failed(target, f"HTTP {status}")
