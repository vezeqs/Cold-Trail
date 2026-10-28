from __future__ import annotations

from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register


@register
class HIBP(Source):
    name = "hibp"
    label = "Have I Been Pwned"
    kind = "email"
    group = "email"
    homepage = "https://haveibeenpwned.com"
    requires_auth = True

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        key = fetcher.settings.hibp_api_key
        if not key:
            return self.blocked(target, "HIBP_API_KEY is not configured")
        status, data = await fetcher.get_json(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(target)}",
            params={"truncateResponse": "false"},
            headers={"hibp-api-key": key},
        )
        if status == 200 and isinstance(data, list):
            breaches = [
                {
                    "name": item.get("Name"),
                    "title": item.get("Title"),
                    "date": item.get("BreachDate"),
                    "pwn_count": item.get("PwnCount"),
                    "data_classes": item.get("DataClasses"),
                }
                for item in data
            ]
            return self.ok(
                target,
                Profile(
                    source=self.name,
                    username=target,
                    url="https://haveibeenpwned.com",
                    bio=f"appears in {len(breaches)} breaches",
                    extra={"breaches": breaches, "count": len(breaches)},
                ),
            )
        if status == 404:
            return self.missing(target, "not found in any breach")
        if status == 401:
            return self.blocked(target, "HIBP rejected the API key")
        if status in (403, 429):
            return self.blocked(target, f"HTTP {status}: rate limited")
        return self.failed(target, f"HTTP {status}")
