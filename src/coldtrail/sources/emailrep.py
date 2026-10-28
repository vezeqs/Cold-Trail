from __future__ import annotations

from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Profile
from ..utils import sensitive_cache_key
from .base import Source, register


@register
class EmailRep(Source):
    name = "emailrep"
    label = "EmailRep"
    kind = "email"
    group = "email"
    homepage = "https://emailrep.io"
    requires_auth = True

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        key = fetcher.settings.emailrep_api_key
        if not key:
            return self.blocked(target, "EMAILREP_API_KEY is not configured")
        status, data = await fetcher.get_json(
            f"https://emailrep.io/{quote(target)}",
            headers={"Key": key},
            cache_key=sensitive_cache_key("emailrep", target),
        )
        if status == 200 and isinstance(data, dict) and data.get("email"):
            details = data.get("details") or {}
            profiles = details.get("profiles") or []
            accounts = [
                {"service": url.split("/")[2] if "//" in url else url, "url": url}
                for url in profiles
            ]
            return self.ok(
                target,
                Profile(
                    source=self.name,
                    username=target,
                    url=f"https://emailrep.io/{quote(target)}",
                    bio=f"reputation: {data.get('reputation')}",
                    extra={
                        "reputation": data.get("reputation"),
                        "suspicious": data.get("suspicious"),
                        "references": data.get("references"),
                        "details": details,
                        "accounts": accounts,
                    },
                ),
            )
        if status == 404:
            return self.missing(target)
        if status in (401, 403):
            return self.blocked(target, f"HTTP {status}: key rejected or quota exhausted")
        if status == 429:
            return self.blocked(target, "rate limited")
        return self.failed(target, f"HTTP {status}")
