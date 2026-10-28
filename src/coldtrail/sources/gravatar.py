from __future__ import annotations

import hashlib

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register


@register
class Gravatar(Source):
    name = "gravatar"
    label = "Gravatar"
    kind = "email"
    group = "email"
    homepage = "https://gravatar.com"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        digest = hashlib.md5(target.strip().casefold().encode(), usedforsecurity=False).hexdigest()
        status, data = await fetcher.get_json(f"https://gravatar.com/{digest}.json?d=404")
        entry = None
        if isinstance(data, dict):
            entries = data.get("entry")
            if isinstance(entries, list) and entries:
                entry = entries[0]
        if status == 200 and isinstance(entry, dict):
            name = entry.get("displayName") or " ".join(
                filter(
                    None,
                    [
                        (entry.get("name") or {}).get("givenName"),
                        (entry.get("name") or {}).get("familyName"),
                    ],
                )
            )
            accounts = [
                {
                    "service": account.get("shortname"),
                    "username": account.get("username"),
                    "url": account.get("url"),
                    "domain": account.get("domain"),
                    "verified": account.get("verified"),
                }
                for account in entry.get("accounts") or []
            ]
            return self.ok(
                target,
                Profile(
                    source=self.name,
                    username=entry.get("preferredUsername") or target,
                    url=entry.get("profileUrl") or f"https://gravatar.com/{digest}",
                    display_name=name or None,
                    bio=entry.get("aboutMe"),
                    avatar=entry.get("thumbnailUrl"),
                    website=(entry.get("urls") or [{}])[0].get("value")
                    if entry.get("urls")
                    else None,
                    extra={"accounts": accounts, "hash": digest},
                ),
            )
        if status in (404, 400):
            return self.missing(target)
        if status in (403, 429):
            return self.blocked(target, f"HTTP {status}: rate limited")
        return self.failed(target, f"HTTP {status}")
