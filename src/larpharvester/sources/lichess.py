from __future__ import annotations

from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Profile
from ..utils import parse_dt
from .base import Source, register


@register
class Lichess(Source):
    name = "lichess"
    label = "Lichess"
    group = "social"
    homepage = "https://lichess.org"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        status, data = await fetcher.get_json(
            f"https://lichess.org/api/user/{quote(target.casefold())}"
        )
        if status == 200 and isinstance(data, dict) and data.get("username"):
            profile = data.get("profile") or {}
            created = data.get("createdAt")
            created_iso = None
            if isinstance(created, (int, float)):
                # Lichess createdAt is in milliseconds
                dt = parse_dt(created / 1000.0 if created > 1e11 else created)
                created_iso = dt.isoformat() if dt else None
            elif created:
                dt = parse_dt(created)
                created_iso = dt.isoformat() if dt else None
            return self.ok(
                target,
                Profile(
                    source=self.name,
                    username=data["username"],
                    url=data.get("url") or f"https://lichess.org/@/{data['username']}",
                    display_name=profile.get("realName") or data.get("username"),
                    bio=profile.get("bio"),
                    avatar=data.get("avatar"),
                    website=(profile.get("links") or "").split()[0]
                    if profile.get("links")
                    else None,
                    created_at=created_iso,
                    followers=data.get("followers"),
                    extra={
                        "id": data.get("id"),
                        "location": profile.get("location"),
                        "country": profile.get("country"),
                        "title": data.get("title"),
                        "disabled": data.get("disabled"),
                        "tos_violation": data.get("tosViolation"),
                    },
                ),
            )
        if status == 404:
            return self.missing(target)
        if status in (403, 429):
            return self.blocked(target, f"HTTP {status}: rate limited")
        return self.failed(target, f"HTTP {status}")
