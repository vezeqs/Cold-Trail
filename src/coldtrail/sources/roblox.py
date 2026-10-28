from __future__ import annotations

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register


@register
class Roblox(Source):
    name = "roblox"
    label = "Roblox"
    group = "social"
    homepage = "https://www.roblox.com"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        status, data = await fetcher.post_json(
            "https://users.roblox.com/v1/usernames/users",
            json={"usernames": [target], "excludeBannedUsers": False},
        )
        if status != 200 or not isinstance(data, dict) or not data.get("data"):
            return (
                self.missing(target)
                if status in (200, 404)
                else self.failed(target, f"HTTP {status}")
            )
        user_id = data["data"][0].get("id")
        if not user_id:
            return self.missing(target)
        status, profile = await fetcher.get_json(f"https://users.roblox.com/v1/users/{user_id}")
        if status != 200 or not isinstance(profile, dict):
            return self.failed(target, f"HTTP {status} fetching profile")
        return self.ok(
            target,
            Profile(
                source=self.name,
                username=profile.get("name") or target,
                url=f"https://www.roblox.com/users/{user_id}/profile",
                display_name=profile.get("displayName"),
                bio=profile.get("description"),
                avatar=(
                    "https://www.roblox.com/headshot-thumbnail/image"
                    f"?userId={user_id}&width=420&height=420&format=png"
                ),
                created_at=profile.get("created"),
                extra={
                    "id": user_id,
                    "banned": profile.get("isBanned"),
                    "verified": profile.get("hasVerifiedBadge"),
                },
            ),
        )
