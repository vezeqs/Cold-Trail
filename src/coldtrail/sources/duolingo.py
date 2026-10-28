from __future__ import annotations

from ..http import Fetcher
from ..models import CheckResult, Profile
from ..utils import parse_dt
from .base import Source, register


@register
class Duolingo(Source):
    name = "duolingo"
    label = "Duolingo"
    group = "social"
    homepage = "https://www.duolingo.com"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        status, data = await fetcher.get_json(
            "https://www.duolingo.com/2017-06-30/users", params={"username": target}
        )
        if status != 200 or not isinstance(data, dict):
            return self.missing(target) if status == 404 else self.failed(target, f"HTTP {status}")
        users = data.get("users") or []
        if not users:
            return self.missing(target)
        user = users[0]
        return self.ok(
            target,
            Profile(
                source=self.name,
                username=user.get("username") or target,
                url=f"https://www.duolingo.com/profile/{user.get('username') or target}",
                display_name=user.get("name"),
                bio=user.get("bio"),
                avatar=user.get("picture"),
                created_at=parse_dt(user.get("creationDate")).isoformat()
                if parse_dt(user.get("creationDate"))
                else None,
                followers=user.get("followers"),
                extra={
                    "id": user.get("id"),
                    "total_xp": user.get("totalXp"),
                    "streak": user.get("streak"),
                    "location": user.get("location"),
                    "courses": [
                        course.get("title")
                        for course in user.get("courses") or []
                        if course.get("title")
                    ],
                },
            ),
        )
