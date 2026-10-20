from __future__ import annotations

from ..http import Fetcher
from ..models import CheckResult, Profile
from ..utils import parse_dt
from .base import Source, register

API = "https://api.stackexchange.com/2.3"


@register
class StackOverflow(Source):
    name = "stackoverflow"
    label = "Stack Overflow"
    group = "dev"
    homepage = "https://stackoverflow.com"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        status, data = await fetcher.get_json(
            f"{API}/users",
            params={
                "site": "stackoverflow",
                "inname": target,
                "sort": "name",
                "pagesize": 100,
                "filter": "default",
            },
        )
        if status != 200 or not isinstance(data, dict):
            return self.failed(target, f"HTTP {status}")
        items = data.get("items") or []
        user = next(
            (
                item
                for item in items
                if str(item.get("display_name", "")).casefold() == target.casefold()
                or str(item.get("link", ""))
                .rstrip("/")
                .casefold()
                .endswith(f"/{target.casefold()}")
            ),
            None,
        )
        if user is None:
            return self.missing(target)
        return self.ok(
            target,
            Profile(
                source=self.name,
                username=user.get("display_name") or target,
                url=user.get("link") or f"https://stackoverflow.com/users/{user.get('user_id')}",
                display_name=user.get("display_name"),
                bio=user.get("about_me"),
                avatar=user.get("profile_image"),
                website=user.get("website_url"),
                created_at=parse_dt(user.get("creation_date")).isoformat()
                if parse_dt(user.get("creation_date"))
                else None,
                extra={
                    "user_id": user.get("user_id"),
                    "reputation": user.get("reputation"),
                    "location": user.get("location"),
                    "badges": user.get("badge_counts"),
                    "account_id": user.get("account_id"),
                },
            ),
        )
