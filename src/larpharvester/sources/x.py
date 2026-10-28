from __future__ import annotations

from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register


@register
class XTwitter(Source):
    name = "x"
    label = "X (Twitter)"
    kind = "username"
    group = "social"
    homepage = "https://x.com"
    requires_auth = True

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        token = fetcher.settings.x_bearer_token
        if not token:
            return self.blocked(target, "X_BEARER_TOKEN is not configured")
        handle = target.strip().lstrip("@")
        status, data = await fetcher.get_json(
            f"https://api.x.com/2/users/by/username/{quote(handle)}",
            params={
                "user.fields": (
                    "created_at,description,location,profile_image_url,public_metrics,url,verified"
                )
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        if status == 404:
            return self.missing(target, "user not found")
        if status in (401, 403):
            return self.blocked(target, "X rejected the bearer token")
        if status == 429:
            return self.blocked(target, "rate limited by X")
        if status != 200:
            return self.failed(target, f"HTTP {status}")
        if not isinstance(data, dict):
            return self.failed(target, "unexpected X API payload")
        user = data.get("data")
        if not isinstance(user, dict):
            errors = data.get("errors") or []
            detail = errors[0].get("detail") if errors and isinstance(errors[0], dict) else None
            if detail and "not found" in str(detail).casefold():
                return self.missing(target, str(detail))
            return self.failed(target, detail or "no user object in X response")
        username = str(user.get("username") or handle)
        metrics = user.get("public_metrics") or {}
        return self.ok(
            target,
            Profile(
                source=self.name,
                username=username,
                url=f"https://x.com/{username}",
                display_name=user.get("name"),
                bio=user.get("description"),
                avatar=user.get("profile_image_url"),
                website=user.get("url"),
                created_at=user.get("created_at"),
                followers=metrics.get("followers_count") if isinstance(metrics, dict) else None,
                extra={
                    "x_id": user.get("id"),
                    "location": user.get("location"),
                    "verified": user.get("verified"),
                    "public_metrics": metrics,
                },
            ),
        )
