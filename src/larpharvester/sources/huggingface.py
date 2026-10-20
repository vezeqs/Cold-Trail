from __future__ import annotations

from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register


@register
class HuggingFace(Source):
    name = "huggingface"
    label = "Hugging Face"
    group = "dev"
    homepage = "https://huggingface.co"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        status, data = await fetcher.get_json(
            f"https://huggingface.co/api/users/{quote(target)}/overview"
        )
        if status == 200 and isinstance(data, dict) and (data.get("user") or data.get("username")):
            username = data.get("user") or data.get("username")
            return self.ok(
                target,
                Profile(
                    source=self.name,
                    username=username,
                    url=f"https://huggingface.co/{username}",
                    display_name=data.get("fullname") or username,
                    bio=data.get("bio"),
                    avatar=f"https://huggingface.co/avatars/{username}",
                    created_at=data.get("createdAt"),
                    followers=data.get("numFollowers"),
                    extra={
                        "models": data.get("numModels"),
                        "datasets": data.get("numDatasets"),
                        "spaces": data.get("numSpaces"),
                        "likes": data.get("numLikes"),
                        "following": data.get("numFollowing"),
                        "orgs": data.get("orgs"),
                    },
                ),
            )
        if status == 404:
            return self.missing(target)
        if status in (403, 429):
            return self.blocked(target, f"HTTP {status}: rate limited")
        return self.failed(target, f"HTTP {status}")
