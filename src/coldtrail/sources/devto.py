from __future__ import annotations

from ..http import Fetcher
from ..models import CheckResult, Post, Profile
from ..utils import is_after
from .base import Source, register

API = "https://dev.to/api"


@register
class DevTo(Source):
    name = "devto"
    label = "DEV Community"
    group = "dev"
    homepage = "https://dev.to"
    supports_posts = True

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        status, data = await fetcher.get_json(f"{API}/users/by_username", params={"url": target})
        if status == 200 and isinstance(data, dict) and data.get("username"):
            return self.ok(
                target,
                Profile(
                    source=self.name,
                    username=data["username"],
                    url=f"https://dev.to/{data['username']}",
                    display_name=data.get("name"),
                    bio=data.get("summary"),
                    avatar=data.get("profile_image"),
                    website=data.get("website_url"),
                    created_at=data.get("joined_at"),
                    extra={
                        "id": data.get("id"),
                        "location": data.get("location"),
                        "github_username": data.get("github_username"),
                        "twitter_username": data.get("twitter_username"),
                    },
                ),
            )
        if status == 404:
            return self.missing(target)
        if status in (403, 429):
            return self.blocked(target, f"HTTP {status}: rate limited")
        return self.failed(target, f"HTTP {status}")

    async def posts(
        self, fetcher: Fetcher, target: str, limit: int, *, since: str | None = None
    ) -> list[Post]:
        posts: list[Post] = []
        page = 1
        while len(posts) < limit and page <= 10:
            per_page = min(100, limit - len(posts))
            status, data = await fetcher.get_json(
                f"{API}/articles",
                params={"username": target, "per_page": per_page, "page": page},
            )
            if status != 200 or not isinstance(data, list) or not data:
                break
            for article in data:
                if not article.get("id"):
                    continue
                created = article.get("published_at") or article.get("created_at")
                if not is_after(created, since):
                    page = 999
                    break
                posts.append(
                    Post(
                        source=self.name,
                        username=target,
                        post_id=str(article["id"]),
                        url=article.get("url") or "",
                        created_at=created,
                        text=article.get("title"),
                        metrics={
                            "reactions": article.get("positive_reactions_count"),
                            "comments": article.get("comments_count"),
                            "tags": article.get("tag_list"),
                        },
                    )
                )
            if len(data) < per_page:
                break
            page += 1
        return posts[:limit]
