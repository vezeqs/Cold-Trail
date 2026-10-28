from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Post, Profile
from ..utils import is_after, strip_html
from .base import Source, register

PROFILE_API = "https://hacker-news.firebaseio.com/v0/user"
SEARCH_API = "https://hn.algolia.com/api/v1/search_by_date"


@register
class HackerNews(Source):
    name = "hackernews"
    label = "Hacker News"
    group = "social"
    homepage = "https://news.ycombinator.com"
    supports_posts = True

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        status, data = await fetcher.get_json(f"{PROFILE_API}/{quote(target)}.json")
        if status == 200 and isinstance(data, dict) and data.get("id"):
            created = data.get("created")
            return self.ok(
                target,
                Profile(
                    source=self.name,
                    username=data["id"],
                    url=f"https://news.ycombinator.com/user?id={quote(data['id'])}",
                    bio=strip_html(data.get("about")),
                    created_at=(
                        datetime.fromtimestamp(created, UTC).isoformat(timespec="seconds")
                        if isinstance(created, (int, float))
                        else None
                    ),
                    extra={
                        "karma": data.get("karma"),
                        "submitted": len(data.get("submitted") or []),
                    },
                ),
            )
        if status == 200:
            return self.missing(target)
        if status in (403, 429):
            return self.blocked(target, f"HTTP {status}: rate limited")
        return self.failed(target, f"HTTP {status}")

    async def posts(
        self, fetcher: Fetcher, target: str, limit: int, *, since: str | None = None
    ) -> list[Post]:
        posts: list[Post] = []
        page = 0
        while len(posts) < limit and page < 10:
            per_page = min(100, limit - len(posts))
            status, data = await fetcher.get_json(
                SEARCH_API,
                params={
                    "tags": f"author_{target}",
                    "hitsPerPage": per_page,
                    "page": page,
                },
            )
            if status != 200 or not isinstance(data, dict):
                break
            hits = data.get("hits") or []
            if not hits:
                break
            for hit in hits:
                created = hit.get("created_at")
                if not is_after(created, since):
                    page = 999
                    break
                object_id = str(hit.get("objectID") or "")
                if not object_id:
                    continue
                posts.append(
                    Post(
                        source=self.name,
                        username=target,
                        post_id=object_id,
                        url=f"https://news.ycombinator.com/item?id={object_id}",
                        created_at=created,
                        text=strip_html(hit.get("comment_text") or hit.get("title")),
                        metrics={
                            "points": hit.get("points"),
                            "comments": hit.get("num_comments"),
                            "story": hit.get("story_title"),
                        },
                    )
                )
            if len(hits) < per_page:
                break
            page += 1
        return posts[:limit]
