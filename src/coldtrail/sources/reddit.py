from __future__ import annotations

from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Post, Profile
from ..utils import is_after, strip_html
from .base import Source, register

BASE = "https://www.reddit.com"


@register
class Reddit(Source):
    name = "reddit"
    label = "Reddit"
    group = "social"
    homepage = "https://reddit.com"
    supports_posts = True

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        status, data = await fetcher.get_json(f"{BASE}/user/{quote(target)}/about.json")
        if status == 200 and isinstance(data, dict):
            user = data.get("data") or {}
            if user.get("name"):
                subreddit = user.get("subreddit") or {}
                bio = subreddit.get("public_description") or subreddit.get("title")
                return self.ok(
                    target,
                    Profile(
                        source=self.name,
                        username=user["name"],
                        url=f"{BASE}/user/{user['name']}",
                        display_name=subreddit.get("title") or None,
                        bio=strip_html(bio),
                        avatar=user.get("icon_img") or None,
                        created_at=_epoch(user.get("created_utc")),
                        extra={
                            "id": user.get("id"),
                            "total_karma": user.get("total_karma"),
                            "link_karma": user.get("link_karma"),
                            "comment_karma": user.get("comment_karma"),
                            "is_mod": user.get("is_mod"),
                            "verified": user.get("verified"),
                            "has_verified_email": user.get("has_verified_email"),
                        },
                    ),
                )
            return self.missing(target)
        if status == 404:
            return self.missing(target)
        if status in (403, 429):
            return self.blocked(
                target, f"HTTP {status}: Reddit is throttling or blocking this client"
            )
        return self.failed(target, f"HTTP {status}")

    async def posts(
        self, fetcher: Fetcher, target: str, limit: int, *, since: str | None = None
    ) -> list[Post]:
        posts: list[Post] = []
        after: str | None = None
        while len(posts) < limit:
            per_page = min(100, limit - len(posts))
            params: dict[str, object] = {"limit": per_page, "sort": "new"}
            if after:
                params["after"] = after
            status, data = await fetcher.get_json(
                f"{BASE}/user/{quote(target)}/submitted.json", params=params
            )
            if status != 200 or not isinstance(data, dict):
                break
            listing = data.get("data") or {}
            children = listing.get("children") or []
            if not children:
                break
            stop = False
            for child in children:
                item = child.get("data") or {}
                created = _epoch(item.get("created_utc"))
                if not item.get("id"):
                    continue
                if not is_after(created, since):
                    stop = True
                    break
                permalink = item.get("permalink") or ""
                posts.append(
                    Post(
                        source=self.name,
                        username=item.get("author") or target,
                        post_id=item["id"],
                        url=f"{BASE}{permalink}",
                        created_at=created,
                        text=item.get("title") or strip_html(item.get("selftext")),
                        metrics={
                            "score": item.get("score"),
                            "comments": item.get("num_comments"),
                            "subreddit": item.get("subreddit"),
                            "type": item.get("post_hint"),
                        },
                    )
                )
            if stop:
                break
            after = listing.get("after")
            if not after or len(children) < per_page:
                break
        return posts[:limit]


def _epoch(value: object) -> str | None:
    from datetime import UTC, datetime

    if not isinstance(value, (int, float)):
        return None
    return datetime.fromtimestamp(value, UTC).isoformat(timespec="seconds")
