from __future__ import annotations

from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Post, Profile
from ..utils import is_after
from .base import Source, register

API = "https://gitlab.com/api/v4"


@register
class GitLab(Source):
    name = "gitlab"
    label = "GitLab"
    group = "dev"
    homepage = "https://gitlab.com"
    supports_posts = True

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        status, data = await fetcher.get_json(f"{API}/users", params={"username": target})
        if status == 200 and isinstance(data, list) and data:
            user = next(
                (u for u in data if str(u.get("username", "")).casefold() == target.casefold()),
                data[0],
            )
            return self.ok(
                target,
                Profile(
                    source=self.name,
                    username=user.get("username") or target,
                    url=user.get("web_url") or f"https://gitlab.com/{target}",
                    display_name=user.get("name"),
                    bio=user.get("bio"),
                    avatar=user.get("avatar_url"),
                    website=user.get("website_url"),
                    created_at=user.get("created_at"),
                    extra={
                        "id": user.get("id"),
                        "state": user.get("state"),
                        "public_email": user.get("public_email"),
                        "location": user.get("location"),
                        "organization": user.get("organization"),
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
        status, data = await fetcher.get_json(f"{API}/users", params={"username": target})
        if status != 200 or not isinstance(data, list) or not data:
            return []
        user_id = data[0].get("id")
        if not user_id:
            return []
        posts: list[Post] = []
        page = 1
        while len(posts) < limit and page <= 5:
            per_page = min(100, limit - len(posts))
            status, events = await fetcher.get_json(
                f"{API}/users/{quote(str(user_id))}/events",
                params={"per_page": per_page, "page": page},
            )
            if status != 200 or not isinstance(events, list) or not events:
                break
            for event in events:
                created = event.get("created_at")
                if not is_after(created, since):
                    return posts[:limit]
                project = event.get("project_id")
                action = event.get("action_name") or "event"
                posts.append(
                    Post(
                        source=self.name,
                        username=target,
                        post_id=str(event.get("id") or f"{action}-{created}"),
                        url=f"https://gitlab.com/projects/{project}"
                        if project
                        else f"https://gitlab.com/{target}",
                        created_at=created,
                        text=f"{action} {event.get('target_title') or ''}".strip(),
                        metrics={"project_id": project},
                    )
                )
            if len(events) < per_page:
                break
            page += 1
        return posts[:limit]
