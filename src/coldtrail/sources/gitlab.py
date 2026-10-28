from __future__ import annotations

import asyncio
from urllib.parse import quote

from ..http import Fetcher, FetchError
from ..models import CheckResult, Post, Profile
from ..utils import is_after, ssh_fingerprint
from .base import Source, register

API = "https://gitlab.com/api/v4"


def _select_user(users: list, target: str) -> dict | None:
    """Pick the exact case-insensitive username match, else None."""
    for user in users:
        if str(user.get("username", "")).casefold() == target.casefold():
            return user
    return None


async def _keys(fetcher: Fetcher, user_id: object) -> dict[str, list]:
    """Fetch SSH and GPG keys for a GitLab user (best-effort)."""

    async def ssh() -> list[dict]:
        try:
            status, data = await fetcher.get_json(f"{API}/users/{quote(str(user_id))}/keys")
        except FetchError:
            return []
        if status != 200 or not isinstance(data, list):
            return []
        out = []
        for item in data:
            fingerprint = ssh_fingerprint(item.get("key"))
            if fingerprint:
                out.append({"id": item.get("id"), "fingerprint": fingerprint})
        return out

    async def gpg() -> list[dict]:
        try:
            status, data = await fetcher.get_json(f"{API}/users/{quote(str(user_id))}/gpg_keys")
        except FetchError:
            return []
        if status != 200 or not isinstance(data, list):
            return []
        return [
            {"id": item.get("id"), "key_id": item.get("key_id"), "emails": item.get("emails") or []}
            for item in data
            if item.get("key_id") or item.get("emails")
        ]

    ssh_keys, gpg_keys = await asyncio.gather(ssh(), gpg())
    return {"ssh_keys": ssh_keys, "gpg_keys": gpg_keys}


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
            user = _select_user(data, target) or data[0]
            key_material = await _keys(fetcher, user.get("id"))
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
                        **key_material,
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
        user = _select_user(data, target)
        if user is None:
            return []
        user_id = user.get("id")
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
