from __future__ import annotations

import asyncio
from urllib.parse import quote

from ..http import Fetcher, FetchError
from ..models import CheckResult, Edge, Post, Profile
from ..utils import is_after, ssh_fingerprint
from .base import Source, register

API = "https://api.github.com"


@register
class GitHub(Source):
    name = "github"
    label = "GitHub"
    group = "dev"
    homepage = "https://github.com"
    supports_posts = True

    def _headers(self, fetcher: Fetcher) -> dict[str, str]:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if fetcher.settings.github_token:
            headers["Authorization"] = f"Bearer {fetcher.settings.github_token}"
        return headers

    async def _keys(self, fetcher: Fetcher, target: str) -> dict[str, list]:
        """Fetch SSH and GPG keys (best-effort; never fails the profile check)."""
        headers = self._headers(fetcher)

        async def ssh() -> list[dict]:
            try:
                status, data = await fetcher.get_json(
                    f"{API}/users/{quote(target)}/keys", headers=headers
                )
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
                status, data = await fetcher.get_json(
                    f"{API}/users/{quote(target)}/gpg_keys", headers=headers
                )
            except FetchError:
                return []
            if status != 200 or not isinstance(data, list):
                return []
            return [
                {
                    "id": item.get("id"),
                    "key_id": item.get("key_id"),
                    "emails": item.get("emails") or [],
                }
                for item in data
                if item.get("key_id") or item.get("emails")
            ]

        ssh_keys, gpg_keys = await asyncio.gather(ssh(), gpg())
        return {"ssh_keys": ssh_keys, "gpg_keys": gpg_keys}

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        status, data = await fetcher.get_json(
            f"{API}/users/{quote(target)}", headers=self._headers(fetcher)
        )
        if status == 200 and isinstance(data, dict) and data.get("login"):
            login = data["login"]
            key_material = await self._keys(fetcher, login)
            extra = {
                "id": data.get("id"),
                "public_repos": data.get("public_repos"),
                "company": data.get("company"),
                "location": data.get("location"),
                "twitter_username": data.get("twitter_username"),
                "hireable": data.get("hireable"),
                "email": data.get("email"),
                **key_material,
            }
            return self.ok(
                target,
                Profile(
                    source=self.name,
                    username=login,
                    url=data.get("html_url") or f"https://github.com/{login}",
                    display_name=data.get("name"),
                    bio=data.get("bio"),
                    avatar=data.get("avatar_url"),
                    website=data.get("blog") or None,
                    created_at=data.get("created_at"),
                    followers=data.get("followers"),
                    extra=extra,
                ),
            )
        if status == 404:
            return self.missing(target)
        if status in (403, 429):
            hint = (
                "set GITHUB_TOKEN for a higher limit" if not fetcher.settings.github_token else ""
            )
            return self.blocked(
                target, f"HTTP {status}: rate limited{' (' + hint + ')' if hint else ''}"
            )
        return self.failed(target, f"HTTP {status}")

    async def posts(
        self, fetcher: Fetcher, target: str, limit: int, *, since: str | None = None
    ) -> list[Post]:
        posts: list[Post] = []
        page = 1
        while len(posts) < limit and page <= 10:
            per_page = min(100, limit - len(posts))
            status, data = await fetcher.get_json(
                f"{API}/users/{quote(target)}/events/public",
                params={"per_page": per_page, "page": page},
                headers=self._headers(fetcher),
            )
            if status != 200 or not isinstance(data, list) or not data:
                break
            for event in data:
                created = event.get("created_at")
                if not is_after(created, since):
                    page = 999
                    break
                repo = (event.get("repo") or {}).get("name") or ""
                event_type = event.get("type") or "Event"
                commits = (event.get("payload") or {}).get("commits") or []
                posts.append(
                    Post(
                        source=self.name,
                        username=target,
                        post_id=str(event.get("id") or f"{event_type}-{created}"),
                        url=f"https://github.com/{repo}"
                        if repo
                        else f"https://github.com/{target}",
                        created_at=created,
                        text=f"{event_type} {repo}".strip(),
                        metrics={"type": event_type, "commits": len(commits)},
                    )
                )
            if len(data) < per_page:
                break
            page += 1
        if len(posts) < limit:
            try:
                status, gists = await fetcher.get_json(
                    f"{API}/users/{quote(target)}/gists",
                    params={"per_page": min(100, limit - len(posts))},
                    headers=self._headers(fetcher),
                )
            except FetchError:
                status, gists = 0, None
            if status == 200 and isinstance(gists, list):
                for gist in gists:
                    created = gist.get("created_at")
                    if not is_after(created, since):
                        continue
                    files = list((gist.get("files") or {}).keys())
                    posts.append(
                        Post(
                            source=self.name,
                            username=target,
                            post_id=f"gist:{gist.get('id')}",
                            url=gist.get("html_url") or f"https://gist.github.com/{gist.get('id')}",
                            created_at=created,
                            text=f"gist: {gist.get('description') or ', '.join(files[:5])}".strip(),
                            metrics={"type": "gist", "files": len(files)},
                        )
                    )
        return posts[:limit]

    async def follows(self, fetcher: Fetcher, target: str, limit: int = 100) -> list[Edge]:
        edges: list[Edge] = []
        page = 1
        while len(edges) < limit and page <= 10:
            per_page = min(100, limit - len(edges))
            status, data = await fetcher.get_json(
                f"{API}/users/{quote(target)}/following",
                params={"per_page": per_page, "page": page},
                headers=self._headers(fetcher),
            )
            if status != 200 or not isinstance(data, list) or not data:
                break
            for item in data:
                login = item.get("login")
                if login:
                    edges.append(
                        Edge(
                            platform=self.name,
                            actor=target,
                            target=login,
                            direction="follows",
                        )
                    )
            if len(data) < per_page:
                break
            page += 1
        return edges[:limit]
