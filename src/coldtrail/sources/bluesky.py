from __future__ import annotations

from urllib.parse import quote

from ..http import Fetcher, FetchError
from ..models import CheckResult, Edge, Post, Profile
from ..utils import is_after
from .base import Source, register

PUBLIC_API = "https://public.api.bsky.app/xrpc"
PLC_DIRECTORY = "https://plc.directory"


async def _plc_history(fetcher: Fetcher, did: str) -> dict:
    """Resolve DID document + audit log history (handle changes, PDS host)."""
    try:
        status, data = await fetcher.get_json(f"{PLC_DIRECTORY}/{quote(did)}/log/audit")
    except FetchError:
        return {}
    if status != 200 or not isinstance(data, list):
        return {}
    handles: list[str] = []
    pds: str | None = None
    for entry in data:
        operation = entry.get("operation") or {}
        handle = operation.get("handle")
        if handle and handle not in handles:
            handles.append(handle)
        for aka in operation.get("alsoKnownAs") or []:
            if isinstance(aka, str) and aka.startswith("at://"):
                alias = aka.removeprefix("at://")
                if alias not in handles:
                    handles.append(alias)
        if operation.get("service"):
            pds = operation["service"]
    return {"handle_history": handles, "pds": pds, "plc_entries": len(data)}


@register
class Bluesky(Source):
    name = "bluesky"
    label = "Bluesky"
    group = "social"
    homepage = "https://bsky.app"
    supports_posts = True

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        status, data = await fetcher.get_json(
            f"{PUBLIC_API}/app.bsky.actor.getProfile", params={"actor": target}
        )
        if status == 200 and isinstance(data, dict) and data.get("did"):
            handle = data.get("handle") or target
            extra = {
                "did": data.get("did"),
                "follows": data.get("followsCount"),
                "posts": data.get("postsCount"),
                "labels": data.get("labels"),
            }
            if str(data.get("did", "")).startswith("did:plc:"):
                extra.update(await _plc_history(fetcher, str(data["did"])))
            return self.ok(
                target,
                Profile(
                    source=self.name,
                    username=handle,
                    url=f"https://bsky.app/profile/{handle}",
                    display_name=data.get("displayName") or None,
                    bio=data.get("description"),
                    avatar=data.get("avatar"),
                    created_at=data.get("createdAt"),
                    followers=data.get("followersCount"),
                    extra=extra,
                ),
            )
        if status in (400, 404):
            return self.missing(target)
        if status in (403, 429):
            return self.blocked(target, f"HTTP {status}: rate limited")
        return self.failed(target, f"HTTP {status}")

    async def posts(
        self, fetcher: Fetcher, target: str, limit: int, *, since: str | None = None
    ) -> list[Post]:
        posts: list[Post] = []
        cursor: str | None = None
        while len(posts) < limit:
            params: dict[str, object] = {
                "actor": target,
                "limit": min(100, limit - len(posts)),
            }
            if cursor:
                params["cursor"] = cursor
            status, payload = await fetcher.get_json(
                f"{PUBLIC_API}/app.bsky.feed.getAuthorFeed", params=params
            )
            if status != 200 or not isinstance(payload, dict):
                break
            feed = payload.get("feed") or []
            if not feed:
                break
            stop = False
            for item in feed:
                post = item.get("post") or {}
                uri = post.get("uri") or ""
                record = post.get("record") or {}
                rkey = uri.rsplit("/", 1)[-1] if uri else ""
                created = record.get("createdAt")
                if not rkey:
                    continue
                if not is_after(created, since):
                    stop = True
                    break
                author = (post.get("author") or {}).get("handle") or target
                posts.append(
                    Post(
                        source=self.name,
                        username=author,
                        post_id=rkey,
                        url=f"https://bsky.app/profile/{quote(author)}/post/{rkey}",
                        created_at=created,
                        text=record.get("text"),
                        metrics={
                            "likes": post.get("likeCount"),
                            "reposts": post.get("repostCount"),
                            "replies": post.get("replyCount"),
                            "repost": bool(item.get("reason")),
                        },
                    )
                )
                if len(posts) >= limit:
                    break
            if stop or len(posts) >= limit:
                break
            cursor = payload.get("cursor")
            if not cursor:
                break
        return posts[:limit]

    async def follows(self, fetcher: Fetcher, target: str, limit: int = 100) -> list[Edge]:
        status, data = await fetcher.get_json(
            f"{PUBLIC_API}/app.bsky.actor.getProfile", params={"actor": target}
        )
        if status != 200 or not isinstance(data, dict) or not data.get("did"):
            return []
        edges: list[Edge] = []
        cursor: str | None = None
        while len(edges) < limit:
            params: dict[str, object] = {
                "actor": data["did"],
                "limit": min(100, limit - len(edges)),
            }
            if cursor:
                params["cursor"] = cursor
            status, payload = await fetcher.get_json(
                f"{PUBLIC_API}/app.bsky.graph.getFollows", params=params
            )
            if status != 200 or not isinstance(payload, dict):
                break
            batch = payload.get("follows") or []
            if not batch:
                break
            for item in batch:
                handle = item.get("handle") or item.get("did") or ""
                if handle:
                    edges.append(
                        Edge(
                            platform=self.name,
                            actor=target,
                            target=handle,
                            direction="follows",
                        )
                    )
            cursor = payload.get("cursor")
            if not cursor or len(batch) < params["limit"]:
                break
        return edges[:limit]
