from __future__ import annotations

from urllib.parse import quote, urlsplit

from ..http import Fetcher, FetchError
from ..models import CheckResult, Edge, Post, Profile
from ..security import is_public_host
from ..utils import is_after, strip_html
from .base import Source, register


async def _webfinger_instance(fetcher: Fetcher, user: str, domain: str) -> str | None:
    """Resolve the real ActivityPub host for user@custom-domain via WebFinger."""
    if not fetcher.settings.allow_private_targets and not is_public_host(domain, resolve=False):
        return None
    try:
        status, data = await fetcher.get_json(
            f"https://{domain}/.well-known/webfinger",
            params={"resource": f"acct:{user}@{domain}"},
        )
    except FetchError:
        return None
    if status != 200 or not isinstance(data, dict):
        return None
    for link in data.get("links") or []:
        if isinstance(link, dict) and link.get("rel") == "self" and link.get("href"):
            host = urlsplit(str(link["href"])).netloc
            if host:
                return host
    return None


@register
class Mastodon(Source):
    name = "mastodon"
    label = "Mastodon"
    group = "social"
    homepage = "https://joinmastodon.org"
    supports_posts = True

    async def _lookup(self, fetcher: Fetcher, target: str):
        found: list[tuple[str, dict]] = []
        failure: CheckResult | None = None
        instances = list(fetcher.settings.mastodon_instances)
        handle = target
        if "@" in target:
            parts = target.strip().lstrip("@").split("@")
            if len(parts) == 2:
                handle, instance = parts
                if instance not in instances:
                    resolved = await _webfinger_instance(fetcher, handle, instance)
                    if resolved and resolved not in instances:
                        instances.insert(0, resolved)
                    if instance not in instances:
                        instances.append(instance)
        for instance in instances:
            if not fetcher.settings.allow_private_targets and not is_public_host(
                instance, resolve=False
            ):
                continue
            status, data = await fetcher.get_json(
                f"https://{instance}/api/v1/accounts/lookup", params={"acct": handle}
            )
            if status == 200 and isinstance(data, dict) and data.get("id"):
                found.append((instance, data))
                continue
            if status == 404:
                continue
            failure = (
                self.blocked(target, f"HTTP {status} on {instance}")
                if status in (403, 429)
                else self.failed(target, f"HTTP {status} on {instance}")
            )
        return found, failure

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        found, failure = await self._lookup(fetcher, target)
        if found:
            instance, data = found[0]
            profile = _profile(instance, data)
            if len(found) > 1:
                profile.extra["also_found_on"] = [name for name, _ in found[1:]]
                profile.extra["ambiguous"] = True
            return self.ok(target, profile)
        if failure:
            return failure
        return self.missing(target)

    async def posts(
        self, fetcher: Fetcher, target: str, limit: int, *, since: str | None = None
    ) -> list[Post]:
        found, _ = await self._lookup(fetcher, target)
        if not found:
            return []
        instance, data = found[0]
        account_id = str(data["id"])
        posts: list[Post] = []
        max_id: str | None = None
        while len(posts) < limit:
            per_page = min(40, limit - len(posts))
            params: dict[str, object] = {"limit": per_page, "exclude_replies": "false"}
            if max_id:
                params["max_id"] = max_id
            status, statuses = await fetcher.get_json(
                f"https://{instance}/api/v1/accounts/{quote(account_id)}/statuses",
                params=params,
            )
            if status != 200 or not isinstance(statuses, list) or not statuses:
                break
            stop = False
            for item in statuses:
                if not item.get("id"):
                    continue
                created = item.get("created_at")
                if not is_after(created, since):
                    stop = True
                    break
                posts.append(
                    Post(
                        source=self.name,
                        username=target,
                        post_id=str(item["id"]),
                        url=item.get("url") or "",
                        created_at=created,
                        text=strip_html(item.get("content")),
                        metrics={
                            "reblogs": item.get("reblogs_count"),
                            "favourites": item.get("favourites_count"),
                            "replies": item.get("replies_count"),
                            "instance": instance,
                        },
                    )
                )
            if stop or len(statuses) < per_page:
                break
            max_id = str(statuses[-1].get("id") or "") or None
            if not max_id:
                break
        return posts[:limit]

    async def follows(self, fetcher: Fetcher, target: str, limit: int = 100) -> list[Edge]:
        found, _ = await self._lookup(fetcher, target)
        if not found:
            return []
        instance, data = found[0]
        edges: list[Edge] = []
        max_id: str | None = None
        while len(edges) < limit:
            per_page = min(80, limit - len(edges))
            params: dict[str, object] = {"limit": per_page}
            if max_id:
                params["max_id"] = max_id
            status, following = await fetcher.get_json(
                f"https://{instance}/api/v1/accounts/{quote(str(data['id']))}/following",
                params=params,
            )
            if status != 200 or not isinstance(following, list) or not following:
                break
            for item in following:
                tgt = item.get("acct") or item.get("username")
                if tgt:
                    edges.append(
                        Edge(
                            platform=self.name,
                            actor=target,
                            target=tgt,
                            direction="follows",
                        )
                    )
            if len(following) < per_page:
                break
            max_id = str(following[-1].get("id") or "") or None
            if not max_id:
                break
        return edges[:limit]


def _profile(instance: str, data: dict) -> Profile:
    return Profile(
        source="mastodon",
        username=data.get("username") or data.get("acct") or "",
        url=data.get("url") or f"https://{instance}/@{data.get('acct')}",
        display_name=data.get("display_name") or None,
        bio=strip_html(data.get("note")),
        avatar=data.get("avatar") or None,
        created_at=data.get("created_at"),
        followers=data.get("followers_count"),
        extra={
            "instance": instance,
            "acct": data.get("acct"),
            "id": data.get("id"),
            "bot": data.get("bot"),
            "fields": [
                {"name": f.get("name"), "value": strip_html(f.get("value"))}
                for f in data.get("fields") or []
            ],
        },
    )
