from __future__ import annotations

from .analysis import enrich_profile
from .avatars import hash_avatars
from .config import Settings
from .http import BlockedError, Fetcher, FetchError, shared_fetcher
from .models import CheckResult, Edge, Post
from .pivot import _check, profile_entities
from .sources import SOURCES, Source


async def _enrich_profile(fetcher: Fetcher, result: CheckResult) -> None:
    profile = result.profile
    if profile is None:
        return
    enrich_profile(profile)
    ents = profile_entities(profile)
    if ents:
        profile.extra["extracted_entities"] = [{"kind": e.kind, "value": e.value} for e in ents]
    if fetcher.settings.avatar_hash:
        await hash_avatars(fetcher, [profile])


async def harvest(
    source_name: str,
    username: str,
    *,
    settings: Settings,
    limit: int = 50,
    since: str | None = None,
    store=None,
    run_id: int | None = None,
    fetcher: Fetcher | None = None,
) -> tuple[CheckResult, list[Post]]:
    source: Source = SOURCES[source_name]
    username = username.strip().lstrip("@")
    async with shared_fetcher(settings, store, fetcher, run_id=run_id) as active_fetcher:
        result = await _check(source, active_fetcher, username)
        posts: list[Post] = []
        if result.status == "found":
            await _enrich_profile(active_fetcher, result)
            try:
                posts = await source.posts(active_fetcher, username, limit, since=since)
            except (BlockedError, FetchError):
                posts = []
    return result, posts


async def collect_follows(
    source_name: str,
    username: str,
    *,
    settings: Settings,
    limit: int = 100,
    store=None,
    run_id: int | None = None,
    fetcher: Fetcher | None = None,
) -> tuple[CheckResult, list[Edge]]:
    source: Source = SOURCES[source_name]
    username = username.strip().lstrip("@")
    async with shared_fetcher(settings, store, fetcher, run_id=run_id) as active_fetcher:
        result = await _check(source, active_fetcher, username)
        edges: list[Edge] = []
        if result.status == "found":
            await _enrich_profile(active_fetcher, result)
            try:
                edges = await source.follows(active_fetcher, username, limit)
            except (BlockedError, FetchError):
                edges = []
    return result, edges
