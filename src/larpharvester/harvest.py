from __future__ import annotations

from .analysis import enrich_profile
from .avatars import hash_avatars
from .config import Settings
from .http import BlockedError, Fetcher
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
) -> tuple[CheckResult, list[Post]]:
    source: Source = SOURCES[source_name]
    username = username.strip().lstrip("@")
    async with Fetcher(settings, store=store, run_id=run_id) as fetcher:
        result = await _check(source, fetcher, username)
        posts: list[Post] = []
        if result.status == "found":
            await _enrich_profile(fetcher, result)
            try:
                posts = await source.posts(fetcher, username, limit, since=since)
            except BlockedError:
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
) -> tuple[CheckResult, list[Edge]]:
    source: Source = SOURCES[source_name]
    username = username.strip().lstrip("@")
    async with Fetcher(settings, store=store, run_id=run_id) as fetcher:
        result = await _check(source, fetcher, username)
        edges: list[Edge] = []
        if result.status == "found":
            await _enrich_profile(fetcher, result)
            try:
                edges = await source.follows(fetcher, username, limit)
            except BlockedError:
                edges = []
    return result, edges
