from __future__ import annotations

import asyncio
from dataclasses import replace

from .alerts import Alerter, dispatch
from .analysis import entities_from_posts
from .config import Settings
from .harvest import harvest
from .http import shared_fetcher
from .models import ProfileChange
from .pivot import entities_for_profiles, pivot
from .sources import SOURCES
from .store import Store


def _change_key(change: ProfileChange) -> tuple[str, str, str, str | None]:
    return (change.source, change.username.casefold(), change.field, change.new_value)


async def watch(
    target: str,
    *,
    settings: Settings,
    store: Store,
    sources: list[str] | None = None,
    interval: int = 3600,
    iterations: int = 0,
    limit: int = 20,
    expand: bool = False,
    alerters: list[Alerter] | None = None,
    on_cycle=None,
) -> int:
    """Re-pivot and re-harvest on an interval, alerting on new posts or profile edits.

    A single Fetcher is shared across the whole cycle (pivot + every harvest), so
    per-run request budgets, host pacing, and circuit state apply globally. Profile
    changes already alerted on are not re-dispatched on later cycles.
    """
    alerters = alerters or []
    cycle = 0
    watch_settings = replace(settings, cache_ttl=0, negative_cache_ttl=0)
    notified_changes: set[tuple[str, str, str, str | None]] = set()
    while True:
        cycle += 1
        async with shared_fetcher(watch_settings, store) as fetcher:
            report = await pivot(
                target,
                settings=watch_settings,
                sources=sources,
                expand=expand,
                store=store,
                fetcher=fetcher,
            )
            run_id = store.start_run("watch", target)
            try:
                store.save_checks(run_id, report.results)
                store.save_profiles(run_id, report.profiles)
                store.save_links(run_id, report.links)
                store.save_clusters(run_id, report.clusters)
                store.save_entities(run_id, entities_for_profiles(report.profiles))

                new_posts = []
                for profile in report.profiles:
                    source = SOURCES.get(profile.source)
                    if source is None or not source.supports_posts:
                        continue
                    existing = {
                        post["post_id"]
                        for post in store.posts(
                            username=profile.username, source=source.name, limit=None
                        )
                    }
                    result, posts = await harvest(
                        source.name,
                        profile.username,
                        settings=watch_settings,
                        limit=limit,
                        store=store,
                        run_id=run_id,
                        fetcher=fetcher,
                    )
                    if result.status != "found":
                        continue
                    store.save_posts(run_id, posts)
                    store.save_entities(run_id, entities_from_posts(posts))
                    if posts:
                        oldest = min(
                            (post.created_at for post in posts if post.created_at), default=None
                        )
                        store.mark_missing_posts(
                            source.name,
                            profile.username,
                            {post.post_id for post in posts},
                            run_id,
                            since=oldest,
                        )
                    new_posts.extend(post for post in posts if post.post_id not in existing)

                changes = store.record_profile_history(run_id, report.profiles)
                store.finish_run(run_id)
            except Exception:
                store.finish_run(run_id, "error")
                raise

        fresh_changes = [
            change for change in changes if _change_key(change) not in notified_changes
        ]
        notified_changes.update(_change_key(change) for change in fresh_changes)
        if len(notified_changes) > 10_000:
            # Long-running watches must not grow without bound. Dropping the
            # de-duplication memory can re-alert an old change once, which is
            # safer than an unbounded process.
            notified_changes.clear()

        if on_cycle:
            on_cycle(cycle, report, new_posts, changes)
        if new_posts or fresh_changes:
            await dispatch(alerters, *_message(target, new_posts, fresh_changes))

        if iterations and cycle >= iterations:
            return cycle
        await asyncio.sleep(interval)


def _message(target: str, new_posts: list, changes: list[ProfileChange]) -> tuple[str, str]:
    title = f"ColdTrail: {len(new_posts)} new posts / {len(changes)} changes for {target}"
    lines = []
    for post in new_posts[:5]:
        text = " ".join((post.text or "").split())[:160]
        lines.append(f"[{post.source}] {post.created_at or ''} {text} {post.url}")
    for change in changes[:5]:
        lines.append(
            f"[{change.source}:{change.username}] {change.field}: "
            f"{change.old_value!r} -> {change.new_value!r}"
        )
    return title, "\n".join(lines) or "no details"
