from __future__ import annotations

import asyncio
import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Annotated

import typer

from ..alerts import build_alerters
from ..analysis import entities_from_posts
from ..config import Settings
from ..correlate import recluster_rows
from ..harvest import collect_follows
from ..harvest import harvest as run_harvest
from ..http import Fetcher
from ..models import PivotReport
from ..pivot import entities_for_profiles, persist_pivot
from ..pivot import pivot as run_pivot
from ..sources import SOURCES
from ..store import Store
from ..utils import epoch_seconds
from ..watch import watch as run_watch
from ._app import (
    STATUS_STYLE,
    _exit_for_found,
    _print_json,
    _render_edges,
    _render_links,
    _render_pivot,
    _render_posts,
    _render_profiles,
    _settings,
    app,
    console,
)

WEB_CORPUS_COUNT = sum(1 for source in SOURCES.values() if source.group == "web")


@app.command(rich_help_panel="Collect")
def pivot(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Username, handle, or email")],
    source: Annotated[
        list[str] | None,
        typer.Option("-s", "--source", help="Sources or groups (repeatable)"),
    ] = None,
    group: Annotated[
        list[str] | None, typer.Option("-g", "--group", help="Source groups (repeatable)")
    ] = None,
    expand: Annotated[
        bool, typer.Option("--expand", help="Cross-kind expansion (email <-> usernames)")
    ] = False,
    max_expand: Annotated[int, typer.Option("--max-expand", min=0, help="0 = unlimited")] = 5,
    depth: Annotated[
        int, typer.Option("--depth", min=1, max=5, help="Multi-hop expansion depth")
    ] = 1,
    variants: Annotated[
        bool, typer.Option("--variants", help="Probe generated handle/email variants")
    ] = False,
    web: Annotated[
        bool,
        typer.Option("--web", help=f"Include the {WEB_CORPUS_COUNT}-site web corpus"),
    ] = False,
    all_sources: Annotated[bool, typer.Option("--all", help="Every registered source")] = False,
    avatar_hash: Annotated[
        bool | None,
        typer.Option(
            "--avatar-hash/--no-avatar-hash",
            help="Download avatars for perceptual hashing (privacy: off by default)",
        ),
    ] = None,
    all_checks: Annotated[
        bool, typer.Option("--all-checks", help="Show every check, not just found profiles")
    ] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
    jsonl: Annotated[bool, typer.Option("--jsonl")] = False,
    save: Annotated[bool, typer.Option("--save/--no-save")] = True,
) -> None:
    """Check an identity across sources and correlate the hits."""
    settings = _settings(ctx)
    names: list[str] | None = list(source or []) + list(group or [])
    if all_sources:
        names = list(names) + ["all"]
    if web:
        names = list(names) + ["web"] if names else None
    if not names and not web:
        names = None

    if not save:
        settings.cache_ttl = 0
        settings.negative_cache_ttl = 0
        settings.keep_raw = False

    progress = {"checked": 0, "found": 0}

    def on_result(result) -> None:
        progress["checked"] += 1
        if result.status == "found":
            progress["found"] += 1

    try:
        store = Store(settings.db_path) if save else None
        try:
            if json_out or jsonl:
                report = asyncio.run(
                    run_pivot(
                        target,
                        settings=settings,
                        sources=names,
                        expand=expand,
                        max_expand=max_expand,
                        depth=depth,
                        use_variants=variants,
                        include_web=web,
                        avatar_hash=avatar_hash,
                        use_cache=save and settings.negative_cache_ttl > 0,
                        store=store,
                        on_result=on_result,
                    )
                )
            else:
                with console.status(f"probing {target}…", spinner="dots") as status:

                    def report_progress(result) -> None:
                        on_result(result)
                        status.update(
                            f"probing {target}… {progress['checked']} checked, "
                            f"[green]{progress['found']} found[/green]"
                        )

                    report = asyncio.run(
                        run_pivot(
                            target,
                            settings=settings,
                            sources=names,
                            expand=expand,
                            max_expand=max_expand,
                            depth=depth,
                            use_variants=variants,
                            include_web=web,
                            avatar_hash=avatar_hash,
                            use_cache=save and settings.negative_cache_ttl > 0,
                            store=store,
                            on_result=report_progress,
                        )
                    )
        finally:
            if store is not None:
                store.close()
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    if save:
        _save_pivot(settings, report)

    if json_out:
        _print_json(_report_payload(report))
        _exit_for_found(report)
        return
    if jsonl:
        _pivot_jsonl(report)
        _exit_for_found(report)
        return

    _render_pivot(report, show_all=all_checks)
    if report.run_id:
        console.print(f"[dim]saved as run #{report.run_id} in {settings.db_path}[/dim]")
    _exit_for_found(report)


def _report_payload(report: PivotReport) -> dict:
    payload = asdict(report)
    payload["profiles"] = [asdict(profile) for profile in report.profiles]
    return payload


def _pivot_jsonl(report: PivotReport) -> None:
    for result in report.results:
        typer.echo(json.dumps({"type": "check", **asdict(result)}, default=str))
    for profile in report.profiles:
        typer.echo(json.dumps({"type": "profile", **asdict(profile)}, default=str))
    for entity in entities_for_profiles(report.profiles):
        typer.echo(json.dumps({"type": "entity", **asdict(entity)}, default=str))
    for link in report.links:
        typer.echo(json.dumps({"type": "link", **asdict(link)}, default=str))
    for cluster in report.clusters:
        typer.echo(json.dumps({"type": "cluster", **asdict(cluster)}, default=str))


def _save_pivot(settings: Settings, report: PivotReport) -> None:
    with Store(settings.db_path) as store:
        persist_pivot(store, report)


@app.command(rich_help_panel="Collect")
def batch(
    ctx: typer.Context,
    targets: Annotated[
        list[str] | None, typer.Argument(help="Usernames or emails to pivot")
    ] = None,
    file: Annotated[
        Path | None, typer.Option("-f", "--file", help="Newline-delimited target file")
    ] = None,
    source: Annotated[
        list[str] | None, typer.Option("-s", "--source", help="Sources or groups")
    ] = None,
    expand: Annotated[bool, typer.Option("--expand")] = False,
    depth: Annotated[int, typer.Option("--depth", min=1, max=5)] = 1,
    web: Annotated[bool, typer.Option("--web")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
    save: Annotated[bool, typer.Option("--save/--no-save")] = True,
    jobs: Annotated[
        int,
        typer.Option("-j", "--jobs", min=1, max=32, help="Targets to pivot concurrently"),
    ] = 1,
) -> None:
    """Pivot multiple targets, optionally concurrently, and correlate each."""
    settings = _settings(ctx)
    items: list[str] = list(targets or [])
    if file is not None:
        for line in file.read_text(encoding="utf-8").splitlines():
            cleaned = line.strip()
            if cleaned and not cleaned.startswith("#"):
                items.append(cleaned)
    if not items:
        raise typer.BadParameter("provide at least one target argument or --file")

    names = list(source) if source else None
    store = Store(settings.db_path) if save else None

    async def run_batch() -> list[dict]:
        semaphore = asyncio.Semaphore(jobs)
        reports: list[dict | None] = [None] * len(items)

        async def one(index: int, target: str) -> None:
            async with semaphore:
                report = await run_pivot(
                    target,
                    settings=settings,
                    sources=names,
                    expand=expand,
                    depth=depth,
                    include_web=web,
                    use_cache=save and settings.negative_cache_ttl > 0,
                    store=store,
                    fetcher=fetcher,
                )
            if store is not None:
                persist_pivot(store, report)
            reports[index] = _report_payload(report)
            if not json_out:
                _render_pivot(report)

        async with Fetcher(settings) as fetcher:
            results = await asyncio.gather(
                *(one(index, target) for index, target in enumerate(items)),
                return_exceptions=True,
            )
        for result in results:
            if isinstance(result, ValueError):
                raise typer.BadParameter(str(result)) from result
            if isinstance(result, BaseException):
                raise result
        return [report for report in reports if report is not None]

    try:
        reports = asyncio.run(run_batch())
    finally:
        if store is not None:
            store.close()

    if json_out:
        _print_json(reports)


@app.command(rich_help_panel="Collect")
def recluster(
    ctx: typer.Context,
    run_id: Annotated[int | None, typer.Option("--run", help="Specific run (omit for all)")] = None,
    threshold: Annotated[float, typer.Option("--threshold", min=0.1, max=1.0)] = 0.5,
    save: Annotated[
        bool, typer.Option("--save/--no-save", help="Persist links/clusters back to the run")
    ] = True,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Re-run correlation and clustering over stored profiles (single run or cross-run)."""
    settings = _settings(ctx)
    with Store(settings.db_path) as store:
        if run_id is not None and store.run(run_id) is None:
            typer.echo(f"run {run_id} not found", err=True)
            raise typer.Exit(code=1)
        rows = store.profiles(run_id=run_id, limit=None)
        links, clusters = recluster_rows(rows, threshold=threshold)
        if save and run_id is not None:
            store.replace_links_and_clusters(run_id, links, clusters)
    if json_out:
        _print_json(
            {
                "profiles": len(rows),
                "saved": bool(save and run_id is not None),
                "links": [asdict(link) for link in links],
                "clusters": [asdict(c) for c in clusters],
            }
        )
        return
    saved_note = f" · saved to run #{run_id}" if save and run_id is not None else ""
    console.print(
        f"[bold]Recluster[/bold] — {len(rows)} profile row(s) → "
        f"{len(links)} link(s), {len(clusters)} cluster(s){saved_note}"
    )
    if save and run_id is None:
        console.print("[dim]cross-run recluster is read-only; pass --run to persist[/dim]")
    if links:
        _render_links(links)


# -- harvest ----------------------------------------------------------------


@app.command(rich_help_panel="Collect")
def harvest(
    ctx: typer.Context,
    username: Annotated[str, typer.Argument(help="Username on the chosen source")],
    source: Annotated[str, typer.Option("-s", "--source", help="Source name")],
    limit: Annotated[int, typer.Option("-n", "--limit", min=1, max=2000)] = 50,
    since: Annotated[str | None, typer.Option("--since", help="ISO timestamp lower bound")] = None,
    incremental: Annotated[
        bool, typer.Option("--incremental", help="Use the stored cursor as --since")
    ] = False,
    follows: Annotated[bool, typer.Option("--follows", help="Also collect follows")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
    save: Annotated[bool, typer.Option("--save/--no-save")] = True,
) -> None:
    """Pull a profile, recent posts, and optionally follows from one source."""
    settings = _settings(ctx)
    if source not in SOURCES:
        raise typer.BadParameter(f"unknown source {source!r}; try `coldtrail sources`")
    if SOURCES[source].kind != "username":
        raise typer.BadParameter(f"{source!r} is an email source; use `pivot` for emails")
    if not username.strip().lstrip("@"):
        raise typer.BadParameter("username must be non-empty")

    store = Store(settings.db_path)
    try:
        if incremental:
            cursor = store.get_cursor(source, username)
            if cursor:
                since = cursor["last_seen_at"]

        fetch_store = store if save else None
        check, posts = asyncio.run(
            run_harvest(
                source,
                username,
                settings=settings,
                limit=limit,
                since=since,
                store=fetch_store,
                run_id=None,
            )
        )
        edges = []
        if follows:
            _, edges = asyncio.run(
                collect_follows(source, username, settings=settings, limit=limit, store=fetch_store)
            )

        run_id: int | None = None
        if save:
            run_id = store.start_run("harvest", f"{source}:{username}")
            try:
                store.save_checks(run_id, [check])
                if check.profile:
                    store.save_profiles(run_id, [check.profile])
                    store.record_profile_history(run_id, [check.profile])
                store.save_posts(run_id, posts)
                store.save_entities(run_id, entities_from_posts(posts))
                if check.profile:
                    store.save_entities(run_id, entities_for_profiles([check.profile]))
                if edges:
                    store.save_edges(run_id, edges)
                if posts:
                    oldest = min(
                        (post.created_at for post in posts if post.created_at),
                        key=lambda value: epoch_seconds(value) or 0,
                        default=None,
                    )
                    store.mark_missing_posts(
                        source,
                        username,
                        {post.post_id for post in posts},
                        run_id,
                        since=oldest or since,
                    )
                if posts:
                    newest_post = max(
                        (post for post in posts if post.created_at),
                        key=lambda post: epoch_seconds(post.created_at) or 0,
                        default=None,
                    )
                    if newest_post:
                        store.set_cursor(
                            source,
                            username,
                            newest_post.post_id,
                            newest_post.created_at or "",
                        )
            except Exception:
                store.finish_run(run_id, "error")
                raise
            store.finish_run(run_id)
    finally:
        store.close()

    if json_out:
        _print_json(
            {
                "check": asdict(check),
                "posts": [asdict(post) for post in posts],
                "edges": [asdict(edge) for edge in edges],
                "run_id": run_id,
            }
        )
        if check.status != "found":
            raise typer.Exit(code=1)
        return

    console.print(f"[bold]{source}[/bold] {check.status}", style=STATUS_STYLE[check.status])
    if check.profile:
        _render_profiles([check.profile], f"Profile: {check.profile.username}")
    elif check.detail:
        console.print(f"[dim]{check.detail}[/dim]")
    _render_posts(posts, f"Recent posts ({len(posts)})")
    if edges:
        _render_edges(edges)
    if run_id:
        console.print(f"[dim]saved as run #{run_id} in {settings.db_path}[/dim]")
    if check.status != "found":
        raise typer.Exit(code=1)


# -- follows / graph --------------------------------------------------------


@app.command(rich_help_panel="Collect")
def graph(
    ctx: typer.Context,
    username: Annotated[str, typer.Argument()],
    source: Annotated[str, typer.Option("-s", "--source")],
    limit: Annotated[int, typer.Option("-n", "--limit", min=1, max=500)] = 100,
    json_out: Annotated[bool, typer.Option("--json")] = False,
    save: Annotated[bool, typer.Option("--save/--no-save")] = True,
) -> None:
    """Collect a public follow graph."""
    settings = _settings(ctx)
    if source not in SOURCES:
        raise typer.BadParameter(f"unknown source {source!r}")
    if SOURCES[source].kind != "username":
        raise typer.BadParameter(f"{source!r} is an email source; graphs need a username source")
    if not username.strip().lstrip("@"):
        raise typer.BadParameter("username must be non-empty")
    store = Store(settings.db_path)
    try:
        check, edges = asyncio.run(
            collect_follows(
                source,
                username,
                settings=settings,
                limit=limit,
                store=store if save else None,
            )
        )
        run_id: int | None = None
        if save:
            run_id = store.start_run("graph", f"{source}:{username}")
            try:
                store.save_checks(run_id, [check])
                if check.profile:
                    store.save_profiles(run_id, [check.profile])
                    store.record_profile_history(run_id, [check.profile])
                store.save_edges(run_id, edges)
            except Exception:
                store.finish_run(run_id, "error")
                raise
            store.finish_run(run_id)
    finally:
        store.close()
    if json_out:
        _print_json(
            {
                "check": asdict(check),
                "edges": [asdict(edge) for edge in edges],
                "run_id": run_id,
            }
        )
        return
    console.print(f"[bold]{source}[/bold] {check.status}", style=STATUS_STYLE[check.status])
    _render_edges(edges)
    if run_id:
        console.print(f"[dim]saved as run #{run_id} in {settings.db_path}[/dim]")


# -- watch ------------------------------------------------------------------


@app.command(rich_help_panel="Collect")
def watch(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Username or email")],
    source: Annotated[list[str] | None, typer.Option("-s", "--source")] = None,
    interval: Annotated[
        int, typer.Option("--interval", min=1, help="Seconds between cycles")
    ] = 3600,
    iterations: Annotated[int, typer.Option("--iterations", min=0, help="0 = forever")] = 0,
    limit: Annotated[int, typer.Option("-n", "--limit", min=1)] = 20,
    expand: Annotated[bool, typer.Option("--expand")] = False,
    alert: Annotated[
        str | None, typer.Option("--alert", help="webhook|discord|slack|telegram|ntfy|smtp")
    ] = None,
    alert_target: Annotated[
        str | None, typer.Option("--alert-target", help="URL, ntfy topic, or email")
    ] = None,
) -> None:
    """Monitor a target, alerting on new posts and profile edits."""
    settings = _settings(ctx)
    alerters = build_alerters(alert, alert_target) if alert and alert_target else []
    if alert and not alerters:
        console.print(f"[yellow]unknown or unconfigured alert kind: {alert}[/yellow]")
    store = Store(settings.db_path)

    def on_cycle(cycle, report, new_posts, changes):
        stamp = time.strftime("%H:%M:%S")
        console.print(
            f"[dim]{stamp}[/dim] [bold]cycle {cycle}[/bold] {target}: "
            f"{len(report.profiles)} profiles, {len(new_posts)} new posts, "
            f"{len(changes)} changes"
        )

    try:
        asyncio.run(
            run_watch(
                target,
                settings=settings,
                store=store,
                sources=source,
                interval=interval,
                iterations=iterations,
                limit=limit,
                expand=expand,
                alerters=alerters,
                on_cycle=on_cycle,
            )
        )
    except KeyboardInterrupt:
        console.print("[dim]stopped[/dim]")
    finally:
        store.close()
