from __future__ import annotations

import asyncio
import json
from dataclasses import asdict
from typing import Annotated

import typer

from ..alerts import build_alerters
from ..analysis import entities_from_posts
from ..config import Settings
from ..harvest import collect_follows
from ..harvest import harvest as run_harvest
from ..models import PivotReport
from ..pivot import entities_for_profiles
from ..pivot import pivot as run_pivot
from ..sources import SOURCES
from ..store import Store
from ..watch import watch as run_watch
from ._app import (
    STATUS_STYLE,
    _exit_for_found,
    _null,
    _print_json,
    _render_edges,
    _render_pivot,
    _render_posts,
    _render_profiles,
    _settings,
    app,
    console,
)


@app.command()
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
    variants: Annotated[
        bool, typer.Option("--variants", help="Probe generated handle/email variants")
    ] = False,
    web: Annotated[bool, typer.Option("--web", help="Include the 478-site web corpus")] = False,
    all_sources: Annotated[bool, typer.Option("--all", help="Every registered source")] = False,
    avatar_hash: Annotated[
        bool, typer.Option("--avatar-hash/--no-avatar-hash", help="Perceptual avatar hashing")
    ] = True,
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

    try:
        store = Store(settings.db_path) if save else None
        try:
            with console.status(f"probing {target}…", spinner="dots") if not json_out else _null():
                report = asyncio.run(
                    run_pivot(
                        target,
                        settings=settings,
                        sources=names,
                        expand=expand,
                        max_expand=max_expand,
                        use_variants=variants,
                        include_web=web,
                        avatar_hash=avatar_hash,
                        use_cache=save and settings.negative_cache_ttl > 0,
                        store=store,
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
        _print_json(asdict(report))
        _exit_for_found(report)
        return
    if jsonl:
        _pivot_jsonl(report)
        _exit_for_found(report)
        return

    _render_pivot(report)
    if report.run_id:
        console.print(f"[dim]saved as run #{report.run_id} in {settings.db_path}[/dim]")
    _exit_for_found(report)


def _pivot_jsonl(report: PivotReport) -> None:
    for result in report.results:
        typer.echo(json.dumps({"type": "check", **asdict(result)}, default=str))
    for link in report.links:
        typer.echo(json.dumps({"type": "link", **asdict(link)}, default=str))
    for cluster in report.clusters:
        typer.echo(json.dumps({"type": "cluster", **asdict(cluster)}, default=str))


def _save_pivot(settings: Settings, report: PivotReport) -> None:
    with Store(settings.db_path) as store:
        run_id = store.start_run("pivot", report.target)
        try:
            store.save_checks(run_id, report.results)
            store.save_profiles(run_id, report.profiles)
            store.save_links(run_id, report.links)
            store.save_clusters(run_id, report.clusters)
            store.save_entities(run_id, entities_for_profiles(report.profiles))
            store.record_profile_history(run_id, report.profiles)
        except Exception:
            store.finish_run(run_id, "error")
            raise
        store.finish_run(run_id)
        report.run_id = run_id


# -- harvest ----------------------------------------------------------------


@app.command()
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
        raise typer.BadParameter(f"unknown source {source!r}; try `larpharvester sources`")
    if SOURCES[source].kind != "username":
        raise typer.BadParameter(f"{source!r} is an email source; use `pivot` for emails")

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
                        (post.created_at for post in posts if post.created_at), default=None
                    )
                    store.mark_missing_posts(
                        source,
                        username,
                        {post.post_id for post in posts},
                        run_id,
                        since=oldest or since,
                    )
                if posts:
                    newest = max(
                        (post.created_at for post in posts if post.created_at), default=None
                    )
                    if newest:
                        store.set_cursor(source, username, posts[0].post_id, newest)
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


@app.command()
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


@app.command()
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
    alert: Annotated[str | None, typer.Option("--alert", help="webhook|discord|ntfy|smtp")] = None,
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
        console.print(
            f"[bold]cycle {cycle}[/bold] {target}: "
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
