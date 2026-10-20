from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from .. import __version__
from ..config import Settings
from ..models import Link, PivotReport, Post, Profile
from ..store import Store

app = typer.Typer(
    add_completion=True,
    no_args_is_help=False,
    help="OSINT pivoting, harvesting, correlation and reporting.",
    epilog=(
        "Global options (--db, --config, --timeout, --concurrency, --proxy, --tor, "
        "--cache, --max-requests, ...) must be placed before the command, e.g. "
        "`larpharvester --db case.db pivot alice`."
    ),
)
case_app = typer.Typer(help="Case management.")
source_app = typer.Typer(help="Source inspection.")
app.add_typer(case_app, name="case", rich_help_panel="Casework")
app.add_typer(source_app, name="source", rich_help_panel="Intel")

console = Console()
STATUS_STYLE = {"found": "green", "not_found": "dim", "blocked": "yellow", "error": "red"}


# -- global options ---------------------------------------------------------


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    db: Annotated[Path | None, typer.Option("--db", help="SQLite database path")] = None,
    config: Annotated[Path | None, typer.Option("--config", help="TOML config file")] = None,
    timeout: Annotated[float | None, typer.Option("--timeout", help="Request timeout")] = None,
    concurrency: Annotated[
        int | None, typer.Option("--concurrency", min=1, help="Max in-flight requests")
    ] = None,
    proxy: Annotated[str | None, typer.Option("--proxy", help="HTTP/SOCKS proxy URL")] = None,
    tor: Annotated[bool, typer.Option("--tor", help="Route via 127.0.0.1:9050")] = False,
    cache: Annotated[bool, typer.Option("--cache/--no-cache", help="HTTP + probe cache")] = True,
    raw: Annotated[bool, typer.Option("--raw/--no-raw", help="Retain raw responses")] = True,
    max_requests: Annotated[
        int | None, typer.Option("--max-requests", help="Per-run request budget (0 = unlimited)")
    ] = None,
    respect_robots: Annotated[
        bool, typer.Option("--respect-robots", help="Honour robots.txt")
    ] = False,
    replay: Annotated[
        bool, typer.Option("--replay", help="Serve responses from stored raw captures")
    ] = False,
    version: Annotated[bool, typer.Option("--version", is_eager=True)] = False,
) -> None:
    if version:
        typer.echo(f"larpharvester {__version__}")
        raise typer.Exit()

    settings = Settings.load(config)
    if db is not None:
        settings.db_path = db.expanduser()
    if timeout is not None:
        settings.timeout = timeout
    if concurrency is not None:
        settings.concurrency = concurrency
    if proxy:
        settings.proxy = proxy
    if tor:
        settings.tor = True
    if not cache:
        settings.cache_ttl = 0
        settings.negative_cache_ttl = 0
    if not raw:
        settings.keep_raw = False
    if max_requests is not None:
        settings.max_requests = max_requests
    if respect_robots:
        settings.respect_robots = True
    if replay:
        settings.replay = True
    ctx.obj = settings
    ctx.meta["settings"] = settings

    from ..sources import sync as _sync_sources

    _sync_sources(settings.sites_path)

    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()

    if "--no-save" not in sys.argv:
        try:
            with Store(settings.db_path) as store:
                if settings.retention_days:
                    store.prune(settings.retention_days)
                store.audit_log(
                    ctx.invoked_subcommand,
                    None,
                    {"argv": sys.argv[1:]},
                )
        except (OSError, ValueError):
            pass


def _settings(ctx: typer.Context) -> Settings:
    settings: Settings = ctx.obj
    return settings


def _print_json(payload: Any) -> None:
    typer.echo(json.dumps(payload, indent=2, ensure_ascii=False, default=str))


def _truncate(text: str, width: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= width else text[: width - 1] + "…"


def _exit_for_found(report: PivotReport) -> None:
    if not any(result.status == "found" for result in report.results):
        raise typer.Exit(code=1)


class _null:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


# -- rendering --------------------------------------------------------------


def _render_pivot(report: PivotReport, show_all: bool = False) -> None:
    found = report.coverage.get("found", 0)
    coverage = ", ".join(f"{status}: {count}" for status, count in sorted(report.coverage.items()))
    console.print(
        f"[bold]Pivot[/bold] {report.target} ([cyan]{report.kind}[/cyan]) — "
        f"{found}/{len(report.results)} checks matched ({coverage})"
    )
    visible = report.results if show_all else [r for r in report.results if r.status == "found"]
    if visible:
        table = Table()
        for column in ("Source", "Status", "Target", "Handle", "Name", "URL", "Detail"):
            table.add_column(column, overflow="fold")
        for result in visible:
            profile = result.profile
            table.add_row(
                result.source,
                f"[{STATUS_STYLE[result.status]}]{result.status}[/]",
                result.target,
                profile.username if profile else "",
                (profile.display_name or "") if profile else "",
                profile.url if profile else "",
                result.detail or "",
            )
        console.print(table)
    else:
        console.print("[dim]No matching profiles.[/dim]")
    hidden = len(report.results) - len(visible)
    if hidden:
        console.print(
            f"[dim]{hidden} non-matching checks hidden; use --all-checks to show them.[/dim]"
        )

    if report.expanded:
        console.print(f"[dim]expanded handles: {', '.join(report.expanded)}[/dim]")

    if report.clusters:
        table = Table(title="Inferred identities")
        for column in ("Cluster", "Size", "Confidence", "Members", "Reasons"):
            table.add_column(column, overflow="fold")
        for cluster in report.clusters:
            table.add_row(
                cluster.key,
                str(len(cluster.profiles)),
                f"{cluster.score:.2f}",
                ", ".join(f"{p.source}:{p.username}" for p in cluster.profiles),
                ", ".join(cluster.reasons),
            )
        console.print(table)

    if report.links:
        _render_links(report.links)
    else:
        console.print("[dim]No cross-source links above threshold.[/dim]")


def _render_links(links: list[Link]) -> None:
    table = Table(title="Correlated identities")
    for column in ("A", "B", "Score", "Reasons"):
        table.add_column(column, overflow="fold")
    for link in links:
        table.add_row(
            f"{link.a.source}:{link.a.username}",
            f"{link.b.source}:{link.b.username}",
            f"{link.score:.2f}",
            ", ".join(link.reasons),
        )
    console.print(table)


def _render_stored_links(rows: list[dict[str, Any]]) -> None:
    table = Table(title=f"Links ({len(rows)})")
    for column in ("Run", "A", "B", "Score", "Reasons"):
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(
            str(row["run_id"]),
            f"{row['source_a']}:{row['username_a']}",
            f"{row['source_b']}:{row['username_b']}",
            f"{row['score']:.2f}",
            ", ".join(row["reasons"]),
        )
    console.print(table)


def _render_stored_clusters(rows: list[dict[str, Any]]) -> None:
    table = Table(title=f"Clusters ({len(rows)})")
    for column in ("Run", "Key", "Size", "Confidence", "Members", "Reasons"):
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(
            str(row["run_id"]),
            row["cluster_key"],
            str(row["size"]),
            f"{row['score']:.2f}",
            ", ".join(f"{m['source']}:{m['username']}" for m in row["members"]),
            ", ".join(row["reasons"]),
        )
    console.print(table)


def _render_profiles(profiles: list[Profile], title: str) -> None:
    table = Table(title=title)
    for column in ("Source", "Username", "Name", "Bio", "URL"):
        table.add_column(column, overflow="fold")
    for profile in profiles:
        table.add_row(
            profile.source,
            profile.username,
            profile.display_name or "",
            _truncate(profile.bio or "", 100),
            profile.url,
        )
    console.print(table)


def _render_posts(posts: list[Post], title: str) -> None:
    table = Table(title=title)
    for column in ("When", "Text", "URL"):
        table.add_column(column, overflow="fold")
    for post in posts:
        table.add_row(
            (post.created_at or "")[:19],
            _truncate(post.text or "", 100),
            post.url,
        )
    console.print(table)


def _render_edges(edges) -> None:
    table = Table(title=f"Follows ({len(edges)})")
    for column in ("Platform", "Actor", "Target", "Direction"):
        table.add_column(column, overflow="fold")
    for edge in edges:
        table.add_row(edge.platform, edge.actor, edge.target, edge.direction)
    console.print(table)


def _render_history(rows: list[dict[str, Any]]) -> None:
    table = Table(title=f"Profile changes ({len(rows)})")
    for column in ("Run", "Target", "Field", "Old", "New", "Observed"):
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(
            str(row["run_id"]),
            f"{row['source']}:{row['username']}",
            row["field"],
            _truncate(row["old_value"] or "", 40),
            _truncate(row["new_value"] or "", 40),
            row["observed_at"],
        )
    console.print(table)
