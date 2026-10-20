"""Interactive menu for the most common workflows."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable

import typer
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from ..breach import full_breach_audit
from ..config import Settings
from ..domain import asn_lookup, lookup_domain, ptr, rdap_ip, reverse_ip
from ..dorks import dorks as build_dorks
from ..harvest import collect_follows
from ..harvest import harvest as run_harvest
from ..http import Fetcher
from ..integrations import (
    ToolError,
    ToolUnavailable,
    list_tools,
    persist_tool_result,
    run_tool,
)
from ..phone import lookup as phone_lookup
from ..pivot import persist_pivot
from ..pivot import pivot as run_pivot
from ..store import Store
from ._app import _render_pivot, _settings, app, console

MENU = """
[bold]1[/bold]  Pivot a username or email       [bold]6[/bold]  Domain / IP / phone / dorks
[bold]2[/bold]  Harvest posts from a source     [bold]7[/bold]  Cases
[bold]3[/bold]  Collect a follow graph          [bold]8[/bold]  External OSINT tools
[bold]4[/bold]  Search stored posts             [bold]9[/bold]  Open the TUI
[bold]5[/bold]  Browse runs                      [bold]10[/bold] Start the web UI
[bold]0[/bold]  Exit
"""


@app.command(rich_help_panel="Start here")
def menu(ctx: typer.Context) -> None:
    """Interactive menu for common workflows (pivot, harvest, search, tools)."""
    settings = _settings(ctx)
    actions: dict[str, tuple[str, Callable[[Settings], None]]] = {
        "1": ("Pivot", _menu_pivot),
        "2": ("Harvest", _menu_harvest),
        "3": ("Follow graph", _menu_graph),
        "4": ("Search", _menu_search),
        "5": ("Runs", _menu_runs),
        "6": ("Intel", _menu_intel),
        "7": ("Cases", _menu_cases),
        "8": ("External tools", _menu_tools),
        "9": ("TUI", _menu_tui),
        "10": ("Web UI", _menu_web),
    }
    while True:
        console.print(Panel(MENU.strip(), title="larpharvester menu", expand=False))
        choice = Prompt.ask("Choose", choices=[*actions, "0"], default="0")
        if choice == "0":
            return
        label, handler = actions[choice]
        console.rule(f"[bold]{label}[/bold]")
        try:
            handler(settings)
        except (KeyboardInterrupt, EOFError):
            console.print()
            return
        except Exception as exc:
            console.print(f"[red]{label} failed:[/red] {type(exc).__name__}: {exc}")
        console.print()


def _menu_pivot(settings: Settings) -> None:
    target = Prompt.ask("Target (username or email)").strip()
    if not target:
        return
    scope = Prompt.ask("Scope", choices=["curated", "web"], default="curated")
    expand = Confirm.ask("Expand linked accounts?", default=False)
    progress = {"checked": 0, "found": 0}

    def on_result(result) -> None:
        progress["checked"] += 1
        if result.status == "found":
            progress["found"] += 1

    with console.status("probing…", spinner="dots") as status:

        def report_progress(result) -> None:
            on_result(result)
            status.update(
                f"probing… {progress['checked']} checked, [green]{progress['found']} found[/green]"
            )

        report = asyncio.run(
            run_pivot(
                target,
                settings=settings,
                include_web=scope == "web",
                expand=expand,
                on_result=report_progress,
            )
        )
    with Store(settings.db_path) as store:
        persist_pivot(store, report)
    _render_pivot(report)
    console.print(f"[dim]saved as run #{report.run_id}[/dim]")


def _menu_harvest(settings: Settings) -> None:
    source = Prompt.ask("Source", default="github").strip()
    username = Prompt.ask("Username").strip()
    limit = IntPrompt.ask("Post limit", default=25)
    with Store(settings.db_path) as store:
        check, posts = asyncio.run(
            run_harvest(source, username, settings=settings, limit=limit, store=store)
        )
        run_id = store.start_run("harvest", f"{source}:{username}")
        store.save_checks(run_id, [check])
        if check.profile:
            store.save_profiles(run_id, [check.profile])
            store.record_profile_history(run_id, [check.profile])
        store.save_posts(run_id, posts)
        store.finish_run(run_id)
    console.print(f"{source}: {check.status} · {len(posts)} post(s) · run #{run_id}")


def _menu_graph(settings: Settings) -> None:
    source = Prompt.ask("Source", default="github").strip()
    username = Prompt.ask("Username").strip()
    limit = IntPrompt.ask("Edge limit", default=50)
    with Store(settings.db_path) as store:
        check, edges = asyncio.run(
            collect_follows(source, username, settings=settings, limit=limit, store=store)
        )
        run_id = store.start_run("graph", f"{source}:{username}")
        store.save_checks(run_id, [check])
        if check.profile:
            store.save_profiles(run_id, [check.profile])
        store.save_edges(run_id, edges)
        store.finish_run(run_id)
    console.print(f"{source}: {check.status} · {len(edges)} edge(s) · run #{run_id}")


def _menu_search(settings: Settings) -> None:
    query = Prompt.ask("Search query").strip()
    if not query:
        return
    with Store(settings.db_path) as store:
        rows = store.search(query, limit=50)
    table = Table(title=f"Search: {query} ({len(rows)})")
    for column in ("When", "Source", "Username", "Text"):
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(
            (row["created_at"] or "")[:19],
            row["source"],
            row["username"],
            " ".join((row["text"] or "").split())[:100],
        )
    console.print(table)


def _menu_runs(settings: Settings) -> None:
    with Store(settings.db_path) as store:
        rows = store.runs(limit=20)
    table = Table(title=f"Recent runs ({len(rows)})")
    for column in ("ID", "Kind", "Target", "Started", "Status"):
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(
            str(row["id"]),
            row["kind"],
            row["target"],
            (row["started_at"] or "")[:19],
            row["status"],
        )
    console.print(table)
    if not rows:
        return
    run_id = IntPrompt.ask("Open run ID (0 to skip)", default=0)
    if not run_id:
        return
    with Store(settings.db_path) as store:
        profiles = store.profiles(run_id=run_id, limit=100)
        posts = store.posts(run_id=run_id, limit=100)
        evidence = store.attachments(run_id=run_id, limit=100)
    console.print(
        f"run #{run_id}: {len(profiles)} profiles, {len(posts)} posts, {len(evidence)} evidence"
    )


def _menu_intel(settings: Settings) -> None:
    kind = Prompt.ask(
        "Intel", choices=["domain", "ip", "phone", "dorks", "breach"], default="domain"
    )
    target = Prompt.ask("Target").strip()
    if not target:
        return

    async def run() -> object:
        async with Fetcher(settings) as fetcher:
            if kind == "domain":
                return await lookup_domain(fetcher, target, deep=True)
            if kind == "ip":
                return {
                    "address": target,
                    "ptr": await ptr(fetcher, target),
                    "hostnames": await reverse_ip(fetcher, target, settings.shodan_api_key),
                    "asn": await asn_lookup(fetcher, target),
                    "rdap": await rdap_ip(fetcher, target),
                }
            if kind == "breach":
                return await full_breach_audit(fetcher, target)
            return None

    if kind == "phone":
        payload = phone_lookup(target)
    elif kind == "dorks":
        payload = build_dorks(target)
    else:
        payload = asyncio.run(run())
    console.print_json(json.dumps(payload, indent=2, default=str))


def _menu_cases(settings: Settings) -> None:
    with Store(settings.db_path) as store:
        cases = store.cases()
    table = Table(title=f"Cases ({len(cases)})")
    for column in ("ID", "Name", "Runs", "Created"):
        table.add_column(column, overflow="fold")
    for case in cases:
        table.add_row(str(case["id"]), case["name"], str(case["runs"]), case["created_at"][:19])
    console.print(table)
    name = Prompt.ask("New case name (blank to skip)", default="").strip()
    if not name:
        return
    with Store(settings.db_path) as store:
        case_id = store.create_case(name)
    console.print(f"created case #{case_id} {name}")


def _menu_tools(settings: Settings) -> None:
    rows = list_tools()
    table = Table(title="External tools")
    for column in ("Tool", "Category", "Installed", "Description"):
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(
            row["name"],
            row["category"],
            "[green]yes[/green]" if row["installed"] else "[dim]no[/dim]",
            row["description"],
        )
    console.print(table)
    tool = Prompt.ask("Tool name").strip()
    target = Prompt.ask("Target").strip()
    if not tool or not target:
        return
    try:
        result = run_tool(tool, target)
    except ToolUnavailable as exc:
        console.print(f"[yellow]{exc}[/yellow]")
        return
    except ToolError as exc:
        console.print(f"[red]{exc}[/red]")
        return
    with Store(settings.db_path) as store:
        run_id = persist_tool_result(store, result)
    console.print(f"{tool}: {result.summary} · run #{run_id}")


def _menu_tui(settings: Settings) -> None:
    from ..tui import run_tui

    run_tui(settings)


def _menu_web(settings: Settings) -> None:
    import uvicorn

    from ..web import create_app

    port = IntPrompt.ask("Port", default=8765)
    console.print(f"serving http://127.0.0.1:{port}/ — Ctrl+C to stop")
    uvicorn.run(create_app(settings), host="127.0.0.1", port=port, log_level="warning")
