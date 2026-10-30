from __future__ import annotations

from typing import Annotated

import typer
from rich.table import Table

from ..store import Store
from ._app import (
    _print_json,
    _render_history,
    _render_stored_clusters,
    _render_stored_links,
    _settings,
    _truncate,
    app,
    console,
)


@app.command(rich_help_panel="Query")
def profiles(
    ctx: typer.Context,
    run: Annotated[int | None, typer.Option("--run")] = None,
    source: Annotated[str | None, typer.Option("--source")] = None,
    username: Annotated[str | None, typer.Option("--username")] = None,
    limit: Annotated[int, typer.Option("-n", "--limit", min=1)] = 100,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Query stored profiles."""
    with Store(_settings(ctx).db_path) as store:
        rows = store.profiles(run_id=run, source=source, username=username, limit=limit)
    if json_out:
        _print_json(rows)
        return
    table = Table(title=f"Profiles ({len(rows)})")
    for column in ("Run", "Source", "Username", "Name", "Lang", "Followers", "URL"):
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(
            str(row["run_id"]),
            row["source"],
            row["username"],
            row["display_name"] or "",
            row["lang"] or "",
            str(row["followers"]) if row["followers"] is not None else "",
            row["url"],
        )
    console.print(table)


@app.command(rich_help_panel="Query")
def posts(
    ctx: typer.Context,
    run: Annotated[int | None, typer.Option("--run")] = None,
    username: Annotated[str | None, typer.Option("--username")] = None,
    source: Annotated[str | None, typer.Option("--source")] = None,
    since: Annotated[str | None, typer.Option("--since")] = None,
    deleted: Annotated[bool, typer.Option("--deleted", help="Include tombstones")] = True,
    limit: Annotated[int, typer.Option("-n", "--limit", min=1)] = 100,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Query stored posts."""
    with Store(_settings(ctx).db_path) as store:
        rows = store.posts(
            run_id=run,
            username=username,
            source=source,
            limit=limit,
            since=since,
            include_deleted=deleted,
        )
    if json_out:
        _print_json(rows)
        return
    table = Table(title=f"Posts ({len(rows)})")
    for column in ("Run", "Source", "When", "Text", "URL"):
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(
            str(row["run_id"]),
            row["source"],
            (row["created_at"] or "")[:19],
            _truncate(row["text"] or "", 90),
            row["url"],
        )
    console.print(table)


@app.command(rich_help_panel="Query")
def links(
    ctx: typer.Context,
    run: Annotated[int | None, typer.Option("--run")] = None,
    limit: Annotated[int, typer.Option("-n", "--limit", min=1)] = 100,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Query stored correlation links."""
    with Store(_settings(ctx).db_path) as store:
        rows = store.links(run_id=run, limit=limit)
    if json_out:
        _print_json(rows)
        return
    _render_stored_links(rows)


@app.command(rich_help_panel="Query")
def clusters(
    ctx: typer.Context,
    run: Annotated[int | None, typer.Option("--run")] = None,
    limit: Annotated[int, typer.Option("-n", "--limit", min=1)] = 100,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Query inferred identity clusters."""
    with Store(_settings(ctx).db_path) as store:
        rows = store.clusters(run_id=run, limit=limit)
    if json_out:
        _print_json(rows)
        return
    _render_stored_clusters(rows)


@app.command(rich_help_panel="Query")
def entities(
    ctx: typer.Context,
    run: Annotated[int | None, typer.Option("--run")] = None,
    kind: Annotated[str | None, typer.Option("--kind")] = None,
    value: Annotated[str | None, typer.Option("--value")] = None,
    limit: Annotated[int, typer.Option("-n", "--limit", min=1)] = 200,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Query extracted entities (emails, wallets, phones, handles)."""
    with Store(_settings(ctx).db_path) as store:
        rows = store.entities(run_id=run, kind=kind, value=value, limit=limit)
    if json_out:
        _print_json(rows)
        return
    table = Table(title=f"Entities ({len(rows)})")
    for column in ("Kind", "Value", "Observed on", "Context"):
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(
            row["kind"],
            row["value"],
            f"{row['source']}:{row['username']}",
            _truncate(row["context"] or "", 70),
        )
    console.print(table)


@app.command(rich_help_panel="Query")
def runs(
    ctx: typer.Context,
    limit: Annotated[int, typer.Option("-n", "--limit", min=1)] = 25,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List recent runs."""
    with Store(_settings(ctx).db_path) as store:
        rows = store.runs(limit=limit)
    if json_out:
        _print_json(rows)
        return
    table = Table(title=f"Runs ({len(rows)})")
    for column in ("ID", "Kind", "Target", "Started", "Finished", "Status"):
        table.add_column(column, no_wrap=True)
    for row in rows:
        table.add_row(
            str(row["id"]),
            row["kind"],
            row["target"],
            row["started_at"],
            row["finished_at"] or "",
            row["status"],
        )
    console.print(table)


@app.command(rich_help_panel="Query")
def edges(
    ctx: typer.Context,
    run: Annotated[int | None, typer.Option("--run")] = None,
    actor: Annotated[str | None, typer.Option("--actor")] = None,
    target: Annotated[str | None, typer.Option("--target")] = None,
    limit: Annotated[int, typer.Option("-n", "--limit", min=1)] = 200,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Query stored follow edges."""
    with Store(_settings(ctx).db_path) as store:
        rows = store.edges(run_id=run, actor=actor, target=target, limit=limit)
    if json_out:
        _print_json(rows)
        return
    table = Table(title=f"Edges ({len(rows)})")
    for column in ("Run", "Platform", "Actor", "Target", "Direction"):
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(
            str(row["run_id"]), row["platform"], row["actor"], row["target"], row["direction"]
        )
    console.print(table)


@app.command(rich_help_panel="Query")
def search(
    ctx: typer.Context,
    query: Annotated[str, typer.Argument(help="FTS query")],
    limit: Annotated[int, typer.Option("-n", "--limit", min=1)] = 50,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Full-text search over stored posts."""
    with Store(_settings(ctx).db_path) as store:
        rows = store.search(query, limit=limit)
    if json_out:
        _print_json(rows)
        return
    table = Table(title=f"Search: {query} ({len(rows)})")
    for column in ("When", "Source", "Username", "Text", "URL"):
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(
            (row["created_at"] or "")[:19],
            row["source"],
            row["username"],
            _truncate(row["text"] or "", 100),
            row["url"],
        )
    console.print(table)


@app.command(rich_help_panel="Query")
def timeline(
    ctx: typer.Context,
    run: Annotated[int | None, typer.Option("--run")] = None,
    since: Annotated[str | None, typer.Option("--since", help="ISO lower bound")] = None,
    until: Annotated[str | None, typer.Option("--until", help="ISO upper bound")] = None,
    limit: Annotated[int, typer.Option("-n", "--limit", min=1)] = 500,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Cross-source chronological timeline."""
    with Store(_settings(ctx).db_path) as store:
        rows = store.timeline(run_id=run, limit=limit, since=since, until=until)
    if json_out:
        _print_json(rows)
        return
    table = Table(title=f"Timeline ({len(rows)})")
    for column in ("When", "Source", "Username", "Text", "URL"):
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(
            (row["created_at"] or "")[:19],
            row["source"],
            row["username"],
            _truncate(row["text"] or "", 90),
            row["url"],
        )
    console.print(table)


@app.command(rich_help_panel="Query")
def history(
    ctx: typer.Context,
    run: Annotated[int | None, typer.Option("--run")] = None,
    username: Annotated[str | None, typer.Option("--username")] = None,
    limit: Annotated[int, typer.Option("-n", "--limit", min=1)] = 200,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Profile field changes observed across runs."""
    with Store(_settings(ctx).db_path) as store:
        rows = store.history(run_id=run, username=username, limit=limit)
    if json_out:
        _print_json(rows)
        return
    _render_history(rows)


@app.command(rich_help_panel="Query")
def diff(
    ctx: typer.Context,
    run_a: Annotated[int, typer.Argument(help="Baseline run ID")],
    run_b: Annotated[int, typer.Argument(help="Comparison run ID")],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Compare two stored runs: added/removed/changed profiles, entities, links, posts."""
    from ..correlate import diff_runs

    with Store(_settings(ctx).db_path) as store:
        missing = [run_id for run_id in (run_a, run_b) if store.run(run_id) is None]
        if missing:
            typer.echo(f"run(s) not found: {', '.join(map(str, missing))}", err=True)
            raise typer.Exit(code=1)
        payload = diff_runs(store, run_a, run_b)
    if json_out:
        _print_json(payload)
        return

    profiles = payload["profiles"]
    entities = payload["entities"]
    links = payload["links"]
    clusters = payload["clusters"]
    posts = payload["posts"]
    console.print(f"[bold]Diff[/bold] run #{run_a} → run #{run_b}")
    console.print(
        f"  profiles: +{len(profiles['added'])} / -{len(profiles['removed'])}"
        f" / ~{len(profiles['changed'])}"
    )
    console.print(f"  entities: +{len(entities['added'])} / -{len(entities['removed'])}")
    console.print(f"  links:    +{len(links['added'])} / -{len(links['removed'])}")
    console.print(f"  clusters: +{len(clusters['added'])} / -{len(clusters['removed'])}")
    console.print(
        f"  posts:    +{len(posts['added'])} / -{len(posts['removed'])}"
        f" / tombstoned {len(posts['tombstoned'])}"
    )

    for title, rows in (
        ("Added profiles", profiles["added"]),
        ("Removed profiles", profiles["removed"]),
    ):
        if not rows:
            continue
        table = Table(title=title)
        for column in ("Source", "Username"):
            table.add_column(column, overflow="fold")
        for row in rows:
            table.add_row(row["source"], row["username"])
        console.print(table)

    if profiles["changed"]:
        table = Table(title="Changed profiles")
        for column in ("Source", "Username", "Field", "Old", "New"):
            table.add_column(column, overflow="fold")
        for row in profiles["changed"]:
            for field, (old, new) in row["fields"].items():
                table.add_row(
                    row["source"],
                    row["username"],
                    field,
                    _truncate(str(old), 40),
                    _truncate(str(new), 40),
                )
        console.print(table)

    for title, rows, columns in (
        ("Added entities", entities["added"], ("Kind", "Value", "Observed on")),
        ("Removed entities", entities["removed"], ("Kind", "Value", "Observed on")),
    ):
        if not rows:
            continue
        table = Table(title=title)
        for column in columns:
            table.add_column(column, overflow="fold")
        for row in rows:
            table.add_row(str(row["kind"]), str(row["value"]), f"{row['source']}:{row['username']}")
        console.print(table)
