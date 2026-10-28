"""CLI commands for external OSINT tool integrations and importers."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table

from ..integrations import (
    INGEST_FORMATS,
    ToolError,
    ToolUnavailable,
    ingest_file,
    list_tools,
    persist_ingest,
    persist_tool_result,
    run_tool,
)
from ..store import Store
from ._app import _print_json, _settings, app, console


@app.command(rich_help_panel="Integrations")
def integrations(
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List external OSINT tools, install status, and import formats."""
    rows = list_tools()
    if json_out:
        _print_json(rows)
        return
    table = Table(title=f"External tools ({sum(1 for row in rows if row['installed'])} installed)")
    for column in ("Tool", "Category", "Input", "Installed", "Description", "Install"):
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(
            row["name"],
            row["category"],
            row["input"],
            "[green]yes[/green]" if row["installed"] else "[dim]no[/dim]",
            row["description"],
            "" if row["installed"] else row["install"],
        )
    console.print(table)
    console.print(
        "[dim]Import formats: "
        + ", ".join(sorted(INGEST_FORMATS))
        + " — use `coldtrail ingest FILE --format auto`[/dim]"
    )


@app.command(rich_help_panel="Integrations")
def run(
    ctx: typer.Context,
    tool: Annotated[str, typer.Argument(help="Tool name (see `coldtrail integrations`)")],
    target: Annotated[str, typer.Argument(help="Username, email, domain, URL, IP, or file")],
    timeout: Annotated[float, typer.Option("--timeout", min=1, help="Tool timeout (s)")] = 180.0,
    extra: Annotated[
        list[str] | None, typer.Option("--extra", help="Extra argument passed to the tool")
    ] = None,
    save: Annotated[bool, typer.Option("--save/--no-save")] = True,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Run an installed external OSINT tool and import its findings."""
    settings = _settings(ctx)
    try:
        result = run_tool(
            tool,
            target,
            timeout=timeout,
            extra_args=extra,
            allow_private=settings.allow_private_targets,
        )
    except ToolUnavailable as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    except ToolError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    run_id: int | None = None
    if save:
        with Store(settings.db_path) as store:
            run_id = persist_tool_result(store, result)

    if json_out:
        payload = asdict(result)
        payload["run_id"] = run_id
        _print_json(payload)
        return

    console.print(f"[bold]{tool}[/bold] → {target}: {result.summary}")
    if result.profiles:
        table = Table(title=f"Profiles ({len(result.profiles)})")
        for column in ("Source", "Username", "Name", "URL"):
            table.add_column(column, overflow="fold")
        for profile in result.profiles[:100]:
            table.add_row(
                profile.source,
                profile.username,
                profile.display_name or "",
                profile.url,
            )
        console.print(table)
    if result.entities:
        table = Table(title=f"Entities ({len(result.entities)})")
        for column in ("Kind", "Value", "Source"):
            table.add_column(column, overflow="fold")
        for entity in result.entities[:100]:
            table.add_row(entity.kind, entity.value, entity.source)
        console.print(table)
    if run_id:
        console.print(f"[dim]saved as run #{run_id} (raw output stored as evidence)[/dim]")


@app.command(rich_help_panel="Integrations")
def ingest(
    ctx: typer.Context,
    file: Annotated[Path, typer.Argument(help="Maltego CSV / SpiderFoot / theHarvester JSON")],
    format: Annotated[
        str,
        typer.Option("--format", help="auto|maltego|spiderfoot|theharvester|json"),
    ] = "auto",
    save: Annotated[bool, typer.Option("--save/--no-save")] = True,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Import another OSINT tool's export into the local database."""
    settings = _settings(ctx)
    if not file.is_file():
        typer.echo(f"not a file: {file}", err=True)
        raise typer.Exit(code=1)
    try:
        chosen, parsed, raw = ingest_file(file, format)
    except ToolError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    run_id: int | None = None
    if save:
        with Store(settings.db_path) as store:
            run_id = persist_ingest(store, str(file), chosen, parsed, raw)

    if json_out:
        payload = asdict(parsed)
        payload.update({"format": chosen, "run_id": run_id})
        _print_json(payload)
        return

    console.print(f"[bold]{chosen}[/bold] import: {parsed.summary}")
    if parsed.profiles:
        table = Table(title=f"Profiles ({len(parsed.profiles)})")
        for column in ("Source", "Username", "URL"):
            table.add_column(column, overflow="fold")
        for profile in parsed.profiles[:100]:
            table.add_row(profile.source, profile.username, profile.url)
        console.print(table)
    if parsed.entities:
        table = Table(title=f"Entities ({len(parsed.entities)})")
        for column in ("Kind", "Value", "Source"):
            table.add_column(column, overflow="fold")
        for entity in parsed.entities[:100]:
            table.add_row(entity.kind, entity.value, entity.source)
        console.print(table)
    if run_id:
        console.print(f"[dim]saved as run #{run_id} (source file stored as evidence)[/dim]")
