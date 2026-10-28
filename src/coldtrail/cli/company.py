"""Corporate/sanctions lookup command."""

from __future__ import annotations

import asyncio
from typing import Annotated

import typer
from rich.table import Table

from ..company import company_search
from ..http import Fetcher, FetchError
from ._app import _print_json, _settings, app, console


@app.command(rich_help_panel="Intel")
def company(
    ctx: typer.Context,
    query: Annotated[str, typer.Argument(help="Company, person, or registration query")],
    provider: Annotated[
        str,
        typer.Option("--provider", help="auto|opensanctions|opencorporates|companies-house|all"),
    ] = "auto",
    limit: Annotated[int, typer.Option("-n", "--limit", min=1, max=100)] = 10,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Search corporate registries and sanctions/PEP lists."""
    settings = _settings(ctx)

    async def run():
        async with Fetcher(settings) as fetcher:
            return await company_search(fetcher, query, settings, provider=provider, limit=limit)

    try:
        rows = asyncio.run(run())
    except (FetchError, ValueError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    if json_out:
        _print_json(rows)
        return
    table = Table(title=f"Company/sanctions: {query} ({len(rows)})")
    for column in ("Provider", "Name", "ID/Number", "Status", "Address/Datasets"):
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(
            row["provider"],
            row["name"],
            str(row.get("number") or row.get("id") or ""),
            str(row.get("status") or row.get("schema") or ""),
            str(row.get("address") or row.get("datasets") or ""),
        )
    console.print(table)
