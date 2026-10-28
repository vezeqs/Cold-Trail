"""Web search-engine command."""

from __future__ import annotations

import asyncio
from typing import Annotated

import typer
from rich.table import Table

from ..http import Fetcher, FetchError
from ..websearch import search
from ._app import _print_json, _settings, app, console


@app.command(rich_help_panel="Intel")
def websearch(
    ctx: typer.Context,
    query: Annotated[str, typer.Argument(help="Search query or dork")],
    provider: Annotated[
        str, typer.Option("--provider", help="auto|serper|brave|searxng|duckduckgo")
    ] = "auto",
    limit: Annotated[int, typer.Option("-n", "--limit", min=1, max=100)] = 10,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Run a web search through a configured search provider."""
    settings = _settings(ctx)

    async def run():
        async with Fetcher(settings) as fetcher:
            return await search(fetcher, query, settings, provider=provider, limit=limit)

    try:
        chosen, results = asyncio.run(run())
    except (FetchError, ValueError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    if json_out:
        _print_json({"provider": chosen, "query": query, "results": results})
        return
    table = Table(title=f"Web search: {query} ({chosen}, {len(results)})")
    for column in ("Title", "URL", "Snippet"):
        table.add_column(column, overflow="fold")
    for item in results:
        table.add_row(item["title"], item["url"], item["snippet"])
    console.print(table)
