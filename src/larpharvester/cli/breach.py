"""Breach-exposure audit commands (defensive).

`breach` lists the breaches an email address appears in (HIBP, requires key).
`pwned` checks a user-supplied password against Pwned Passwords via SHA-1
k-anonymity — only a 5-character hash prefix is transmitted, never the
password or the full hash.
"""

from __future__ import annotations

import asyncio
import os
from typing import Annotated

import typer
from rich.table import Table

from ..breach import full_breach_audit, hibp_breaches, pwned_password
from ..http import Fetcher, FetchError
from ._app import _print_json, _settings, app, console


@app.command()
def breach(
    ctx: typer.Context,
    email: Annotated[str, typer.Argument(help="Email address to audit")],
    all_providers: Annotated[
        bool,
        typer.Option("--all", help="Query HIBP + HudsonRock Cavalier + LeakCheck public"),
    ] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List breaches an email address appears in (HIBP, or --all for multi-provider)."""
    settings = _settings(ctx)

    async def run():
        async with Fetcher(settings) as fetcher:
            if all_providers:
                return await full_breach_audit(fetcher, email)
            return await hibp_breaches(fetcher, email)

    try:
        result = asyncio.run(run())
    except FetchError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    if all_providers:
        if json_out:
            _print_json(result)
            return
        console.print(f"[bold]{email}[/bold] — overall: {result['status']}")
        for provider in ("hibp", "hudsonrock", "leakcheck"):
            sub = result.get(provider) or {}
            status = sub.get("status")
            console.print(f"  [cyan]{provider}[/cyan]: {status} — {sub.get('detail', '')}")
        return

    if json_out:
        _print_json(result)
        if result["status"] in ("blocked", "error"):
            raise typer.Exit(code=2)
        return

    if result["status"] == "blocked":
        typer.echo(result["detail"], err=True)
        raise typer.Exit(code=2)
    if result["status"] == "error":
        typer.echo(result["detail"], err=True)
        raise typer.Exit(code=1)
    if result["status"] == "none":
        console.print(f"[green]{email}[/green] — {result['detail']}")
        return

    console.print(f"[bold]{email}[/bold] — {result['detail']}")
    table = Table(title="Breaches")
    for column in ("Name", "Title", "Date", "Accounts", "Data classes"):
        table.add_column(column, overflow="fold")
    for item in result["breaches"]:
        table.add_row(
            item["name"] or "",
            item["title"] or "",
            item["date"] or "",
            f"{item['pwn_count']:,}" if item["pwn_count"] else "",
            ", ".join(item["data_classes"]),
        )
    console.print(table)


@app.command()
def pwned(
    ctx: typer.Context,
    password_env: Annotated[
        str | None,
        typer.Option(
            "--password-env",
            help="Read the password from this environment variable instead of prompting",
        ),
    ] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Check a password against Pwned Passwords (k-anonymity; nothing sensitive sent)."""
    settings = _settings(ctx)
    if password_env:
        password = os.environ.get(password_env)
        if not password:
            typer.echo(f"environment variable {password_env} is not set", err=True)
            raise typer.Exit(code=2)
    else:
        password = typer.prompt("Password", hide_input=True, confirmation_prompt=False)
    if not password:
        typer.echo("empty password", err=True)
        raise typer.Exit(code=2)

    async def run():
        async with Fetcher(settings) as fetcher:
            return await pwned_password(fetcher, password)

    try:
        result = asyncio.run(run())
    except FetchError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    if json_out:
        _print_json(result)
        raise typer.Exit(code=0 if result["status"] == "clean" else 1)

    if result["status"] == "error":
        typer.echo(result["detail"], err=True)
        raise typer.Exit(code=1)
    if result["status"] == "pwned":
        console.print(
            f"[red]exposed[/red] — this password appears {result['count']:,} time(s) "
            "in breach corpora. Change it everywhere it is reused."
        )
        raise typer.Exit(code=1)
    console.print("[green]clean[/green] — not found in the Pwned Passwords corpus.")
