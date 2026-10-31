from __future__ import annotations

import asyncio
import contextlib
import json
import os
from typing import Annotated

import typer
from rich.table import Table

from ..http import Fetcher
from ..store import Store
from ..utils import redact_url_credentials
from ._app import _print_json, _settings, app, console

# -- ops --------------------------------------------------------------------


@app.command(rich_help_panel="Operations")
def config(
    ctx: typer.Context,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Show effective settings, their source, and redacted secrets."""
    settings = _settings(ctx)
    rows = settings.describe(ctx.meta.get("overrides") or {})
    config_mode = None
    if settings.config_path:
        with contextlib.suppress(OSError):
            config_mode = oct(os.stat(settings.config_path).st_mode & 0o777)
    payload = {
        "config_path": str(settings.config_path) if settings.config_path else None,
        "config_mode": config_mode,
        "settings": rows,
    }
    if json_out:
        _print_json(payload)
        return
    console.print(f"config file: {payload['config_path'] or '[none] (defaults + environment)'}")
    table = Table(title="Effective settings")
    for column in ("Key", "Value", "Source"):
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(row["key"], str(row["value"]), row["source"])
    console.print(table)


@app.command(rich_help_panel="Operations")
def audit(
    ctx: typer.Context,
    limit: Annotated[int, typer.Option("-n", "--limit", min=1)] = 100,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Show the command audit log."""
    with Store(_settings(ctx).db_path) as store:
        rows = store.audit(limit=limit)
    if json_out:
        _print_json(rows)
        return
    table = Table(title=f"Audit ({len(rows)})")
    for column in ("When", "Command", "Target"):
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(row["at"], row["command"], row["target"] or "")
    console.print(table)


@app.command(rich_help_panel="Operations")
def doctor(
    ctx: typer.Context,
    json_out: Annotated[bool, typer.Option("--json")] = False,
    offline: Annotated[
        bool, typer.Option("--offline", help="Skip the network reachability probe")
    ] = False,
) -> None:
    """Check database, privacy posture, network, keys, and source health."""
    settings = _settings(ctx)
    with Store(settings.db_path) as store:
        info = store.db_info()
        stats = store.stats()
        health = store.check_stats()

    online: bool | None = None
    if not offline:

        async def probe():
            try:
                async with Fetcher(settings) as fetcher:
                    response = await fetcher.get("https://api.github.com/zen")
                return response.status == 200
            except Exception:
                return False

        online = asyncio.run(probe())

    config_mode = None
    if settings.config_path:
        with contextlib.suppress(OSError):
            config_mode = oct(os.stat(settings.config_path).st_mode & 0o777)
    config_insecure = False
    if config_mode:
        with contextlib.suppress(ValueError):
            config_insecure = bool(int(config_mode, 8) & 0o077)
    proxy_display = redact_url_credentials(settings.proxy or ("tor" if settings.tor else None))
    privacy = {
        "telemetry": "none",
        "raw_retention": settings.keep_raw,
        "avatar_hash": settings.avatar_hash,
        "http_cache_ttl": settings.cache_ttl,
        "retention_days": settings.retention_days,
        "tor": settings.tor,
        "proxy": proxy_display,
        "web_token": bool(settings.web_token),
        "db_mode": info.get("mode"),
        "config_mode": config_mode,
        "config_mode_warning": config_insecure,
    }
    payload = {
        "db": info,
        "stats": stats,
        "online": online,
        "github_token": bool(settings.github_token),
        "hibp_key": bool(settings.hibp_api_key),
        "emailrep_key": bool(settings.emailrep_api_key),
        "shodan_key": bool(settings.shodan_api_key),
        "hunter_key": bool(settings.hunter_api_key),
        "x_token": bool(settings.x_bearer_token),
        "proxy": proxy_display,
        "config": str(settings.config_path) if settings.config_path else None,
        "privacy": privacy,
        "health": health,
    }
    if json_out:
        _print_json(payload)
        return
    console.print(f"database: {info['path']} ({info['size']} bytes, v{info['user_version']})")
    if online is None:
        console.print("network: [dim]skipped (--offline)[/dim]")
    else:
        console.print(f"network: {'[green]ok[/]' if online else '[red]unreachable[/]'}")
    console.print(f"GITHUB_TOKEN: {'set' if settings.github_token else 'unset'}")
    console.print(f"HIBP_API_KEY: {'set' if settings.hibp_api_key else 'unset'}")
    console.print(f"EMAILREP_API_KEY: {'set' if settings.emailrep_api_key else 'unset'}")
    console.print(f"SHODAN_API_KEY: {'set' if settings.shodan_api_key else 'unset'}")
    console.print(f"HUNTER_API_KEY: {'set' if settings.hunter_api_key else 'unset'}")
    console.print(f"X_BEARER_TOKEN: {'set' if settings.x_bearer_token else 'unset'}")
    console.print(
        f"privacy: telemetry=none raw={'on' if settings.keep_raw else 'off'} "
        f"avatar={'on' if settings.avatar_hash else 'off'} "
        f"cache_ttl={settings.cache_ttl}s retention={settings.retention_days or 'off'} "
        f"tor={'on' if settings.tor else 'off'} db_mode={privacy['db_mode'] or '?'}"
    )
    if config_insecure:
        console.print(
            f"[yellow]warning:[/yellow] {settings.config_path} is group/world-readable "
            f"({config_mode}); chmod 600 it if it contains API keys"
        )
    if health:
        table = Table(title="Source health")
        for column in ("Source", "Status", "Count"):
            table.add_column(column)
        for row in health:
            table.add_row(row["source"], row["status"], str(row["count"]))
        console.print(table)


@app.command(rich_help_panel="Output")
def schema(
    name: Annotated[str | None, typer.Argument(help="Schema name (omit to list)")] = None,
    list_schemas: Annotated[bool, typer.Option("--list", help="List schema names")] = False,
) -> None:
    """Emit JSON Schema for ColdTrail's --json payloads."""
    from ..schemas import SCHEMA_NAMES, SCHEMAS

    if list_schemas or not name:
        for key in SCHEMA_NAMES:
            typer.echo(key)
        return
    if name not in SCHEMAS:
        typer.echo(
            f"unknown schema {name!r}; choose from: {', '.join(SCHEMA_NAMES)}",
            err=True,
        )
        raise typer.Exit(code=2)
    typer.echo(json.dumps(SCHEMAS[name], indent=2))


@app.command(rich_help_panel="Operations")
def prune(
    ctx: typer.Context,
    days: Annotated[int, typer.Option("--days", min=1)] = 30,
    vacuum: Annotated[bool, typer.Option("--vacuum")] = False,
) -> None:
    """Delete runs and raw payloads older than N days."""
    with Store(_settings(ctx).db_path) as store:
        removed = store.prune(days)
        if vacuum:
            store.vacuum()
    console.print(f"pruned {removed} runs older than {days} days")


@app.command(rich_help_panel="Operations")
def db(
    ctx: typer.Context,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Show database information and row counts."""
    with Store(_settings(ctx).db_path) as store:
        payload = {"info": store.db_info(), "stats": store.stats()}
    if json_out:
        _print_json(payload)
        return
    console.print(f"path: {payload['info']['path']}")
    console.print(f"size: {payload['info']['size']} bytes")
    for table_name, count in payload["stats"].items():
        console.print(f"{table_name}: {count}")
