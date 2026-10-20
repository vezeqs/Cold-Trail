"""CLI entry points for the interactive interfaces: TUI and local web UI."""

from __future__ import annotations

import threading
import webbrowser
from typing import Annotated

import typer

from ._app import _settings, app, console

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


@app.command()
def tui(ctx: typer.Context) -> None:
    """Open the interactive terminal UI."""
    settings = _settings(ctx)
    try:
        from ..tui import run_tui
    except ImportError as exc:
        console.print(f"[red]TUI dependencies missing:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    run_tui(settings)


@app.command()
def serve(
    ctx: typer.Context,
    host: Annotated[str, typer.Option("--host", help="Bind address")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", min=1, max=65535, help="Bind port")] = 8765,
    open_browser: Annotated[
        bool, typer.Option("--open/--no-open", help="Open a browser window")
    ] = False,
    log_level: Annotated[str, typer.Option("--log-level")] = "info",
    token: Annotated[
        str | None,
        typer.Option("--token", help="Require this bearer token / login cookie"),
    ] = None,
) -> None:
    """Serve the local web UI (FastAPI + uvicorn)."""
    settings = _settings(ctx)
    if token:
        settings.web_token = token
    try:
        import uvicorn
    except ImportError as exc:
        console.print(f"[red]web dependencies missing:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    from ..web import create_app

    web_app = create_app(settings)
    url = f"http://{host}:{port}/"
    if host not in LOCAL_HOSTS:
        console.print(f"[yellow]warning:[/yellow] binding {host} exposes the UI beyond localhost")
    if settings.web_token:
        console.print("[bold]auth:[/bold] bearer token / login required")
    console.print(f"larpharvester web UI on [bold]{url}[/bold]  (Ctrl+C to stop)")
    console.print(f"[dim]database: {settings.db_path}[/dim]")
    if open_browser:
        threading.Timer(1.0, webbrowser.open, args=[url]).start()
    try:
        uvicorn.run(web_app, host=host, port=port, log_level=log_level)
    except KeyboardInterrupt:
        console.print("[dim]stopped[/dim]")
