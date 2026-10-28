from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Annotated, Any

import typer

from ..report import (
    decrypt_bytes,
    encrypt_bytes,
    redact_payload,
    to_csv,
    to_dot,
    to_gexf,
    to_graphml,
    to_html,
    to_json,
    to_jsonl,
    to_maltego_csv,
    to_markdown,
    to_stix,
)
from ..sites import slugify
from ..store import Store
from ._app import _settings, app, console

# -- export / report --------------------------------------------------------


@app.command("export", rich_help_panel="Output")
def export_cmd(
    ctx: typer.Context,
    run_id: Annotated[int, typer.Argument(help="Run ID")],
    format: Annotated[
        str,
        typer.Option("--format", help="json|jsonl|csv|graphml|gexf|dot|html|md|stix|maltego"),
    ] = "json",
    table: Annotated[str, typer.Option("--table", help="CSV table")] = "profiles",
    out: Annotated[Path | None, typer.Option("-o", "--out")] = None,
    redact: Annotated[bool, typer.Option("--redact")] = False,
    encrypt: Annotated[bool, typer.Option("--encrypt")] = False,
    passphrase_env: Annotated[str, typer.Option("--passphrase-env")] = "COLDTRAIL_PASSPHRASE",
) -> None:
    """Export a run as JSON/JSONL/CSV/GraphML/GEXF/DOT/HTML."""
    settings = _settings(ctx)
    with Store(settings.db_path) as store:
        try:
            payload = store.export_run(run_id)
        except KeyError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=1) from exc
    if redact:
        payload = redact_payload(payload)
    text = _render_format(payload, format, table, redacted=redact)
    data = text.encode()
    if encrypt:
        passphrase = os.environ.get(passphrase_env)
        if not passphrase:
            typer.echo(f"passphrase not set in {passphrase_env}", err=True)
            raise typer.Exit(code=2)
        data = encrypt_bytes(data, passphrase)
    if out is None:
        sys.stdout.buffer.write(data)
        if not data.endswith(b"\n"):
            sys.stdout.buffer.write(b"\n")
        return
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    console.print(f"wrote {out}")


@app.command(rich_help_panel="Output")
def report(
    ctx: typer.Context,
    run_id: Annotated[int, typer.Argument(help="Run ID")],
    out: Annotated[Path | None, typer.Option("-o", "--out")] = None,
    redact: Annotated[bool, typer.Option("--redact")] = False,
) -> None:
    """Render a self-contained HTML dossier."""
    settings = _settings(ctx)
    with Store(settings.db_path) as store:
        try:
            payload = store.export_run(run_id)
        except KeyError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=1) from exc
    if redact:
        payload = redact_payload(payload)
    target = (payload.get("run") or {}).get("target", "run")
    destination = out or Path(f"dossier-{run_id}-{slugify(str(target))}.html")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(to_html(payload, redacted=redact), encoding="utf-8")
    console.print(f"wrote {destination}")


def _render_format(payload: dict[str, Any], fmt: str, table: str, redacted: bool = False) -> str:
    fmt = fmt.casefold()
    if fmt == "json":
        return to_json(payload)
    if fmt == "jsonl":
        return to_jsonl(payload)
    if fmt == "csv":
        return to_csv(payload, table)
    if fmt == "graphml":
        return to_graphml(payload)
    if fmt == "gexf":
        return to_gexf(payload)
    if fmt == "dot":
        return to_dot(payload)
    if fmt == "html":
        return to_html(payload, redacted=redacted)
    if fmt in ("md", "markdown"):
        return to_markdown(payload, redacted=redacted)
    if fmt == "stix":
        return to_stix(payload)
    if fmt == "maltego":
        return to_maltego_csv(payload)
    raise typer.BadParameter(f"unknown format {fmt!r}")


@app.command(rich_help_panel="Output")
def decrypt(
    input_file: Annotated[Path, typer.Argument()],
    output_file: Annotated[Path, typer.Argument()],
    passphrase_env: Annotated[str, typer.Option("--passphrase-env")] = "COLDTRAIL_PASSPHRASE",
) -> None:
    """Decrypt an encrypted export."""
    passphrase = os.environ.get(passphrase_env)
    if not passphrase:
        typer.echo(f"passphrase not set in {passphrase_env}", err=True)
        raise typer.Exit(code=2)
    try:
        data = decrypt_bytes(input_file.read_bytes(), passphrase)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_bytes(data)
    console.print(f"wrote {output_file}")
