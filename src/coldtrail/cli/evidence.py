"""Content-addressed evidence file commands."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table

from ..evidence import add_evidence, evidence_path, verify_evidence
from ..store import Store
from ._app import _print_json, _settings, app, console

evidence_app = typer.Typer(help="Content-addressed evidence files (hashes, dedupe, verify).")
app.add_typer(evidence_app, name="evidence", rich_help_panel="Evidence")


def _human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


@evidence_app.command("add", rich_help_panel="Evidence")
def evidence_add(
    ctx: typer.Context,
    file: Annotated[Path, typer.Argument(help="File to store as evidence")],
    run_id: Annotated[int | None, typer.Option("--run", help="Attach to this run")] = None,
    target_type: Annotated[
        str, typer.Option("--target-type", help="run|profile|entity|case|post")
    ] = "run",
    target: Annotated[str | None, typer.Option("--target", help="Target identifier")] = None,
    note: Annotated[str | None, typer.Option("--note", help="Analyst note")] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Store a file content-addressed and attach it to a run/target."""
    settings = _settings(ctx)
    if not file.is_file():
        typer.echo(f"not a file: {file}", err=True)
        raise typer.Exit(code=1)
    with Store(settings.db_path) as store:
        if run_id is not None and store.run(run_id) is None:
            typer.echo(f"run {run_id} not found", err=True)
            raise typer.Exit(code=1)
        payload = add_evidence(
            store,
            source_path=file,
            run_id=run_id,
            target_type=target_type,
            target=target,
            note=note,
        )
    if json_out:
        _print_json(payload)
        return
    console.print(
        f"stored evidence #{payload['id']} [dim]{payload['sha256'][:16]}…[/dim] "
        f"({_human_size(payload['size'])}) → {payload['path']}"
    )


@evidence_app.command("list", rich_help_panel="Evidence")
def evidence_list(
    ctx: typer.Context,
    run_id: Annotated[int | None, typer.Option("--run")] = None,
    target_type: Annotated[str | None, typer.Option("--target-type")] = None,
    target: Annotated[str | None, typer.Option("--target")] = None,
    limit: Annotated[int, typer.Option("-n", "--limit", min=1)] = 100,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List stored evidence attachments."""
    settings = _settings(ctx)
    with Store(settings.db_path) as store:
        rows = store.attachments(run_id=run_id, target_type=target_type, target=target, limit=limit)
    if json_out:
        _print_json(rows)
        return
    table = Table(title=f"Evidence ({len(rows)})")
    for column in ("ID", "Run", "File", "Size", "SHA-256", "Target", "Note", "Added"):
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(
            str(row["id"]),
            str(row["run_id"] or ""),
            row["filename"],
            _human_size(row["size"]),
            row["sha256"][:12],
            f"{row['target_type']}:{row['target'] or ''}",
            row["note"] or "",
            (row["created_at"] or "")[:19],
        )
    console.print(table)


@evidence_app.command("export", rich_help_panel="Evidence")
def evidence_export(
    ctx: typer.Context,
    attachment_id: Annotated[int, typer.Argument(help="Attachment ID")],
    out: Annotated[Path, typer.Option("-o", "--out", help="Destination path")],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Copy an evidence file out of the content-addressed store."""
    settings = _settings(ctx)
    with Store(settings.db_path) as store:
        row = store.attachment(attachment_id)
        if row is None:
            typer.echo(f"attachment {attachment_id} not found", err=True)
            raise typer.Exit(code=1)
        source = evidence_path(store, row["sha256"])
        if not source.is_file():
            typer.echo(f"evidence blob missing: {source}", err=True)
            raise typer.Exit(code=1)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(source.read_bytes())
    if json_out:
        _print_json({"id": attachment_id, "out": str(out), "size": out.stat().st_size})
        return
    console.print(f"wrote {out}")


@evidence_app.command("verify", rich_help_panel="Evidence")
def evidence_verify(
    ctx: typer.Context,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Verify every evidence blob exists and matches its recorded hash."""
    settings = _settings(ctx)
    with Store(settings.db_path) as store:
        problems = verify_evidence(store)
    if json_out:
        _print_json({"problems": problems})
    elif problems:
        for problem in problems:
            console.print(f"[red]#{problem['id']}[/red] {problem['problem']}")
    else:
        console.print("[green]all evidence blobs verified[/green]")
    if problems:
        raise typer.Exit(code=1)
