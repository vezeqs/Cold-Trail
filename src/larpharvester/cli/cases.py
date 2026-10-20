from __future__ import annotations

from typing import Annotated

import typer
from rich.table import Table

from ..store import Store
from ._app import _print_json, _settings, app, case_app, console

# -- cases, tags, notes -----------------------------------------------------


@case_app.command("new")
def case_new(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument()],
    notes: Annotated[str | None, typer.Option("--notes")] = None,
) -> None:
    """Create a case."""
    with Store(_settings(ctx).db_path) as store:
        try:
            case_id = store.create_case(name, notes)
        except Exception as exc:
            typer.echo(f"could not create case: {exc}", err=True)
            raise typer.Exit(code=1) from exc
    console.print(f"created case #{case_id} {name}")


@case_app.command("list")
def case_list(
    ctx: typer.Context,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List cases."""
    with Store(_settings(ctx).db_path) as store:
        rows = store.cases()
    if json_out:
        _print_json(rows)
        return
    table = Table(title=f"Cases ({len(rows)})")
    for column in ("ID", "Name", "Runs", "Created", "Notes"):
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(
            str(row["id"]),
            row["name"],
            str(row["runs"]),
            row["created_at"],
            row["notes"] or "",
        )
    console.print(table)


@case_app.command("add")
def case_add(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument()],
    run_id: Annotated[int, typer.Argument()],
) -> None:
    """Attach a run to a case."""
    with Store(_settings(ctx).db_path) as store:
        case = store.case(name)
        if case is None:
            typer.echo(f"no such case: {name}", err=True)
            raise typer.Exit(code=1)
        store.add_to_case(case["id"], run_id)
    console.print(f"attached run #{run_id} to {name}")


@case_app.command("show")
def case_show(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument()],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Show a case and its runs."""
    with Store(_settings(ctx).db_path) as store:
        case = store.case(name)
    if case is None:
        typer.echo(f"no such case: {name}", err=True)
        raise typer.Exit(code=1)
    if json_out:
        _print_json(case)
        return
    console.print(f"[bold]{case['name']}[/bold] — {len(case['runs'])} runs")
    for run in case["runs"]:
        console.print(f"  #{run['id']} {run['kind']} {run['target']} ({run['status']})")


@app.command()
def tag(
    ctx: typer.Context,
    target_type: Annotated[str, typer.Argument(help="profile|post|run|entity")],
    target: Annotated[str, typer.Argument(help="Identifier")],
    tag_value: Annotated[str, typer.Argument()],
) -> None:
    """Attach a tag to an object."""
    with Store(_settings(ctx).db_path) as store:
        store.add_tag(target_type, target, tag_value)
    console.print(f"tagged {target_type}:{target} with {tag_value}")


@app.command()
def tags(
    ctx: typer.Context,
    target_type: Annotated[str | None, typer.Option("--type")] = None,
    target: Annotated[str | None, typer.Option("--target")] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List tags."""
    with Store(_settings(ctx).db_path) as store:
        rows = store.tags(target_type, target)
    if json_out:
        _print_json(rows)
        return
    table = Table(title=f"Tags ({len(rows)})")
    for column in ("Type", "Target", "Tag"):
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(row["target_type"], row["target"], row["tag"])
    console.print(table)


@app.command()
def note(
    ctx: typer.Context,
    target_type: Annotated[str, typer.Argument(help="profile|run|entity|case")],
    target: Annotated[str, typer.Argument()],
    text: Annotated[str, typer.Argument()],
) -> None:
    """Attach a note to an object."""
    with Store(_settings(ctx).db_path) as store:
        store.add_note(target_type, target, text)
    console.print("note added")


@app.command()
def notes(
    ctx: typer.Context,
    target_type: Annotated[str | None, typer.Option("--type")] = None,
    target: Annotated[str | None, typer.Option("--target")] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List notes."""
    with Store(_settings(ctx).db_path) as store:
        rows = store.notes(target_type, target)
    if json_out:
        _print_json(rows)
        return
    table = Table(title=f"Notes ({len(rows)})")
    for column in ("Type", "Target", "Note", "Created"):
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(row["target_type"], row["target"], row["note"], row["created_at"])
    console.print(table)
