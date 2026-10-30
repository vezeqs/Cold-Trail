"""Case, tag, and note routes for the local web app."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..casework import merge_case_payload
from ..config import Settings
from ..store import Store
from .helpers import EXPORTERS, _safe_filename


def register_cases(app: FastAPI, settings: Settings, render: Any, export_response: Any) -> None:
    def _open() -> Store:
        return Store(settings.db_path)

    @app.get("/cases", response_class=HTMLResponse)
    def cases_page(request: Request):
        with _open() as store:
            cases = store.cases()
            tags = store.tags()
            notes = store.notes()
            runs = store.runs(limit=100)
        return render(
            request,
            "cases.html",
            {"cases": cases, "tags": tags, "notes": notes, "runs": runs, "active": "cases"},
        )

    @app.post("/cases/new")
    async def cases_new(
        name: Annotated[str, Form(min_length=1, max_length=120)],
        notes: Annotated[str, Form()] = "",
    ):
        with _open() as store:
            try:
                store.create_case(name.strip(), notes.strip() or None)
            except Exception as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        return RedirectResponse("/cases", status_code=303)

    @app.post("/cases/add-run")
    async def cases_add_run(
        case_name: Annotated[str, Form(min_length=1)],
        run_id: Annotated[int, Form(ge=1)],
    ):
        with _open() as store:
            case = store.case(case_name.strip())
            if case is None:
                raise HTTPException(status_code=404, detail=f"no such case: {case_name}")
            store.add_to_case(case["id"], run_id)
        return RedirectResponse("/cases", status_code=303)

    @app.post("/tags/new")
    async def tags_new(
        target_type: Annotated[str, Form(pattern="^(profile|post|run|entity|case)$")],
        target: Annotated[str, Form(min_length=1, max_length=200)],
        tag: Annotated[str, Form(min_length=1, max_length=80)],
    ):
        with _open() as store:
            store.add_tag(target_type, target.strip(), tag.strip())
        return RedirectResponse("/cases", status_code=303)

    @app.post("/notes/new")
    async def notes_new(
        target_type: Annotated[str, Form(pattern="^(profile|post|run|entity|case)$")],
        target: Annotated[str, Form(min_length=1, max_length=200)],
        note: Annotated[str, Form(min_length=1, max_length=2000)],
    ):
        with _open() as store:
            store.add_note(target_type, target.strip(), note.strip())
        return RedirectResponse("/cases", status_code=303)

    @app.get("/cases/{name}", response_class=HTMLResponse)
    def case_detail(request: Request, name: str):
        with _open() as store:
            case = store.case(name)
            if case is None:
                raise HTTPException(status_code=404, detail=f"no such case: {name}")
            run_ids = [run["id"] for run in case["runs"]]
            profiles: dict[tuple[str, str], dict[str, Any]] = {}
            clusters: list[dict[str, Any]] = []
            entities: list[dict[str, Any]] = []
            for run_id in run_ids:
                for profile in store.profiles(run_id=run_id, limit=None):
                    profiles.setdefault((profile["source"], profile["username"]), profile)
                clusters.extend(store.clusters(run_id=run_id, limit=10_000))
                entities.extend(store.entities(run_id=run_id, limit=10_000))
            targets = {name} | {f"{s}:{u}" for s, u in profiles}
            tags = [tag for tag in store.tags() if tag["target"] in targets]
            notes = [note for note in store.notes() if note["target"] in targets]
            attachments: list[dict[str, Any]] = []
            seen_attachments: set[str] = set()
            for run_id in run_ids:
                for attachment in store.attachments(run_id=run_id, limit=10_000):
                    if attachment["sha256"] not in seen_attachments:
                        seen_attachments.add(attachment["sha256"])
                        attachments.append(attachment)
        return render(
            request,
            "case_detail.html",
            {
                "case": case,
                "profiles": list(profiles.values()),
                "clusters": clusters,
                "entities": entities[:500],
                "tags": tags,
                "notes": notes,
                "attachments": attachments,
                "formats": sorted(EXPORTERS),
                "active": "cases",
            },
        )

    @app.get("/cases/{name}/export")
    def case_export(
        name: str,
        format: Annotated[
            str, Query(pattern="^(json|jsonl|csv|graphml|gexf|dot|html|md|stix|maltego)$")
        ] = "json",
        table: Annotated[
            str,
            Query(
                pattern="^(run|checks|profiles|posts|links|clusters|entities|edges|history|attachments)$"
            ),
        ] = "profiles",
        redact: bool = False,
    ):
        with _open() as store:
            case = store.case(name)
            if case is None:
                raise HTTPException(status_code=404, detail=f"no such case: {name}")
            payload = merge_case_payload(store, case)
        return export_response(
            payload,
            format,
            table,
            redact,
            f"coldtrail-case-{_safe_filename(name, 'case')}.{format}",
        )
