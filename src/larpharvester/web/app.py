"""Local web interface for larpharvester.

Design notes:
- Local-first: bind 127.0.0.1 by default, no auth layer needed; `--host`
  exposes it deliberately at the operator's risk.
- Reads open a short-lived SQLite connection per request (WAL mode makes
  concurrent readers cheap).
- Pivots are long-running, so POST /pivot creates a background job and
  redirects to a polling page instead of blocking the request. One pivot
  runs at a time (asyncio lock); further jobs queue.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from .. import __version__
from ..config import Settings
from ..pivot import persist_pivot
from ..pivot import pivot as run_pivot
from ..report import (
    redact_payload,
    to_csv,
    to_dot,
    to_gexf,
    to_graphml,
    to_html,
    to_json,
    to_jsonl,
)
from ..sources import GROUPS, SOURCES
from ..store import Store

log = logging.getLogger("larpharvester.web")

WEB_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = WEB_DIR / "templates"
STATIC_DIR = WEB_DIR / "static"

EXPORTERS = {
    "json": ("application/json", to_json),
    "jsonl": ("application/x-ndjson", to_jsonl),
    "csv": ("text/csv", None),
    "graphml": ("application/graphml+xml", to_graphml),
    "gexf": ("application/gexf+xml", to_gexf),
    "dot": ("text/vnd.graphviz", to_dot),
    "html": ("text/html", None),
}

MAX_JOBS = 200
JOB_RETENTION = 3600.0


@dataclass
class Job:
    id: str
    target: str
    status: str = "queued"  # queued | running | done | error
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    run_id: int | None = None
    result_count: int = 0
    error: str | None = None
    params: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "run_id": self.run_id,
            "result_count": self.result_count,
            "error": self.error,
        }


class PivotRequest(BaseModel):
    target: str = Field(min_length=1, max_length=320)
    sources: list[str] | None = None
    include_web: bool = False
    expand: bool = False
    variants: bool = False
    avatar_hash: bool = True


def _short(value: Any, width: int = 90) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= width else text[: width - 1] + "…"


def _ts(value: Any) -> str:
    text = str(value or "")
    return text.replace("T", " ")[:19]


def _safe_url(value: Any) -> str:
    """Only http(s) URLs may become links; harvested data is untrusted."""
    text = str(value or "").strip()
    return text if text.startswith(("http://", "https://")) else "#"


CSV_TABLES = {
    "run",
    "checks",
    "profiles",
    "posts",
    "links",
    "clusters",
    "entities",
    "edges",
    "history",
}


def _split_names(raw: str) -> list[str]:
    return [part for part in re.split(r"[,\s]+", raw.strip()) if part]


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.load()

    app = FastAPI(
        title="larpharvester",
        version=__version__,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.settings = settings
    app.state.jobs = {}
    app.state.tasks = set()
    app.state.pivot_lock = asyncio.Lock()

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    templates.env.filters["short"] = _short
    templates.env.filters["ts"] = _ts
    templates.env.filters["url"] = _safe_url
    templates.env.globals.update(
        version=__version__,
        groups=sorted(GROUPS),
        source_count=len(SOURCES),
    )

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    def _open() -> Store:
        return Store(settings.db_path)

    def _render(request: Request, name: str, context: dict[str, Any] | None = None):
        payload = {"settings": settings, **(context or {})}
        return templates.TemplateResponse(request, name, payload)

    # -- security headers ---------------------------------------------------

    @app.middleware("http")
    async def _headers(request: Request, call_next):
        started = time.perf_counter()
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data: https:; style-src 'self'; "
            "script-src 'self'; frame-ancestors 'none'",
        )
        elapsed = (time.perf_counter() - started) * 1000
        log.info("%s %s %s %.1fms", request.method, request.url.path, response.status_code, elapsed)
        return response

    # -- errors --------------------------------------------------------------

    @app.exception_handler(404)
    async def _not_found(request: Request, exc: HTTPException):
        if request.url.path.startswith("/api"):
            return JSONResponse({"detail": exc.detail or "not found"}, status_code=404)
        return templates.TemplateResponse(
            request, "404.html", {"settings": settings}, status_code=404
        )

    @app.exception_handler(500)
    async def _server_error(request: Request, exc: Exception):
        log.exception("unhandled error on %s", request.url.path)
        if request.url.path.startswith("/api"):
            return JSONResponse({"detail": "internal error"}, status_code=500)
        return templates.TemplateResponse(
            request, "500.html", {"settings": settings}, status_code=500
        )

    # -- pages ---------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        with _open() as store:
            stats = store.stats()
            runs = store.runs(limit=10)
            health = store.check_stats()
            info = store.db_info()
        found = sum(row["count"] for row in health if row["status"] == "found")
        errored = sum(row["count"] for row in health if row["status"] in ("error", "blocked"))
        return _render(
            request,
            "index.html",
            {
                "stats": stats,
                "runs": runs,
                "health": health,
                "info": info,
                "found": found,
                "errored": errored,
                "active": "dashboard",
            },
        )

    @app.get("/runs", response_class=HTMLResponse)
    def runs_page(
        request: Request,
        page: Annotated[int, Query(ge=1)] = 1,
        per_page: Annotated[int, Query(ge=1, le=200)] = 25,
    ):
        with _open() as store:
            total = store.count_runs()
            runs = store.runs(limit=per_page, offset=(page - 1) * per_page)
        pages = max(1, (total + per_page - 1) // per_page)
        return _render(
            request,
            "runs.html",
            {
                "runs": runs,
                "total": total,
                "page": page,
                "pages": pages,
                "per_page": per_page,
                "active": "runs",
            },
        )

    @app.get("/runs/{run_id}", response_class=HTMLResponse)
    def run_detail(request: Request, run_id: int):
        with _open() as store:
            run = store.run(run_id)
            if run is None:
                raise HTTPException(status_code=404, detail=f"run {run_id} not found")
            context = {
                "run": run,
                "checks": store.checks(run_id, limit=10_000),
                "profiles": store.profiles(run_id, limit=None),
                "posts": store.posts(run_id, limit=500),
                "links": store.links(run_id, limit=10_000),
                "clusters": store.clusters(run_id, limit=10_000),
                "entities": store.entities(run_id, limit=10_000),
                "edges": store.edges(run_id, limit=10_000),
                "history": store.history(run_id, limit=10_000),
            }
        coverage: dict[str, int] = {}
        for check in context["checks"]:
            coverage[check["status"]] = coverage.get(check["status"], 0) + 1
        context.update({"coverage": coverage, "active": "runs", "formats": sorted(EXPORTERS)})
        return _render(request, "run.html", context)

    @app.get("/runs/{run_id}/export")
    def run_export(
        run_id: int,
        format: Annotated[str, Query(pattern="^(json|jsonl|csv|graphml|gexf|dot|html)$")] = "json",
        table: Annotated[
            str,
            Query(pattern="^(run|checks|profiles|posts|links|clusters|entities|edges|history)$"),
        ] = "profiles",
        redact: bool = False,
    ):
        with _open() as store:
            try:
                payload = store.export_run(run_id)
            except KeyError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
        if redact:
            payload = redact_payload(payload)
        media_type, renderer = EXPORTERS[format]
        if format == "csv":
            body = to_csv(payload, table)
        elif format == "html":
            body = to_html(payload, redacted=redact)
        else:
            body = renderer(payload)
        filename = f"larpharvester-run{run_id}.{format}"
        return Response(
            content=body.encode(),
            media_type=media_type,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/search", response_class=HTMLResponse)
    def search_page(
        request: Request,
        q: str = "",
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ):
        rows: list[dict[str, Any]] = []
        error: str | None = None
        if q.strip():
            with _open() as store:
                try:
                    rows = store.search(q, limit=limit)
                except Exception as exc:  # FTS syntax problems must not 500
                    error = f"invalid query: {exc}"
        return _render(
            request,
            "search.html",
            {"q": q, "rows": rows, "limit": limit, "error": error, "active": "search"},
        )

    @app.get("/sources", response_class=HTMLResponse)
    def sources_page(request: Request, group: str = ""):
        items = sorted(SOURCES.values(), key=lambda source: source.name)
        if group:
            items = [source for source in items if source.group == group]
        return _render(
            request,
            "sources.html",
            {"items": items, "group": group, "active": "sources"},
        )

    @app.get("/cases", response_class=HTMLResponse)
    def cases_page(request: Request):
        with _open() as store:
            cases = store.cases()
            tags = store.tags()
            notes = store.notes()
        return _render(
            request,
            "cases.html",
            {"cases": cases, "tags": tags, "notes": notes, "active": "cases"},
        )

    @app.get("/pivot", response_class=HTMLResponse)
    def pivot_page(request: Request):
        return _render(request, "pivot.html", {"active": "pivot"})

    # -- pivot jobs ----------------------------------------------------------

    def _prune_jobs() -> None:
        now = time.time()
        stale = [
            job_id
            for job_id, job in app.state.jobs.items()
            if job.finished_at and now - job.finished_at > JOB_RETENTION
        ]
        for job_id in stale:
            app.state.jobs.pop(job_id, None)
        if len(app.state.jobs) > MAX_JOBS:
            finished = sorted(
                (job for job in app.state.jobs.values() if job.finished_at),
                key=lambda job: job.finished_at or 0,
            )
            for job in finished[: len(app.state.jobs) - MAX_JOBS]:
                app.state.jobs.pop(job.id, None)

    def _start_job(
        target: str,
        *,
        sources: list[str] | None,
        include_web: bool,
        expand: bool,
        variants: bool,
        avatar_hash: bool,
    ) -> Job:
        _prune_jobs()
        job = Job(
            id=uuid.uuid4().hex[:12],
            target=target,
            params={
                "sources": sources,
                "include_web": include_web,
                "expand": expand,
                "variants": variants,
                "avatar_hash": avatar_hash,
            },
        )
        app.state.jobs[job.id] = job

        async def _execute() -> None:
            async with app.state.pivot_lock:
                job.status = "running"
                job.started_at = time.time()
                store = Store(settings.db_path)
                try:
                    report = await run_pivot(
                        target,
                        settings=settings,
                        sources=sources,
                        expand=expand,
                        use_variants=variants,
                        include_web=include_web,
                        avatar_hash=avatar_hash,
                        store=store,
                    )
                    job.result_count = len(report.results)
                    job.run_id = persist_pivot(store, report)
                    job.status = "done"
                except Exception as exc:
                    log.exception("pivot job %s failed", job.id)
                    job.status = "error"
                    job.error = f"{type(exc).__name__}: {exc}"
                finally:
                    store.close()
                    job.finished_at = time.time()

        task = asyncio.create_task(_execute())
        app.state.tasks.add(task)
        task.add_done_callback(app.state.tasks.discard)
        return job

    @app.post("/pivot")
    async def pivot_submit(
        target: Annotated[str, Form(min_length=1, max_length=320)],
        scope: Annotated[str, Form(pattern="^(curated|web|custom)$")] = "curated",
        sources: Annotated[str, Form()] = "",
        expand: Annotated[bool, Form()] = False,
        variants: Annotated[bool, Form()] = False,
        avatar_hash: Annotated[bool, Form()] = True,
    ):
        names = _split_names(sources)
        include_web = scope == "web"
        if scope == "custom" and not names:
            raise HTTPException(status_code=400, detail="custom scope needs source names")
        if scope != "custom":
            names = None
        job = _start_job(
            target.strip(),
            sources=names,
            include_web=include_web,
            expand=expand,
            variants=variants,
            avatar_hash=avatar_hash,
        )
        return RedirectResponse(f"/jobs/{job.id}", status_code=303)

    @app.get("/jobs/{job_id}", response_class=HTMLResponse)
    def job_page(request: Request, job_id: str):
        job = app.state.jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found")
        return _render(request, "job.html", {"job": job, "active": "pivot"})

    @app.get("/api/jobs/{job_id}")
    def api_job(job_id: str):
        job = app.state.jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found")
        return job.as_dict()

    @app.post("/api/pivot", status_code=202)
    async def api_pivot(payload: PivotRequest):
        job = _start_job(
            payload.target.strip(),
            sources=payload.sources,
            include_web=payload.include_web,
            expand=payload.expand,
            variants=payload.variants,
            avatar_hash=payload.avatar_hash,
        )
        return {"job_id": job.id, "status": job.status}

    # -- JSON API ------------------------------------------------------------

    @app.get("/api/health")
    @app.get("/healthz")
    def api_health():
        healthy = True
        detail = "ok"
        try:
            with _open() as store:
                store.conn.execute("SELECT 1").fetchone()
        except Exception as exc:
            healthy = False
            detail = f"{type(exc).__name__}: {exc}"
        payload = {
            "status": "ok" if healthy else "error",
            "detail": detail,
            "version": __version__,
            "db": str(settings.db_path),
        }
        if not healthy:
            return JSONResponse(payload, status_code=503)
        return payload

    @app.get("/api/stats")
    def api_stats():
        with _open() as store:
            return {
                "stats": store.stats(),
                "db": store.db_info(),
                "health": store.check_stats(),
                "version": __version__,
            }

    @app.get("/api/runs")
    def api_runs(
        limit: Annotated[int, Query(ge=1, le=500)] = 25,
        offset: Annotated[int, Query(ge=0)] = 0,
    ):
        with _open() as store:
            return {"runs": store.runs(limit=limit, offset=offset), "total": store.count_runs()}

    @app.get("/api/runs/{run_id}")
    def api_run(run_id: int):
        with _open() as store:
            try:
                return store.export_run(run_id)
            except KeyError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/search")
    def api_search(
        q: Annotated[str, Query(min_length=1)],
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ):
        with _open() as store:
            return {"query": q, "results": store.search(q, limit=limit)}

    @app.get("/api/sources")
    def api_sources(group: str = ""):
        items = sorted(SOURCES.values(), key=lambda source: source.name)
        if group:
            items = [source for source in items if source.group == group]
        return [
            {
                "name": source.name,
                "label": source.label,
                "kind": source.kind,
                "group": source.group,
                "posts": source.supports_posts,
                "auth": source.requires_auth,
                "homepage": source.homepage,
            }
            for source in items
        ]

    return app
