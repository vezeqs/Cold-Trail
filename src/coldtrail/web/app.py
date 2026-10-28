"""Local web interface for ColdTrail.

Design notes:
- Local-first: bind 127.0.0.1 by default, no auth layer needed; `--host`
  exposes it deliberately at the operator's risk.
- Reads open a short-lived SQLite connection per request (WAL mode makes
  concurrent readers cheap).
- Pivots are long-running, so POST /pivot creates a background job and
  redirects to a live streaming page (/jobs/{id}) backed by Server-Sent
  Events (/api/jobs/{id}/stream) and polling fallback (/api/jobs/{id}).
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import re
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from .. import __version__
from ..analysis import entities_from_posts
from ..breach import full_breach_audit, pwned_password
from ..casework import merge_case_payload
from ..config import Settings
from ..correlate import diff_runs, recluster_rows
from ..domain import asn_lookup, lookup_domain, ptr, rdap_ip, reverse_ip, shodan_host
from ..dorks import dorks as build_dorks
from ..dorks import reverse_image_links
from ..evidence import evidence_path
from ..harvest import collect_follows
from ..harvest import harvest as run_harvest
from ..http import Fetcher
from ..integrations import (
    ToolError,
    ToolUnavailable,
    ingest_file,
    list_tools,
    persist_ingest,
    persist_tool_result,
    run_tool,
)
from ..models import CheckResult
from ..phone import lookup as phone_lookup
from ..pivot import entities_for_profiles, persist_pivot
from ..pivot import pivot as run_pivot
from ..report import (
    iter_csv,
    iter_jsonl,
    redact_payload,
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
from ..sources import GROUPS, SOURCES
from ..store import Store
from ..wayback import cdx

log = logging.getLogger("coldtrail.web")

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
    "md": ("text/markdown", None),
    "stix": ("application/stix+json", to_stix),
    "maltego": ("text/csv", to_maltego_csv),
}

MAX_JOBS = 200
JOB_RETENTION = 3600.0
RATE_LIMIT = 20
RATE_WINDOW = 60.0
LOGIN_RATE_LIMIT = 10
LOGIN_RATE_WINDOW = 300.0
RATE_CLIENTS = 2048
MAX_UPLOAD = 50 * 1024 * 1024
UPLOAD_CHUNK = 1024 * 1024
SSE_HEARTBEAT = 15.0
SSE_MAX_SECONDS = 3600.0
PUBLIC_PATHS = {"/healthz", "/api/health", "/login"}


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
    found_count: int = 0
    error: str | None = None
    params: dict[str, Any] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)

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
            "found_count": self.found_count,
            "error": self.error,
            "events": self.events[-100:],
        }


class PivotRequest(BaseModel):
    target: str = Field(min_length=1, max_length=320)
    sources: list[str] | None = None
    include_web: bool = False
    expand: bool = False
    depth: int = Field(default=1, ge=1, le=5)
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


def _filesize(value: Any) -> str:
    size = float(value or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{int(value or 0)} B"


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
    "attachments",
}


def _split_names(raw: str) -> list[str]:
    return [part for part in re.split(r"[,\s]+", raw.strip()) if part]


def _build_graph_payload(
    profiles: list[dict[str, Any]],
    links: list[dict[str, Any]],
    clusters: list[dict[str, Any]],
    entities: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a JSON graph structure (nodes + edges) for the interactive canvas."""
    cluster_of: dict[str, str] = {}
    for cluster in clusters:
        ckey = str(cluster.get("cluster_key") or "")
        for member in cluster.get("members") or []:
            cluster_of[f"{member['source']}:{member['username']}"] = ckey

    nodes: list[dict[str, Any]] = []
    seen_nodes: set[str] = set()
    for p in profiles:
        nid = f"{p['source']}:{p['username']}"
        if nid in seen_nodes:
            continue
        seen_nodes.add(nid)
        nodes.append(
            {
                "id": nid,
                "label": p.get("display_name") or p["username"],
                "username": p["username"],
                "source": p["source"],
                "kind": "profile",
                "cluster": cluster_of.get(nid, ""),
                "url": _safe_url(p.get("url")),
                "bio": (p.get("bio") or "")[:160],
                "followers": p.get("followers"),
            }
        )

    graph_edges: list[dict[str, Any]] = []
    for link in links:
        sa = f"{link['source_a']}:{link['username_a']}"
        sb = f"{link['source_b']}:{link['username_b']}"
        graph_edges.append(
            {
                "source": sa,
                "target": sb,
                "kind": "correlation",
                "score": float(link.get("score") or 0.5),
                "label": ", ".join(link.get("reasons") or []),
            }
        )

    for ent in entities[:80]:
        eid = f"entity:{ent['kind']}:{ent['value']}"
        owner = f"{ent['source']}:{ent['username']}"
        if eid not in seen_nodes:
            seen_nodes.add(eid)
            nodes.append(
                {
                    "id": eid,
                    "label": f"{ent['kind']}: {ent['value']}",
                    "username": ent["value"],
                    "source": ent["kind"],
                    "kind": "entity",
                    "cluster": "",
                    "url": "#",
                    "bio": ent.get("context") or "",
                    "followers": None,
                }
            )
        if owner in seen_nodes:
            graph_edges.append(
                {
                    "source": owner,
                    "target": eid,
                    "kind": "entity",
                    "score": 0.8,
                    "label": ent["kind"],
                }
            )

    for edge in edges[:120]:
        actor_id = f"{edge['platform']}:{edge['actor']}"
        target_id = f"{edge['platform']}:{edge['target']}"
        for nid, uname in ((actor_id, edge["actor"]), (target_id, edge["target"])):
            if nid not in seen_nodes:
                seen_nodes.add(nid)
                nodes.append(
                    {
                        "id": nid,
                        "label": uname,
                        "username": uname,
                        "source": edge["platform"],
                        "kind": "follow",
                        "cluster": "",
                        "url": "#",
                        "bio": "",
                        "followers": None,
                    }
                )
        graph_edges.append(
            {
                "source": actor_id,
                "target": target_id,
                "kind": "follow",
                "score": 0.4,
                "label": edge.get("direction", "follows"),
            }
        )

    return {"nodes": nodes, "edges": graph_edges}


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.load()

    app = FastAPI(
        title="ColdTrail",
        version=__version__,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.settings = settings
    app.state.jobs = {}
    app.state.tasks = set()
    app.state.pivot_lock = asyncio.Lock()
    app.state.rate = {}

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    templates.env.filters["short"] = _short
    templates.env.filters["ts"] = _ts
    templates.env.filters["url"] = _safe_url
    templates.env.filters["filesize"] = _filesize
    templates.env.globals.update(
        version=__version__,
        groups=sorted(GROUPS),
        curated_groups=[group for group in GROUPS if group != "web"],
        source_count=len(SOURCES),
    )

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    def _open() -> Store:
        return Store(settings.db_path)

    def _render(
        request: Request,
        name: str,
        context: dict[str, Any] | None = None,
        status_code: int = 200,
    ):
        payload = {"settings": settings, **(context or {})}
        return templates.TemplateResponse(request, name, payload, status_code=status_code)

    def _client_key(request: Request) -> str:
        """Rate-limit key. X-Forwarded-For is only trusted when explicitly configured."""
        if settings.trust_proxy:
            forwarded = request.headers.get("x-forwarded-for", "")
            if forwarded:
                return forwarded.split(",", 1)[0].strip() or "unknown"
        return request.client.host if request.client else "local"

    def _rate_limited(
        request: Request,
        *,
        limit: int = RATE_LIMIT,
        window: float = RATE_WINDOW,
        bucket: str = "default",
    ) -> bool:
        """Bounded per-client sliding-window limiter for expensive endpoints."""
        now = time.time()
        rate = app.state.rate
        if len(rate) > RATE_CLIENTS:
            for key, stamps in list(rate.items()):
                if not stamps or now - stamps[-1] > max(window, RATE_WINDOW):
                    rate.pop(key, None)
            if len(rate) > RATE_CLIENTS:
                for key in list(rate)[: len(rate) - RATE_CLIENTS]:
                    rate.pop(key, None)
        key = f"{bucket}:{_client_key(request)}"
        stamps = [stamp for stamp in rate.get(key, []) if now - stamp < window]
        if len(stamps) >= limit:
            rate[key] = stamps
            return True
        stamps.append(now)
        rate[key] = stamps
        return False

    async def _read_upload(file: UploadFile) -> bytes:
        """Read an upload in bounded chunks so oversized files never reach RAM."""
        declared = getattr(file, "size", None)
        if declared is not None and declared > MAX_UPLOAD:
            raise HTTPException(status_code=413, detail="upload exceeds 50 MB")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = await file.read(UPLOAD_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_UPLOAD:
                raise HTTPException(status_code=413, detail="upload exceeds 50 MB")
            chunks.append(chunk)
        return b"".join(chunks)

    def _export_response(
        payload: dict[str, Any],
        fmt: str,
        table: str,
        redact: bool,
        filename: str,
    ) -> Response:
        if redact:
            payload = redact_payload(payload)
        media_type, renderer = EXPORTERS[fmt]
        headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
        if fmt == "jsonl":
            return StreamingResponse(
                (line + "\n" for line in iter_jsonl(payload)),
                media_type=media_type,
                headers=headers,
            )
        if fmt == "csv":
            return StreamingResponse(
                iter_csv(payload, table), media_type=media_type, headers=headers
            )
        if fmt == "html":
            body = to_html(payload, redacted=redact)
        elif fmt == "md":
            body = to_markdown(payload, redacted=redact)
        else:
            body = renderer(payload)
        return Response(content=body.encode(), media_type=media_type, headers=headers)

    # -- optional auth ------------------------------------------------------

    @app.middleware("http")
    async def _auth(request: Request, call_next):
        token = settings.web_token
        if not token:
            return await call_next(request)
        path = request.url.path
        if path in PUBLIC_PATHS or path.startswith("/static"):
            return await call_next(request)
        supplied = ""
        authorization = request.headers.get("authorization", "")
        if authorization.lower().startswith("bearer "):
            supplied = authorization[7:].strip()
        elif request.headers.get("x-api-key"):
            supplied = request.headers["x-api-key"].strip()
        elif request.cookies.get("coldtrail_token"):
            supplied = request.cookies["coldtrail_token"]
        if supplied and hmac.compare_digest(supplied, token):
            return await call_next(request)
        if path.startswith("/api"):
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
        return RedirectResponse("/login", status_code=303)

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request):
        return _render(request, "login.html", {"error": None, "active": "login"})

    @app.post("/login", response_class=HTMLResponse)
    async def login_submit(request: Request, token: Annotated[str, Form()] = ""):
        if _rate_limited(request, limit=LOGIN_RATE_LIMIT, window=LOGIN_RATE_WINDOW, bucket="login"):
            return _render(
                request,
                "login.html",
                {"error": "too many attempts; try again later", "active": "login"},
                status_code=429,
            )
        expected = settings.web_token or ""
        if expected and hmac.compare_digest(token.strip(), expected):
            response = RedirectResponse("/", status_code=303)
            response.set_cookie(
                "coldtrail_token",
                token.strip(),
                httponly=True,
                samesite="strict",
                secure=request.url.scheme == "https",
                path="/",
                max_age=86_400,
            )
            return response
        return _render(
            request,
            "login.html",
            {"error": "invalid token", "active": "login"},
            status_code=401,
        )

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
            "script-src 'self'; connect-src 'self'; frame-ancestors 'none'",
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
                "attachments": store.attachments(run_id=run_id, limit=10_000),
                "cases": store.cases(),
            }
        coverage: dict[str, int] = {}
        for check in context["checks"]:
            coverage[check["status"]] = coverage.get(check["status"], 0) + 1
        context.update({"coverage": coverage, "active": "runs", "formats": sorted(EXPORTERS)})
        return _render(request, "run.html", context)

    @app.get("/api/runs/{run_id}/graph")
    def api_run_graph(run_id: int):
        with _open() as store:
            run = store.run(run_id)
            if run is None:
                raise HTTPException(status_code=404, detail=f"run {run_id} not found")
            return _build_graph_payload(
                store.profiles(run_id, limit=None),
                store.links(run_id, limit=10_000),
                store.clusters(run_id, limit=10_000),
                store.entities(run_id, limit=10_000),
                store.edges(run_id, limit=10_000),
            )

    @app.get("/runs/{run_id}/export")
    def run_export(
        run_id: int,
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
            try:
                payload = store.export_run(run_id)
            except KeyError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
        return _export_response(payload, format, table, redact, f"coldtrail-run{run_id}.{format}")

    @app.get("/evidence/{attachment_id}")
    def evidence_download(attachment_id: int):
        with _open() as store:
            row = store.attachment(attachment_id)
            if row is None:
                raise HTTPException(status_code=404, detail="attachment not found")
            path = evidence_path(store, row["sha256"])
        if not path.is_file():
            raise HTTPException(status_code=404, detail="evidence blob missing")
        return FileResponse(
            path,
            media_type=row.get("media_type") or "application/octet-stream",
            filename=row["filename"],
        )

    @app.get("/api/evidence/{attachment_id}")
    def api_evidence(attachment_id: int):
        with _open() as store:
            row = store.attachment(attachment_id)
        if row is None:
            raise HTTPException(status_code=404, detail="attachment not found")
        return row

    @app.get("/diff", response_class=HTMLResponse)
    def diff_page(
        request: Request,
        a: Annotated[int | None, Query(ge=1)] = None,
        b: Annotated[int | None, Query(ge=1)] = None,
    ):
        payload = None
        with _open() as store:
            runs = store.runs(limit=100)
            if a is not None and b is not None:
                if store.run(a) is None or store.run(b) is None:
                    raise HTTPException(status_code=404, detail="run not found")
                payload = diff_runs(store, a, b)
        return _render(
            request,
            "diff.html",
            {"runs": runs, "payload": payload, "a": a, "b": b, "active": "diff"},
        )

    @app.get("/api/diff")
    def api_diff(
        a: Annotated[int, Query(ge=1)],
        b: Annotated[int, Query(ge=1)],
    ):
        with _open() as store:
            if store.run(a) is None or store.run(b) is None:
                raise HTTPException(status_code=404, detail="run not found")
            return diff_runs(store, a, b)

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

    # -- cases, tags, notes CRUD --------------------------------------------

    @app.get("/cases", response_class=HTMLResponse)
    def cases_page(request: Request):
        with _open() as store:
            cases = store.cases()
            tags = store.tags()
            notes = store.notes()
            runs = store.runs(limit=100)
        return _render(
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
        return _render(
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
        return _export_response(payload, format, table, redact, f"coldtrail-case-{name}.{format}")

    # -- OSINT tools workbench ----------------------------------------------

    @app.get("/tools", response_class=HTMLResponse)
    def tools_page(request: Request):
        post_sources = sorted(
            name for name, src in SOURCES.items() if src.kind == "username" and src.supports_posts
        )
        return _render(
            request,
            "tools.html",
            {
                "post_sources": post_sources,
                "external_tools": list_tools(),
                "result": None,
                "tool": None,
                "active": "tools",
            },
        )

    def _tools_context(**extra: Any) -> dict[str, Any]:
        post_sources = sorted(
            name for name, src in SOURCES.items() if src.kind == "username" and src.supports_posts
        )
        return {
            "post_sources": post_sources,
            "external_tools": list_tools(),
            "result": None,
            "tool": None,
            "active": "tools",
            **extra,
        }

    @app.post("/tools/external", response_class=HTMLResponse)
    async def tools_external(
        request: Request,
        tool: Annotated[str, Form(min_length=1)],
        target: Annotated[str, Form(min_length=1)],
        save: Annotated[bool, Form()] = False,
    ):
        if _rate_limited(request):
            raise HTTPException(status_code=429, detail="rate limit exceeded")
        error: str | None = None
        payload: dict[str, Any] | None = None
        try:
            result = await asyncio.to_thread(run_tool, tool, target)
            run_id = None
            if save:
                with _open() as store:
                    run_id = persist_tool_result(store, result)
            payload = {
                "tool": tool,
                "target": target,
                "summary": result.summary,
                "run_id": run_id,
                "profiles": [asdict(profile) for profile in result.profiles[:50]],
                "entities": [asdict(entity) for entity in result.entities[:100]],
            }
        except (ToolUnavailable, ToolError) as exc:
            error = str(exc)
        return _render(
            request,
            "tools.html",
            _tools_context(
                external_result=payload,
                external_error=error,
                external_tool=tool,
                external_target=target,
            ),
        )

    @app.post("/tools/ingest", response_class=HTMLResponse)
    async def tools_ingest(
        request: Request,
        file: Annotated[UploadFile, File()],
        format: Annotated[str, Form()] = "auto",
        save: Annotated[bool, Form()] = False,
    ):
        if _rate_limited(request):
            raise HTTPException(status_code=429, detail="rate limit exceeded")
        error: str | None = None
        payload: dict[str, Any] | None = None
        data = await _read_upload(file)
        suffix = Path(file.filename or "import.json").suffix
        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as handle:
                handle.write(data)
                temp_path = Path(handle.name)
            chosen, parsed, raw = ingest_file(temp_path, format)
            run_id = None
            if save:
                with _open() as store:
                    run_id = persist_ingest(
                        store,
                        str(file.filename or temp_path.name),
                        chosen,
                        parsed,
                        raw,
                    )
            payload = {
                "format": chosen,
                "summary": parsed.summary,
                "run_id": run_id,
                "profiles": [asdict(profile) for profile in parsed.profiles[:50]],
                "entities": [asdict(entity) for entity in parsed.entities[:100]],
            }
        except ToolError as exc:
            error = str(exc)
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
        return _render(
            request,
            "tools.html",
            _tools_context(ingest_result=payload, ingest_error=error),
        )

    @app.post("/tools/run", response_class=HTMLResponse)
    async def tools_run(
        request: Request,
        tool: Annotated[
            str,
            Form(pattern="^(domain|ip|phone|dorks|archive|breach|pwned|harvest|graph|recluster)$"),
        ],
        target: Annotated[str, Form()] = "",
        source: Annotated[str, Form()] = "github",
        limit: Annotated[int, Form(ge=1, le=500)] = 25,
        deep: Annotated[bool, Form()] = False,
    ):
        post_sources = sorted(
            name for name, src in SOURCES.items() if src.kind == "username" and src.supports_posts
        )
        if _rate_limited(request):
            raise HTTPException(status_code=429, detail="rate limit exceeded")
        cleaned = target.strip()
        result: Any = None
        run_id: int | None = None

        if tool == "domain":
            async with Fetcher(settings) as fetcher:
                result = await lookup_domain(fetcher, cleaned, deep=deep)
        elif tool == "ip":
            async with Fetcher(settings) as fetcher:
                result = {
                    "address": cleaned,
                    "ptr": await ptr(fetcher, cleaned),
                    "hostnames": await reverse_ip(fetcher, cleaned, settings.shodan_api_key),
                    "asn": await asn_lookup(fetcher, cleaned),
                    "rdap": await rdap_ip(fetcher, cleaned),
                    "shodan": await shodan_host(fetcher, cleaned, settings.shodan_api_key),
                }
        elif tool == "phone":
            result = phone_lookup(cleaned) or {"error": "invalid or unparseable phone number"}
        elif tool == "dorks":
            rows = build_dorks(cleaned)
            if cleaned.startswith(("http://", "https://")):
                rows.extend(reverse_image_links(cleaned))
            result = rows
        elif tool == "archive":
            async with Fetcher(settings) as fetcher:
                result = await cdx(fetcher, cleaned, limit=limit)
        elif tool == "breach":
            async with Fetcher(settings) as fetcher:
                result = await full_breach_audit(fetcher, cleaned)
        elif tool == "pwned":
            async with Fetcher(settings) as fetcher:
                result = await pwned_password(fetcher, target)
        elif tool == "harvest":
            if source not in SOURCES or SOURCES[source].kind != "username":
                raise HTTPException(status_code=400, detail=f"invalid source {source!r}")
            with _open() as store:
                check, posts = await run_harvest(
                    source, cleaned, settings=settings, limit=limit, store=store
                )
                run_id = store.start_run("harvest", f"{source}:{cleaned}")
                store.save_checks(run_id, [check])
                if check.profile:
                    store.save_profiles(run_id, [check.profile])
                    store.record_profile_history(run_id, [check.profile])
                    store.save_entities(run_id, entities_for_profiles([check.profile]))
                store.save_posts(run_id, posts)
                store.save_entities(run_id, entities_from_posts(posts))
                store.finish_run(run_id)
                result = {
                    "run_id": run_id,
                    "check": asdict(check),
                    "post_count": len(posts),
                    "posts": [asdict(p) for p in posts[:50]],
                }
        elif tool == "graph":
            if source not in SOURCES or SOURCES[source].kind != "username":
                raise HTTPException(status_code=400, detail=f"invalid source {source!r}")
            with _open() as store:
                check, edges = await collect_follows(
                    source, cleaned, settings=settings, limit=limit, store=store
                )
                run_id = store.start_run("graph", f"{source}:{cleaned}")
                store.save_checks(run_id, [check])
                if check.profile:
                    store.save_profiles(run_id, [check.profile])
                store.save_edges(run_id, edges)
                store.finish_run(run_id)
                result = {
                    "run_id": run_id,
                    "check": asdict(check),
                    "edge_count": len(edges),
                    "edges": [asdict(e) for e in edges[:100]],
                }
        elif tool == "recluster":
            with _open() as store:
                rows = store.profiles(limit=None)
            links, clusters = recluster_rows(rows)
            result = {
                "profiles": len(rows),
                "link_count": len(links),
                "cluster_count": len(clusters),
                "clusters": [asdict(c) for c in clusters],
                "links": [asdict(link) for link in links[:100]],
            }

        return _render(
            request,
            "tools.html",
            {
                "post_sources": post_sources,
                "external_tools": list_tools(),
                "tool": tool,
                "target": cleaned if tool != "pwned" else "",
                "result": result,
                "result_json": json.dumps(result, indent=2, ensure_ascii=False, default=str),
                "run_id": run_id,
                "active": "tools",
            },
        )

    @app.get("/pivot", response_class=HTMLResponse)
    def pivot_page(request: Request):
        return _render(request, "pivot.html", {"active": "pivot"})

    @app.get("/help", response_class=HTMLResponse)
    def help_page(request: Request):
        return _render(request, "help.html", {"active": "help"})

    # -- pivot jobs & SSE streaming -----------------------------------------

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
        depth: int = 1,
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
                "depth": depth,
                "variants": variants,
                "avatar_hash": avatar_hash,
            },
        )
        app.state.jobs[job.id] = job

        def _on_result(res: CheckResult) -> None:
            job.result_count += 1
            if res.status == "found":
                job.found_count += 1
            job.events.append(
                {
                    "source": res.source,
                    "target": res.target,
                    "status": res.status,
                    "username": res.profile.username if res.profile else "",
                    "url": _safe_url(res.profile.url) if res.profile else "",
                    "detail": res.detail or "",
                }
            )

        async def _execute() -> None:
            async with app.state.pivot_lock:
                job.status = "running"
                job.started_at = time.time()
                store: Store | None = None
                try:
                    store = Store(settings.db_path)
                    report = await run_pivot(
                        target,
                        settings=settings,
                        sources=sources,
                        expand=expand,
                        depth=depth,
                        use_variants=variants,
                        include_web=include_web,
                        avatar_hash=avatar_hash,
                        store=store,
                        on_result=_on_result,
                    )
                    job.result_count = len(report.results)
                    job.found_count = report.coverage.get("found", 0)
                    job.run_id = persist_pivot(store, report)
                    job.status = "done"
                except Exception as exc:
                    log.exception("pivot job %s failed", job.id)
                    job.status = "error"
                    job.error = f"{type(exc).__name__}: {exc}"
                finally:
                    if store is not None:
                        store.close()
                    job.finished_at = time.time()

        task = asyncio.create_task(_execute())
        app.state.tasks.add(task)
        task.add_done_callback(app.state.tasks.discard)
        return job

    @app.post("/pivot")
    async def pivot_submit(
        request: Request,
        target: Annotated[str, Form(min_length=1, max_length=320)],
        scope: Annotated[str, Form(pattern="^(curated|web|custom)$")] = "curated",
        sources: Annotated[str, Form()] = "",
        expand: Annotated[bool, Form()] = False,
        depth: Annotated[int, Form(ge=1, le=5)] = 1,
        variants: Annotated[bool, Form()] = False,
        avatar_hash: Annotated[bool, Form()] = False,
    ):
        if _rate_limited(request):
            raise HTTPException(status_code=429, detail="rate limit exceeded")
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
            depth=depth,
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

    @app.get("/api/jobs/{job_id}/stream")
    async def api_job_stream(job_id: str):
        job = app.state.jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found")

        async def _event_gen():
            cursor = 0
            started = time.monotonic()
            last_beat = started
            while True:
                while cursor < len(job.events):
                    ev = job.events[cursor]
                    cursor += 1
                    yield f"event: check\ndata: {json.dumps(ev)}\n\n"
                if job.status in ("done", "error"):
                    summary = {
                        "status": job.status,
                        "run_id": job.run_id,
                        "result_count": job.result_count,
                        "found_count": job.found_count,
                        "error": job.error,
                    }
                    yield f"event: done\ndata: {json.dumps(summary)}\n\n"
                    break
                if time.monotonic() - started > SSE_MAX_SECONDS:
                    summary = {
                        "status": "error",
                        "run_id": job.run_id,
                        "result_count": job.result_count,
                        "found_count": job.found_count,
                        "error": "stream timed out before the job finished",
                    }
                    yield f"event: done\ndata: {json.dumps(summary)}\n\n"
                    break
                now = time.monotonic()
                if now - last_beat >= SSE_HEARTBEAT:
                    last_beat = now
                    yield ": keep-alive\n\n"
                await asyncio.sleep(0.15)

        return StreamingResponse(
            _event_gen(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    @app.post("/api/pivot", status_code=202)
    async def api_pivot(payload: PivotRequest, request: Request):
        if _rate_limited(request):
            raise HTTPException(status_code=429, detail="rate limit exceeded")
        job = _start_job(
            payload.target.strip(),
            sources=payload.sources,
            include_web=payload.include_web,
            expand=payload.expand,
            depth=payload.depth,
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
