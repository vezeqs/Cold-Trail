"""JSON API routes for the local web app."""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse

from .. import __version__
from ..config import Settings
from ..correlate import diff_runs
from ..sources import SOURCES
from ..store import Store
from .helpers import _build_graph_payload

log = logging.getLogger("coldtrail.web.api")


def register_api(app: FastAPI, settings: Settings) -> None:
    def _open() -> Store:
        return Store(settings.db_path)

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

    @app.get("/api/evidence/{attachment_id}")
    def api_evidence(attachment_id: int):
        with _open() as store:
            row = store.attachment(attachment_id)
        if row is None:
            raise HTTPException(status_code=404, detail="attachment not found")
        return row

    @app.get("/api/diff")
    def api_diff(
        a: Annotated[int, Query(ge=1)],
        b: Annotated[int, Query(ge=1)],
    ):
        with _open() as store:
            if store.run(a) is None or store.run(b) is None:
                raise HTTPException(status_code=404, detail="run not found")
            return diff_runs(store, a, b)

    @app.get("/healthz")
    @app.get("/api/health")
    def api_health():
        healthy = True
        detail = "ok"
        try:
            with _open() as store:
                store.conn.execute("SELECT 1").fetchone()
        except Exception:
            log.exception("health check failed")
            healthy = False
            detail = "database unavailable"
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
        scope: str = "posts",
        prefix: bool = False,
        source: str = "",
        username: str = "",
    ):
        scope = scope if scope in {"posts", "profiles", "entities", "all"} else "posts"
        with _open() as store:
            if scope == "profiles":
                results: Any = store.search_profiles(q, limit=limit)
            elif scope == "entities":
                results = store.search_entities(q, limit=limit)
            elif scope == "all":
                results = store.search_all(
                    q,
                    limit=limit,
                    prefix=prefix,
                    source=source or None,
                    username=username or None,
                )
            else:
                results = store.search(
                    q,
                    limit=limit,
                    prefix=prefix,
                    source=source or None,
                    username=username or None,
                )
        return {"query": q, "scope": scope, "results": results}

    @app.get("/api/sources")
    def api_sources(group: str = ""):
        items = sorted(SOURCES.values(), key=lambda source: source.name)
        if group:
            items = [source for source in items if source.group == group]
        with _open() as store:
            health = store.source_health_map()
        return [
            {
                "name": source.name,
                "label": source.label,
                "kind": source.kind,
                "group": source.group,
                "posts": source.supports_posts,
                "auth": source.requires_auth,
                "homepage": source.homepage,
                "health": health.get(source.name),
            }
            for source in items
        ]
