"""Shared web constants, template filters, and graph helpers.

Kept separate from the app factory so routers and tests can import them
without building the FastAPI application.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from ..report import (
    to_dot,
    to_gexf,
    to_graphml,
    to_json,
    to_jsonl,
    to_maltego_csv,
    to_stix,
)

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
MAX_JOB_EVENTS = 10_000
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
PUBLIC_PATHS = {"/healthz", "/api/health", "/login", "/logout"}
COOKIE_NAME = "coldtrail_token"

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


def _cookie_value(token: str) -> str:
    """Derive the browser cookie from the shared token.

    The cookie is an HMAC, never the bearer secret itself, so a cookie leak or
    browser sync does not expose the API token.
    """
    return hmac.new(token.encode("utf-8"), b"coldtrail-cookie-v1", hashlib.sha256).hexdigest()


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
    avatar_hash: bool | None = None


def _short(value: Any, width: int = 90) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= width else text[: width - 1] + "…"


def _ts(value: Any) -> str:
    text = str(value or "")
    return text.replace("T", " ")[:19]


def _safe_filename(value: str, fallback: str) -> str:
    """Keep user-controlled names out of Content-Disposition headers."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-")
    return (cleaned or fallback)[:80]


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
