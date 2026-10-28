"""Case-level aggregation shared by the CLI and web UI."""

from __future__ import annotations

from typing import Any

from .store import Store


def merge_case_payload(store: Store, case: dict[str, Any]) -> dict[str, Any]:
    """Merge every run in a case into one exportable dossier payload."""
    runs = case.get("runs") or []
    merged: dict[str, Any] = {
        "run": {
            "id": f"case:{case['name']}",
            "kind": "case",
            "target": case["name"],
            "started_at": runs[0]["started_at"] if runs else case["created_at"],
            "finished_at": runs[-1].get("finished_at") if runs else None,
            "status": "ok",
        },
        "checks": [],
        "profiles": [],
        "posts": [],
        "links": [],
        "clusters": [],
        "entities": [],
        "edges": [],
        "history": [],
        "attachments": [],
    }
    seen_profiles: set[tuple[str, str]] = set()
    seen_posts: set[tuple[str, str]] = set()
    seen_links: set[tuple[str, str, str, str]] = set()
    seen_clusters: set[str] = set()
    seen_entities: set[tuple[str, str, str, str]] = set()
    seen_edges: set[tuple[str, str, str, str]] = set()
    seen_attachments: set[str] = set()
    for run in runs:
        try:
            payload = store.export_run(run["id"])
        except KeyError:
            continue
        merged["checks"].extend(payload.get("checks") or [])
        merged["history"].extend(payload.get("history") or [])
        for profile in payload.get("profiles") or []:
            key = (profile["source"], profile["username"].casefold())
            if key not in seen_profiles:
                seen_profiles.add(key)
                merged["profiles"].append(profile)
        for post in payload.get("posts") or []:
            key = (post["source"], str(post["post_id"]))
            if key not in seen_posts:
                seen_posts.add(key)
                merged["posts"].append(post)
        for link in payload.get("links") or []:
            key = (
                link["source_a"],
                link["username_a"].casefold(),
                link["source_b"],
                link["username_b"].casefold(),
            )
            if key not in seen_links:
                seen_links.add(key)
                merged["links"].append(link)
        for cluster in payload.get("clusters") or []:
            key = str(cluster.get("cluster_key"))
            if key not in seen_clusters:
                seen_clusters.add(key)
                merged["clusters"].append(cluster)
        for entity in payload.get("entities") or []:
            key = (
                entity["source"],
                entity["username"].casefold(),
                entity["kind"],
                str(entity["value"]).casefold(),
            )
            if key not in seen_entities:
                seen_entities.add(key)
                merged["entities"].append(entity)
        for edge in payload.get("edges") or []:
            key = (
                edge["platform"],
                edge["actor"].casefold(),
                edge["target"].casefold(),
                edge.get("direction") or "follows",
            )
            if key not in seen_edges:
                seen_edges.add(key)
                merged["edges"].append(edge)
        for attachment in payload.get("attachments") or []:
            key = str(attachment["sha256"])
            if key not in seen_attachments:
                seen_attachments.add(key)
                merged["attachments"].append(attachment)
    return merged
