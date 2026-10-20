from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import uuid
from typing import Any
from xml.sax.saxutils import escape

from cryptography.fernet import Fernet, InvalidToken

from .correlate import calibrate_probability
from .dorks import dorks
from .utils import short_key

MAGIC = b"LPH1"
PBKDF2_ROUNDS = 200_000


def redact(value: str | None) -> str | None:
    if not value:
        return value
    return f"redacted-{short_key(value, 10)}"


def redact_payload(payload: dict[str, Any]) -> dict[str, Any]:
    data = json.loads(json.dumps(payload, default=str))
    if data.get("run"):
        data["run"]["target"] = redact(data["run"].get("target"))
    for check in data.get("checks", []):
        check["target"] = redact(check.get("target"))
    for profile in data.get("profiles", []):
        profile["username"] = redact(profile.get("username"))
        profile["display_name"] = redact(profile.get("display_name"))
        profile["url"] = redact(profile.get("url"))
        profile["avatar"] = redact(profile.get("avatar"))
        profile["website"] = redact(profile.get("website"))
        profile["bio"] = None
        profile["extra"] = {}
    for post in data.get("posts", []):
        post["username"] = redact(post.get("username"))
        post["url"] = redact(post.get("url"))
        post["text"] = None
    for entity in data.get("entities", []):
        entity["value"] = redact(entity.get("value"))
        entity["username"] = redact(entity.get("username"))
        entity["context"] = None
    for link in data.get("links", []):
        link["username_a"] = redact(link.get("username_a"))
        link["username_b"] = redact(link.get("username_b"))
    for cluster in data.get("clusters", []):
        if cluster.get("cluster_key"):
            cluster["cluster_key"] = redact(cluster.get("cluster_key"))
        for member in cluster.get("members", []):
            member["username"] = redact(member.get("username"))
    for edge in data.get("edges", []):
        edge["actor"] = redact(edge.get("actor"))
        edge["target"] = redact(edge.get("target"))
    for hist in data.get("history", []):
        hist["username"] = redact(hist.get("username"))
        hist["old_value"] = redact(hist.get("old_value")) if hist.get("old_value") else None
        hist["new_value"] = redact(hist.get("new_value")) if hist.get("new_value") else None
    return data


def to_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str)


def iter_jsonl(payload: dict[str, Any]):
    """Yield JSONL records one at a time (streaming-friendly for large runs)."""
    if payload.get("run"):
        yield json.dumps({"type": "run", **payload["run"]}, ensure_ascii=False, default=str)
    for check in payload.get("checks", []):
        yield json.dumps({"type": "check", **check}, ensure_ascii=False, default=str)
    for profile in payload.get("profiles", []):
        yield json.dumps({"type": "profile", **profile}, ensure_ascii=False, default=str)
    for post in payload.get("posts", []):
        yield json.dumps({"type": "post", **post}, ensure_ascii=False, default=str)
    for entity in payload.get("entities", []):
        yield json.dumps({"type": "entity", **entity}, ensure_ascii=False, default=str)
    for link in payload.get("links", []):
        yield json.dumps({"type": "link", **link}, ensure_ascii=False, default=str)
    for cluster in payload.get("clusters", []):
        yield json.dumps({"type": "cluster", **cluster}, ensure_ascii=False, default=str)
    for edge in payload.get("edges", []):
        yield json.dumps({"type": "edge", **edge}, ensure_ascii=False, default=str)
    for change in payload.get("history", []):
        yield json.dumps({"type": "history", **change}, ensure_ascii=False, default=str)


def to_jsonl(payload: dict[str, Any]) -> str:
    return "\n".join(iter_jsonl(payload))


def iter_csv(payload: dict[str, Any], table: str = "profiles"):
    """Yield a CSV header then one row at a time."""
    rows = payload.get(table) or []
    if not rows:
        return
    flat_rows = []
    for row in rows:
        flat = {}
        for key, value in row.items():
            if isinstance(value, (dict, list)):
                flat[key] = json.dumps(value, ensure_ascii=False, default=str)
            else:
                flat[key] = value
        flat_rows.append(flat)
    fieldnames = list(dict.fromkeys(key for row in flat_rows for key in row))
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    yield buffer.getvalue()
    for row in flat_rows:
        buffer.seek(0)
        buffer.truncate(0)
        writer.writerow(row)
        yield buffer.getvalue()


def to_csv(payload: dict[str, Any], table: str = "profiles") -> str:
    return "".join(iter_csv(payload, table))


def _node_id(profile: dict[str, Any]) -> str:
    return f"{profile['source']}:{profile['username']}"


def to_graphml(payload: dict[str, Any]) -> str:
    nodes = payload.get("profiles", [])
    links = payload.get("links", [])
    cluster_of = {}
    for cluster in payload.get("clusters", []):
        for member in cluster.get("members", []):
            cluster_of[f"{member['source']}:{member['username']}"] = cluster.get("cluster_key")

    out = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
        '<key id="label" for="node" attr.name="label" attr.type="string"/>',
        '<key id="source" for="node" attr.name="source" attr.type="string"/>',
        '<key id="url" for="node" attr.name="url" attr.type="string"/>',
        '<key id="cluster" for="node" attr.name="cluster" attr.type="string"/>',
        '<key id="score" for="edge" attr.name="score" attr.type="double"/>',
        '<key id="reasons" for="edge" attr.name="reasons" attr.type="string"/>',
        '<graph edgedefault="undirected">',
    ]
    for profile in nodes:
        node = _node_id(profile)
        label = escape(str(profile.get("display_name") or profile["username"]))
        out.append(f'<node id="{escape(node)}">')
        out.append(f'<data key="label">{label}</data>')
        out.append(f'<data key="source">{escape(str(profile.get("source")))}</data>')
        out.append(f'<data key="url">{escape(str(profile.get("url") or ""))}</data>')
        out.append(f'<data key="cluster">{escape(str(cluster_of.get(node, "")))}</data>')
        out.append("</node>")
    for link in links:
        source = f"{link['source_a']}:{link['username_a']}"
        target = f"{link['source_b']}:{link['username_b']}"
        out.append(f'<edge source="{escape(source)}" target="{escape(target)}">')
        out.append(f'<data key="score">{float(link.get("score") or 0)}</data>')
        out.append(f'<data key="reasons">{escape(", ".join(link.get("reasons") or []))}</data>')
        out.append("</edge>")
    out.append("</graph></graphml>")
    return "\n".join(out)


def to_gexf(payload: dict[str, Any]) -> str:
    nodes = payload.get("profiles", [])
    links = payload.get("links", [])
    out = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<gexf xmlns="http://gexf.net/1.3" version="1.3">',
        '<graph mode="static" defaultedgetype="undirected">',
        "<nodes>",
    ]
    for profile in nodes:
        node = _node_id(profile)
        label = str(profile.get("display_name") or profile["username"])
        out.append(f'<node id="{escape(node)}" label="{escape(label)}"/>')
    out.append("</nodes><edges>")
    for index, link in enumerate(links):
        source = f"{link['source_a']}:{link['username_a']}"
        target = f"{link['source_b']}:{link['username_b']}"
        weight = float(link.get("score") or 0)
        out.append(
            f'<edge id="{index}" source="{escape(source)}" '
            f'target="{escape(target)}" weight="{weight}"/>'
        )
    out.append("</edges></graph></gexf>")
    return "\n".join(out)


def _dot_escape(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def to_dot(payload: dict[str, Any]) -> str:
    out = ["graph larpharvester {", "  node [shape=box];"]
    for profile in payload.get("profiles", []):
        node = _node_id(profile)
        label = f"{profile['source']}:{profile.get('display_name') or profile['username']}"
        out.append(f'  "{_dot_escape(node)}" [label="{_dot_escape(label)}"];')
    for link in payload.get("links", []):
        source = f"{link['source_a']}:{link['username_a']}"
        target = f"{link['source_b']}:{link['username_b']}"
        out.append(
            f'  "{_dot_escape(source)}" -- "{_dot_escape(target)}" '
            f'[label="{link.get("score")}", weight={link.get("score")}];'
        )
    out.append("}")
    return "\n".join(out)


def to_markdown(payload: dict[str, Any], redacted: bool = False) -> str:
    run = payload.get("run") or {}
    target = run.get("target") or payload.get("target") or "unknown"
    profiles = payload.get("profiles") or []
    links = payload.get("links") or []
    clusters = payload.get("clusters") or []
    entities = payload.get("entities") or []
    posts = payload.get("posts") or []
    checks = payload.get("checks") or []

    counts: dict[str, int] = {}
    for check in checks:
        counts[check.get("status", "?")] = counts.get(check.get("status", "?"), 0) + 1
    cov_str = ", ".join(f"{k}: {v}" for k, v in sorted(counts.items()))

    lines = [
        f"# OSINT Dossier: `{target}`",
        "",
        f"- **Run ID:** {run.get('id', 'n/a')}",
        f"- **Kind:** {run.get('kind', 'pivot')}",
        f"- **Started:** {run.get('started_at', '')}",
        f"- **Coverage:** {cov_str or 'n/a'}",
        f"- **Redacted:** {'yes' if redacted else 'no'}",
        "",
    ]
    if clusters:
        lines.extend(["## Inferred Identity Clusters", ""])
        lines.append("| Cluster | Size | Confidence | Members | Reasons |")
        lines.append("| --- | --- | --- | --- | --- |")
        for cluster in clusters:
            members = ", ".join(
                f"`{m['source']}:{m['username']}`" for m in cluster.get("members", [])
            )
            reasons = ", ".join(cluster.get("reasons") or [])
            lines.append(
                f"| `{cluster.get('cluster_key', '')}` | {cluster.get('size', 0)} "
                f"| {float(cluster.get('score') or 0):.2f} | {members} | {reasons} |"
            )
        lines.append("")

    if profiles:
        lines.extend(["## Profiles", ""])
        lines.append("| Source | Username | Display Name | Followers | URL |")
        lines.append("| --- | --- | --- | --- | --- |")
        for p in profiles:
            followers = p.get("followers") if p.get("followers") is not None else ""
            lines.append(
                f"| {p.get('source', '')} | `{p.get('username', '')}` "
                f"| {p.get('display_name') or ''} | {followers} | {p.get('url') or ''} |"
            )
        lines.append("")

    if links:
        lines.extend(["## Correlated Pairs", ""])
        lines.append("| Account A | Account B | Score | Confidence | Reasons |")
        lines.append("| --- | --- | --- | --- | --- |")
        for row in links:
            score = float(row.get("score") or 0)
            lines.append(
                f"| `{row.get('source_a')}:{row.get('username_a')}` "
                f"| `{row.get('source_b')}:{row.get('username_b')}` "
                f"| {score:.2f} | {calibrate_probability(score):.2f} "
                f"| {', '.join(row.get('reasons') or [])} |"
            )
        lines.append("")

    if entities:
        lines.extend(["## Extracted Entities", ""])
        lines.append("| Kind | Value | Observed On |")
        lines.append("| --- | --- | --- |")
        for e in entities:
            lines.append(
                f"| {e.get('kind', '')} | `{e.get('value', '')}` "
                f"| `{e.get('source')}:{e.get('username')}` |"
            )
        lines.append("")

    if posts:
        lines.extend(["## Recent Posts", ""])
        for p in sorted(posts, key=lambda item: item.get("created_at") or "")[:50]:
            when = str(p.get("created_at") or "")[:19]
            txt = " ".join(str(p.get("text") or "").split())[:200]
            lines.append(f"- **{when}** `{p.get('source')}:{p.get('username')}` — {txt}")
        lines.append("")

    return "\n".join(lines)


def _stix_id(kind: str, seed: str) -> str:
    ns = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
    return f"{kind}--{uuid.uuid5(ns, f'larpharvester:{kind}:{seed}')}"


def to_stix(payload: dict[str, Any]) -> str:
    """Export a run as a STIX 2.1 JSON bundle (user-account, identity, relationship)."""
    run = payload.get("run") or {}
    started = run.get("started_at") or "2025-01-01T00:00:00Z"
    if not started.endswith("Z") and "+" not in started:
        started = started + "Z"

    objects: list[dict[str, Any]] = []
    acct_ids: dict[str, str] = {}

    for profile in payload.get("profiles") or []:
        node = _node_id(profile)
        oid = _stix_id("user-account", node)
        acct_ids[node] = oid
        objects.append(
            {
                "type": "user-account",
                "spec_version": "2.1",
                "id": oid,
                "user_id": profile.get("username"),
                "account_login": profile.get("username"),
                "account_type": profile.get("source"),
                "display_name": profile.get("display_name") or profile.get("username"),
                "extensions": {
                    "x-larpharvester": {
                        "url": profile.get("url"),
                        "bio": profile.get("bio"),
                        "avatar_hash": profile.get("avatar_hash"),
                        "followers": profile.get("followers"),
                    }
                },
            }
        )

    for cluster in payload.get("clusters") or []:
        ckey = str(cluster.get("cluster_key") or "cluster")
        ident_id = _stix_id("identity", ckey)
        objects.append(
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": ident_id,
                "created": started,
                "modified": started,
                "name": f"cluster:{ckey}",
                "identity_class": "individual",
                "confidence": int(round(float(cluster.get("score") or 0) * 100)),
                "description": ", ".join(cluster.get("reasons") or []),
            }
        )
        for member in cluster.get("members") or []:
            mkey = f"{member['source']}:{member['username']}"
            if mkey in acct_ids:
                rel_id = _stix_id("relationship", f"{ident_id}->{acct_ids[mkey]}")
                objects.append(
                    {
                        "type": "relationship",
                        "spec_version": "2.1",
                        "id": rel_id,
                        "created": started,
                        "modified": started,
                        "relationship_type": "attributed-to",
                        "source_ref": acct_ids[mkey],
                        "target_ref": ident_id,
                    }
                )

    for link in payload.get("links") or []:
        sa = f"{link['source_a']}:{link['username_a']}"
        sb = f"{link['source_b']}:{link['username_b']}"
        if sa in acct_ids and sb in acct_ids:
            rel_id = _stix_id("relationship", f"{sa}<->{sb}")
            objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": rel_id,
                    "created": started,
                    "modified": started,
                    "relationship_type": "related-to",
                    "description": ", ".join(link.get("reasons") or []),
                    "confidence": int(round(float(link.get("score") or 0) * 100)),
                    "source_ref": acct_ids[sa],
                    "target_ref": acct_ids[sb],
                }
            )

    bundle = {
        "type": "bundle",
        "id": _stix_id("bundle", str(run.get("id") or "0")),
        "objects": objects,
    }
    return json.dumps(bundle, indent=2, ensure_ascii=False, default=str)


def to_maltego_csv(payload: dict[str, Any]) -> str:
    """Export links and entity observations as a Maltego-importable edge table."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    header = ["SourceType", "SourceValue", "Relation", "TargetType", "TargetValue", "Weight"]
    writer.writerow(header)
    for link in payload.get("links") or []:
        writer.writerow(
            [
                "maltego.Alias",
                f"{link['source_a']}:{link['username_a']}",
                ", ".join(link.get("reasons") or []) or "correlated",
                "maltego.Alias",
                f"{link['source_b']}:{link['username_b']}",
                link.get("score", 0.5),
            ]
        )
    for ent in payload.get("entities") or []:
        writer.writerow(
            [
                "maltego.Alias",
                f"{ent.get('source')}:{ent.get('username')}",
                f"mentions:{ent.get('kind')}",
                f"maltego.{ent.get('kind')}",
                ent.get("value"),
                0.8,
            ]
        )
    for edge in payload.get("edges") or []:
        writer.writerow(
            [
                "maltego.Alias",
                f"{edge.get('platform')}:{edge.get('actor')}",
                edge.get("direction", "follows"),
                "maltego.Alias",
                f"{edge.get('platform')}:{edge.get('target')}",
                0.5,
            ]
        )
    return buffer.getvalue()


def to_html(payload: dict[str, Any], redacted: bool = False) -> str:
    run = payload.get("run") or {}
    target = run.get("target") or payload.get("target") or "unknown"
    profiles = payload.get("profiles") or []
    links = payload.get("links") or []
    clusters = payload.get("clusters") or []
    entities = payload.get("entities") or []
    posts = payload.get("posts") or []
    history = payload.get("history") or []
    checks = payload.get("checks") or []
    counts: dict[str, int] = {}
    for check in checks:
        counts[check.get("status", "?")] = counts.get(check.get("status", "?"), 0) + 1

    def table(headers: list[str], rows: list[list[str]]) -> str:
        head = "".join(f"<th>{escape(h)}</th>" for h in headers)
        body = "".join(
            "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows
        )
        return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"

    def link(url: str, text: str | None = None) -> str:
        if not url:
            return ""
        safe = escape(url, {'"': "&quot;", "'": "&#x27;"})
        if safe.casefold().startswith(("javascript:", "data:", "vbscript:")):
            return escape(url)
        return f'<a href="{safe}" rel="noreferrer">{escape(text or url)}</a>'

    cluster_rows = [
        [
            escape(str(cluster.get("cluster_key", ""))),
            str(cluster.get("size", len(cluster.get("members", [])))),
            f"{float(cluster.get('score') or 0):.2f}",
            escape(", ".join(f"{m['source']}:{m['username']}" for m in cluster.get("members", []))),
            escape(", ".join(cluster.get("reasons") or [])),
        ]
        for cluster in clusters
    ]
    profile_rows = [
        [
            escape(str(p.get("source", ""))),
            escape(str(p.get("username", ""))),
            escape(str(p.get("display_name") or "")),
            escape(str(p.get("bio") or ""))[:280],
            str(p.get("followers") if p.get("followers") is not None else ""),
            link(str(p.get("url") or "")),
        ]
        for p in profiles
    ]
    link_rows = [
        [
            f"{escape(str(row.get('source_a')))}:{escape(str(row.get('username_a')))}",
            f"{escape(str(row.get('source_b')))}:{escape(str(row.get('username_b')))}",
            f"{float(row.get('score') or 0):.2f}",
            f"{calibrate_probability(float(row.get('score') or 0)):.2f}",
            escape(", ".join(row.get("reasons") or [])),
        ]
        for row in links
    ]
    entity_rows = [
        [
            escape(str(e.get("kind", ""))),
            escape(str(e.get("value", ""))),
            escape(f"{e.get('source')}:{e.get('username')}"),
            escape(str(e.get("context") or ""))[:200],
        ]
        for e in entities
    ]
    post_rows = [
        [
            escape(str(p.get("created_at") or "")[:19]),
            escape(str(p.get("source", ""))),
            escape(str(p.get("username", ""))),
            escape(str(p.get("text") or ""))[:400],
            link(str(p.get("url") or "")),
        ]
        for p in sorted(posts, key=lambda item: item.get("created_at") or "")
    ]
    history_rows = [
        [
            escape(f"{h.get('source')}:{h.get('username')}"),
            escape(str(h.get("field", ""))),
            escape(str(h.get("old_value") or ""))[:120],
            escape(str(h.get("new_value") or ""))[:120],
            escape(str(h.get("observed_at") or "")),
        ]
        for h in history
    ]
    check_rows = [
        [
            escape(str(c.get("source", ""))),
            escape(str(c.get("target", ""))),
            escape(str(c.get("status", ""))),
            escape(str(c.get("detail") or "")),
        ]
        for c in checks
    ]
    dork_rows = (
        []
        if redacted
        else [
            [escape(row["engine"]), escape(row["query"]), link(row["url"], "open")]
            for row in dorks(target)
        ]
    )

    coverage = " ".join(
        f'<span class="badge">{escape(status)}: {count}</span>'
        for status, count in sorted(counts.items())
    )
    sections = [
        ("Clusters", table(["Cluster", "Size", "Confidence", "Members", "Reasons"], cluster_rows)),
        (
            "Profiles",
            table(["Source", "Username", "Name", "Bio", "Followers", "URL"], profile_rows),
        ),
        ("Correlation links", table(["A", "B", "Score", "Confidence", "Reasons"], link_rows)),
        ("Entities", table(["Kind", "Value", "Observed on", "Context"], entity_rows)),
        ("Timeline", table(["When", "Source", "Username", "Text", "URL"], post_rows)),
        ("Profile changes", table(["Target", "Field", "Old", "New", "Observed"], history_rows)),
        ("Source checks", table(["Source", "Target", "Status", "Detail"], check_rows)),
        ("Search dorks", table(["Engine", "Query", "Open"], dork_rows)),
    ]
    empty = '<p class="muted">none</p>'
    body = "\n".join(
        f"<section><h2>{escape(title)}</h2>{content or empty}</section>"
        for title, content in sections
    )
    redacted_note = " &middot; <strong>redacted</strong>" if redacted else ""
    meta_line = (
        f"run {escape(str(run.get('id', 'n/a')))} &middot; "
        f"{escape(str(run.get('kind', '')))} &middot; "
        f"started {escape(str(run.get('started_at', '')))}{redacted_note}"
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>larpharvester dossier: {escape(target)}</title>
<style>
:root {{ color-scheme: dark; }}
body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 0; padding: 2rem;
        background:#0e1116; color:#d7dde7; }}
h1 {{ margin:0 0 .25rem; font-size:1.6rem; }}
h2 {{ margin:0 0 .75rem; font-size:1.05rem; color:#9ecbff; }}
section {{ margin: 1.75rem 0; }}
table {{ border-collapse: collapse; width:100%; font-size:.85rem; }}
th, td {{ text-align:left; padding:.45rem .6rem; border-bottom:1px solid #232a36;
          vertical-align:top; }}
th {{ color:#8b97a8; font-weight:600; text-transform:uppercase; font-size:.7rem;
      letter-spacing:.05em; }}
a {{ color:#7cc4ff; word-break:break-all; }}
.badge {{ display:inline-block; padding:.2rem .55rem; border-radius:999px;
          background:#1b2432; border:1px solid #2a3648; margin-right:.4rem; font-size:.75rem; }}
.muted {{ color:#6c7889; }}
.meta {{ color:#8b97a8; font-size:.85rem; }}
</style></head><body>
<h1>Dossier: {escape(target)}</h1>
<div class="meta">{meta_line}</div>
<p>{coverage}</p>
{body}
</body></html>"""


def encrypt_bytes(data: bytes, passphrase: str) -> bytes:
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, PBKDF2_ROUNDS)
    token = Fernet(base64.urlsafe_b64encode(key)).encrypt(data)
    return MAGIC + salt + token


def decrypt_bytes(blob: bytes, passphrase: str) -> bytes:
    if not blob.startswith(MAGIC):
        raise ValueError("not a larpharvester encrypted file")
    salt, token = blob[len(MAGIC) : len(MAGIC) + 16], blob[len(MAGIC) + 16 :]
    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, PBKDF2_ROUNDS)
    try:
        return Fernet(base64.urlsafe_b64encode(key)).decrypt(token)
    except InvalidToken as exc:
        raise ValueError("wrong passphrase or corrupted file") from exc
