from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import asdict
from itertools import combinations
from typing import Annotated

import typer
from rich.table import Table

from ..analysis import entities_from_posts, infer_timezone, marker_overlap, style_similarity
from ..domain import lookup_domain, ptr, reverse_ip, shodan_host
from ..dorks import dorks as build_dorks
from ..http import Fetcher, FetchError
from ..models import Post
from ..phone import lookup as phone_lookup
from ..pivot import _check
from ..sources import SOURCES
from ..store import Store
from ..wayback import cdx, snapshot
from ._app import (
    STATUS_STYLE,
    _print_json,
    _render_profiles,
    _settings,
    app,
    console,
    source_app,
)

# -- sources ----------------------------------------------------------------


@app.command()
def sources(
    group: Annotated[str | None, typer.Option("-g", "--group", help="Filter by group")] = None,
    all_sources: Annotated[bool, typer.Option("--all", help="Include web corpus")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List available sources."""
    items = list(SOURCES.values())
    if group:
        items = [source for source in items if source.group == group]
    elif not all_sources:
        items = [source for source in items if source.group != "web"]
    rows = [
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
    if json_out:
        _print_json(rows)
        return
    table = Table(title=f"Sources ({len(rows)})")
    for column in ("Name", "Label", "Kind", "Group", "Posts", "Auth", "Homepage"):
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(
            row["name"],
            row["label"],
            row["kind"],
            row["group"],
            "yes" if row["posts"] else "",
            "yes" if row["auth"] else "",
            row["homepage"],
        )
    console.print(table)
    if not all_sources and not group:
        console.print("[dim]web corpus hidden; use --all or -g web[/dim]")


@source_app.command("list")
def source_list() -> None:
    sources()


@source_app.command("test")
def source_test(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Source name")],
    target: Annotated[str, typer.Argument(help="Username or email")],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Probe one source and show the parsed result."""
    settings = _settings(ctx)
    if name not in SOURCES:
        raise typer.BadParameter(f"unknown source {name!r}")
    source = SOURCES[name]

    async def run():
        async with Fetcher(settings) as fetcher:
            return await _check(source, fetcher, target)

    result = asyncio.run(run())
    if json_out:
        _print_json(asdict(result))
        return
    console.print(f"{name}: [{STATUS_STYLE[result.status]}]{result.status}[/]")
    if result.profile:
        _render_profiles([result.profile], f"Profile: {result.profile.username}")
    if result.detail:
        console.print(f"[dim]{result.detail}[/dim]")


# -- dorks ------------------------------------------------------------------


@app.command()
def dorks(
    target: Annotated[str, typer.Argument(help="Handle or name")],
    engine: Annotated[list[str] | None, typer.Option("-e", "--engine")] = None,
    image: Annotated[
        str | None, typer.Option("--image", help="Avatar URL for reverse search")
    ] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Generate search-engine dork and reverse-image links."""
    rows = build_dorks(target, engine)
    if image:
        from ..dorks import reverse_image_links

        rows.extend(reverse_image_links(image))
    if json_out:
        _print_json(rows)
        return
    table = Table(title=f"Dorks for {target} ({len(rows)})")
    table.add_column("Engine")
    table.add_column("Query", overflow="fold")
    table.add_column("URL", overflow="fold")
    for row in rows:
        table.add_row(row["engine"], row.get("query", "reverse image"), row["url"])
    console.print(table)


# -- analysis / enrichment --------------------------------------------------


@app.command()
def analyze(
    ctx: typer.Context,
    run: Annotated[int | None, typer.Option("--run")] = None,
    threshold: Annotated[float, typer.Option("--threshold", min=0.0, max=1.0)] = 0.9,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Infer timezones and score writing-style similarity across stored posts."""
    with Store(_settings(ctx).db_path) as store:
        rows = store.posts(run_id=run, limit=None)
        groups: dict[tuple[str, str], list[Post]] = defaultdict(list)
        for row in rows:
            groups[(row["source"], row["username"])].append(
                Post(
                    source=row["source"],
                    username=row["username"],
                    post_id=row["post_id"],
                    url=row["url"],
                    created_at=row["created_at"],
                    text=row["text"],
                    metrics=row["metrics"],
                )
            )
        timezones = []
        for (source, username), items in groups.items():
            zone = infer_timezone(items)
            if zone:
                store.set_profile_timezone(source, username, zone)
                timezones.append({"source": source, "username": username, "timezone": zone})
        pairs = []
        for left, right in combinations(groups, 2):
            text_left = " ".join(post.text or "" for post in groups[left])
            text_right = " ".join(post.text or "" for post in groups[right])
            similarity = style_similarity(text_left, text_right)
            if similarity >= threshold:
                pairs.append(
                    {
                        "a": f"{left[0]}:{left[1]}",
                        "b": f"{right[0]}:{right[1]}",
                        "similarity": round(similarity, 3),
                        "markers": round(marker_overlap(text_left, text_right), 3),
                    }
                )
        pairs.sort(key=lambda row: row["similarity"], reverse=True)
        if run is not None:
            store.save_entities(
                run, entities_from_posts([post for items in groups.values() for post in items])
            )
    payload = {"timezones": timezones, "style_pairs": pairs}
    if json_out:
        _print_json(payload)
        return
    if timezones:
        table = Table(title="Inferred timezones")
        for column in ("Source", "Username", "Timezone"):
            table.add_column(column)
        for row in timezones:
            table.add_row(row["source"], row["username"], row["timezone"])
        console.print(table)
    if pairs:
        table = Table(title="Writing-style similarity")
        for column in ("A", "B", "Similarity", "Markers"):
            table.add_column(column, overflow="fold")
        for row in pairs:
            table.add_row(row["a"], row["b"], f"{row['similarity']:.3f}", f"{row['markers']:.3f}")
        console.print(table)
    if not timezones and not pairs:
        console.print("[dim]no timezone or style signals available[/dim]")


@app.command()
def archive(
    ctx: typer.Context,
    url: Annotated[str, typer.Argument(help="URL to look up in the Wayback Machine")],
    limit: Annotated[int, typer.Option("-n", "--limit", min=1, max=500)] = 20,
    snapshot_ts: Annotated[
        str | None, typer.Option("--snapshot", help="Fetch this capture timestamp")
    ] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List Wayback captures and optionally print an archived snapshot."""
    settings = _settings(ctx)

    async def collect():
        async with Fetcher(settings) as fetcher:
            rows = await cdx(fetcher, url, limit)
            text = await snapshot(fetcher, snapshot_ts, url) if snapshot_ts else None
            return rows, text

    try:
        rows, text = asyncio.run(collect())
    except FetchError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    if json_out:
        _print_json({"captures": rows, "snapshot": text})
        return
    table = Table(title=f"Wayback captures: {url} ({len(rows)})")
    for column in ("Timestamp", "Original", "Status", "MIME", "Length"):
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(
            str(row.get("timestamp", "")),
            str(row.get("original", "")),
            str(row.get("statuscode", "")),
            str(row.get("mimetype", "")),
            str(row.get("length", "")),
        )
    console.print(table)
    if text:
        console.print(text[:5000])
    if not rows:
        raise typer.Exit(code=1)


@app.command()
def domain(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Domain name")],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """RDAP, DNS records, and certificate-transparency subdomains."""
    settings = _settings(ctx)

    async def collect():
        async with Fetcher(settings) as fetcher:
            return await lookup_domain(fetcher, name)

    try:
        payload = asyncio.run(collect())
    except FetchError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    if json_out:
        _print_json(payload)
        return
    console.print(f"[bold]{payload['domain']}[/bold]")
    rdap = payload.get("rdap")
    if rdap:
        for action, when in (rdap.get("events") or {}).items():
            console.print(f"  {action}: {when}")
        if rdap.get("nameservers"):
            console.print(f"  nameservers: {', '.join(rdap['nameservers'])}")
        if rdap.get("status"):
            console.print(f"  status: {', '.join(rdap['status'])}")
    if payload.get("dns"):
        table = Table(title="DNS")
        for column in ("Type", "Value"):
            table.add_column(column, overflow="fold")
        for record_type, values in payload["dns"].items():
            for value in values:
                table.add_row(record_type, value)
        console.print(table)
    subdomains = payload.get("subdomains") or []
    if subdomains:
        console.print(f"subdomains ({len(subdomains)}):")
        for subdomain in subdomains[:100]:
            console.print(f"  {subdomain}")


@app.command("ip")
def ip_cmd(
    ctx: typer.Context,
    address: Annotated[str, typer.Argument(help="IPv4 address")],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """PTR record, reverse-IP hostnames, and Shodan data for an address."""
    settings = _settings(ctx)

    async def collect():
        async with Fetcher(settings) as fetcher:
            return {
                "address": address,
                "ptr": await ptr(fetcher, address),
                "hostnames": await reverse_ip(fetcher, address, settings.shodan_api_key),
                "shodan": await shodan_host(fetcher, address, settings.shodan_api_key),
            }

    try:
        payload = asyncio.run(collect())
    except FetchError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    if json_out:
        _print_json(payload)
        return
    console.print(f"[bold]{address}[/bold]")
    for key in ("ptr", "hostnames"):
        values = payload[key]
        if values:
            shown = ", ".join(values[:50])
            extra = f" (+{len(values) - 50} more)" if len(values) > 50 else ""
            console.print(f"{key} ({len(values)}): {shown}{extra}")
    if payload["shodan"]:
        table = Table(title="Shodan")
        for column in ("Field", "Value"):
            table.add_column(column, overflow="fold")
        for key, value in payload["shodan"].items():
            table.add_row(key, str(value))
        console.print(table)


@app.command()
def phone(
    number: Annotated[str, typer.Argument(help="Phone number")],
    region: Annotated[str | None, typer.Option("--region", help="ISO region hint")] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Parse a phone number: carrier, region, timezone, type."""
    payload = phone_lookup(number, region)
    if payload is None:
        typer.echo("invalid or unparseable number", err=True)
        raise typer.Exit(code=1)
    if json_out:
        _print_json(payload)
        return
    table = Table(title=f"Phone: {payload['e164']}")
    for column in ("Field", "Value"):
        table.add_column(column)
    for key, value in payload.items():
        if isinstance(value, list):
            value = ", ".join(str(item) for item in value)
        table.add_row(key, str(value))
    console.print(table)
