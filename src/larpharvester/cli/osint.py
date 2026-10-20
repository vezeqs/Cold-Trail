from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import asdict
from itertools import combinations
from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table

from ..analysis import entities_from_posts, infer_timezone, marker_overlap, style_similarity
from ..domain import (
    asn_lookup,
    bgp_prefixes,
    crtsh_identities,
    lookup_domain,
    ptr,
    rdap_ip,
    reverse_ip,
    shodan_host,
)
from ..dorks import dorks as build_dorks
from ..http import Fetcher, FetchError
from ..models import Post
from ..phone import lookup as phone_lookup
from ..pivot import _check
from ..sources import SOURCES
from ..store import Store
from ..wayback import cdx, recover_profile_snapshots, snapshot
from ._app import (
    STATUS_STYLE,
    _print_json,
    _render_profiles,
    _settings,
    _truncate,
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


@source_app.command("verify")
def source_verify(
    ctx: typer.Context,
    name: Annotated[
        list[str] | None, typer.Option("-s", "--source", help="Sources (repeatable)")
    ] = None,
    record: Annotated[
        bool, typer.Option("--record", help="Probe live and record replayable fixtures")
    ] = False,
    live: Annotated[
        bool, typer.Option("--live", help="Probe live and validate contracts (needs network)")
    ] = False,
    directory: Annotated[
        Path | None, typer.Option("--dir", help="Fixture directory")
    ] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Verify source contracts offline (replay fixtures), or record/live-verify them."""
    from ..contracts import CONTRACTS, record_contract, verify_all, verify_live

    settings = _settings(ctx)
    names = list(name) if name else sorted(CONTRACTS)
    unknown = [item for item in names if item not in SOURCES]
    if unknown:
        typer.echo(f"unknown source(s): {', '.join(unknown)}", err=True)
        raise typer.Exit(code=2)

    if record:
        recorded: dict[str, str] = {}
        for item in names:
            try:
                payload = asyncio.run(record_contract(item, settings, directory))
                recorded[item] = payload.get("observed_status") or "?"
            except Exception as exc:
                recorded[item] = f"error: {type(exc).__name__}: {exc}"
        if json_out:
            _print_json(recorded)
            return
        for item, status in recorded.items():
            console.print(f"recorded {item}: {status}")
        return

    if live:
        results = {
            item: asyncio.run(verify_live(item, settings)) for item in names
        }
    else:
        results = asyncio.run(verify_all(settings, directory, names))

    failures = {item: problems for item, problems in results.items() if problems}
    if json_out:
        _print_json({"results": results, "failures": failures})
        if failures:
            raise typer.Exit(code=1)
        return
    table = Table(title=f"Contract verification ({len(results)} sources)")
    for column in ("Source", "Result", "Problems"):
        table.add_column(column, overflow="fold")
    for item, problems in sorted(results.items()):
        table.add_row(
            item,
            "[green]ok[/green]" if not problems else "[red]fail[/red]",
            "; ".join(problems)[:120],
        )
    console.print(table)
    if failures:
        raise typer.Exit(code=1)


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
    recover: Annotated[
        bool,
        typer.Option("--recover", help="Recover historical titles/descriptions from captures"),
    ] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List Wayback captures and optionally print an archived snapshot or recover history."""
    settings = _settings(ctx)

    async def collect():
        async with Fetcher(settings) as fetcher:
            rows = await cdx(fetcher, url, limit)
            text = await snapshot(fetcher, snapshot_ts, url) if snapshot_ts else None
            history = (
                await recover_profile_snapshots(fetcher, url, limit=5) if recover else None
            )
            return rows, text, history

    try:
        rows, text, history = asyncio.run(collect())
    except FetchError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    if json_out:
        _print_json({"captures": rows, "snapshot": text, "recovered": history})
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
    if history:
        history_table = Table(title="Recovered profile history")
        for column in ("Captured", "Title", "Description"):
            history_table.add_column(column, overflow="fold")
        for item in history:
            history_table.add_row(
                str(item.get("timestamp", "")),
                _truncate(str(item.get("title") or ""), 60),
                _truncate(str(item.get("description") or ""), 80),
            )
        console.print(history_table)
    if not rows:
        raise typer.Exit(code=1)


@app.command("ct")
def ct_search(
    ctx: typer.Context,
    query: Annotated[str, typer.Argument(help="Domain, organization, or email identity")],
    limit: Annotated[int, typer.Option("-n", "--limit", min=1, max=500)] = 100,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Search certificate transparency logs for an identity string."""
    settings = _settings(ctx)

    async def collect():
        async with Fetcher(settings) as fetcher:
            return await crtsh_identities(fetcher, query, limit=limit)

    rows = asyncio.run(collect())
    if json_out:
        _print_json(rows)
        return
    table = Table(title=f"Certificate transparency: {query} ({len(rows)})")
    for column in ("Common name", "Issuer", "Not before", "Not after"):
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(
            str(row.get("common_name", "")),
            _truncate(str(row.get("issuer") or ""), 60),
            str(row.get("not_before") or "")[:10],
            str(row.get("not_after") or "")[:10],
        )
    console.print(table)


@app.command()
def domain(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Domain name")],
    deep: Annotated[
        bool,
        typer.Option("--deep", help="Also query DMARC, security.txt, favicon MMH3, and takeovers"),
    ] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """RDAP, DNS records, certificate-transparency subdomains, and optional deep recon."""
    settings = _settings(ctx)

    async def collect():
        async with Fetcher(settings) as fetcher:
            return await lookup_domain(fetcher, name, deep=deep)

    try:
        payload = asyncio.run(collect())
    except FetchError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    if json_out:
        _print_json(payload)
        return
    console.print(f"[bold]{payload['domain']}[/bold]")
    if payload.get("mx_provider"):
        console.print(f"  mail provider: {payload['mx_provider']}")
    if payload.get("spf"):
        console.print(f"  spf: {payload['spf']}")
    if payload.get("dmarc"):
        console.print(f"  dmarc: {payload['dmarc']}")
    if payload.get("favicon_mmh3") is not None:
        console.print(f"  favicon mmh3: {payload['favicon_mmh3']}")
    tls = payload.get("tls")
    if tls:
        console.print(
            f"  tls: {tls.get('issuer_cn') or ''} · {tls.get('tls_version') or ''}"
            f" · expires {str(tls.get('not_after') or '')[:16]}"
        )
        if tls.get("sans"):
            console.print(f"  tls SANs ({len(tls['sans'])}): {', '.join(tls['sans'][:10])}")
    if payload.get("takeover"):
        tk = payload["takeover"]
        console.print(f"  [yellow]takeover candidate: {tk['service']} ({tk['cname']})[/yellow]")
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
    asn: Annotated[bool, typer.Option("--asn", help="Include RIPE ASN & IP RDAP")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """PTR record, reverse-IP hostnames, Shodan, and optional ASN/RDAP data for an address."""
    settings = _settings(ctx)

    async def collect():
        async with Fetcher(settings) as fetcher:
            out = {
                "address": address,
                "ptr": await ptr(fetcher, address),
                "hostnames": await reverse_ip(fetcher, address, settings.shodan_api_key),
                "shodan": await shodan_host(fetcher, address, settings.shodan_api_key),
            }
            if asn:
                out["asn"] = await asn_lookup(fetcher, address)
                out["bgp"] = await bgp_prefixes(fetcher, address)
                out["rdap"] = await rdap_ip(fetcher, address)
            return out

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
    bgp = payload.get("bgp")
    if bgp:
        console.print(
            f"bgp: {bgp.get('asn')} {bgp.get('holder') or ''} "
            f"({len(bgp.get('announced') or [])} prefix(es))"
        )
        for prefix in (bgp.get("announced") or [])[:15]:
            console.print(f"  {prefix}")
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
