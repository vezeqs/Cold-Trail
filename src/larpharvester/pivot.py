from __future__ import annotations

import asyncio
import contextlib
import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from .analysis import enrich_profile, entities_from_posts, extract_entities
from .avatars import hash_avatars
from .config import Settings
from .correlate import build_clusters, correlate
from .http import BlockedError, BudgetExceeded, Fetcher, FetchError, shared_fetcher
from .models import CheckResult, Entity, Kind, PivotReport, Profile
from .sources import GROUPS, SOURCES, Source
from .variants import email_variants
from .variants import variants as handle_variants

MAX_EXPAND = 5


def select_sources(names: list[str] | None, kind: Kind, include_web: bool = False) -> list[Source]:
    if names:
        resolved: list[Source] = []
        unknown: list[str] = []
        wrong_kind: list[str] = []
        for name in names:
            if name == "all":
                resolved.extend(source for source in SOURCES.values() if source.kind == kind)
            elif name in GROUPS:
                resolved.extend(
                    source
                    for source in SOURCES.values()
                    if source.group == name and source.kind == kind
                )
            elif name in SOURCES:
                source = SOURCES[name]
                if source.kind == kind:
                    resolved.append(source)
                else:
                    wrong_kind.append(name)
            else:
                unknown.append(name)
        problems: list[str] = []
        if unknown:
            problems.append(f"unknown source(s): {', '.join(sorted(set(unknown)))}")
        if wrong_kind:
            problems.append(
                f"source(s) not usable for {kind} pivots: {', '.join(sorted(set(wrong_kind)))}"
            )
        if problems:
            raise ValueError(
                "; ".join(problems)
                + f". Try `larpharvester sources` or one of: {', '.join(GROUPS)}, all"
            )
        selected: list[Source] = []
        seen: set[str] = set()
        for source in resolved:
            if source.name in seen:
                continue
            seen.add(source.name)
            selected.append(source)
        return sorted(selected, key=lambda source: source.name)

    pool = [
        source
        for source in SOURCES.values()
        if source.kind == kind and (include_web or source.group != "web")
    ]
    return sorted(pool, key=lambda source: source.name)


async def _check(
    source: Source,
    fetcher: Fetcher,
    target: str,
    on_result: Callable[[CheckResult], None] | None = None,
) -> CheckResult:
    try:
        res = await source.check(fetcher, target)
    except BlockedError as exc:
        res = source.blocked(target, str(exc))
    except BudgetExceeded as exc:
        res = source.failed(target, str(exc))
    except FetchError as exc:
        res = source.failed(target, str(exc))
    except Exception as exc:  # a broken source must not sink the whole pivot
        res = source.failed(target, f"{type(exc).__name__}: {exc}")
    if on_result is not None:
        with contextlib.suppress(Exception):
            on_result(res)
    return res


def _cache_fresh(row: dict[str, Any], ttl: int) -> bool:
    if ttl <= 0:
        return False
    try:
        checked = datetime.fromisoformat(row["checked_at"])
        if checked.tzinfo is None:
            checked = checked.replace(tzinfo=UTC)
        age = (datetime.now(UTC) - checked).total_seconds()
    except (KeyError, TypeError, ValueError):
        return False
    return age <= ttl


def _targets(target: str, kind: Kind, use_variants: bool) -> list[str]:
    if not use_variants:
        return [target]
    if kind == "email":
        return email_variants(target)
    return handle_variants(target)


async def pivot(
    target: str,
    *,
    settings: Settings,
    sources: list[str] | None = None,
    expand: bool = False,
    max_expand: int = MAX_EXPAND,
    depth: int = 1,
    use_variants: bool = False,
    include_web: bool = False,
    avatar_hash: bool = True,
    use_cache: bool = True,
    store=None,
    on_result: Callable[[CheckResult], None] | None = None,
    fetcher: Fetcher | None = None,
) -> PivotReport:
    target = target.strip().lstrip("@")
    kind: Kind = "email" if "@" in target else "username"
    selected = select_sources(sources, kind, include_web=include_web)
    if not selected:
        raise ValueError(f"no sources selected for {kind} pivots")

    targets = _targets(target, kind, use_variants)
    results: list[CheckResult] = []
    pending: list[tuple[Source, str]] = []
    ttl = settings.negative_cache_ttl if use_cache else 0

    for probe in targets:
        for source in selected:
            cached = store.probe_get(source.name, probe) if store is not None and ttl else None
            if cached is not None and _cache_fresh(cached, ttl) and cached["status"] != "found":
                cached_res = CheckResult(
                    source.name, probe, cached["status"], detail=cached["detail"]
                )
                results.append(cached_res)
                if on_result is not None:
                    with contextlib.suppress(Exception):
                        on_result(cached_res)
            else:
                pending.append((source, probe))

    async with shared_fetcher(settings, store, fetcher) as active_fetcher:
        fetched = await asyncio.gather(
            *(_check(source, active_fetcher, probe, on_result) for source, probe in pending)
        )
        results.extend(fetched)
        if store is not None and ttl:
            for result in fetched:
                if result.status == "not_found":
                    store.probe_put(result.source, result.target, result.status, result.detail)
        await _enrich(results, active_fetcher, avatar_hash, store)

        expanded: list[str] = []
        if expand:
            visited: set[str] = {t.casefold() for t in targets}
            current_kind: Kind = kind
            frontier_results = list(results)
            hops = max(1, depth)
            for _hop in range(hops):
                raw_candidates = (
                    discovered_usernames(frontier_results, limit=max_expand)
                    if current_kind == "email"
                    else discovered_emails(frontier_results, limit=max_expand)
                )
                candidates = [c for c in raw_candidates if c.casefold() not in visited]
                if not candidates:
                    break
                visited.update(c.casefold() for c in candidates)
                probe_kind: Kind = "username" if current_kind == "email" else "email"
                try:
                    extra_sources = select_sources(sources, probe_kind, include_web=include_web)
                except ValueError:
                    extra_sources = select_sources(None, probe_kind, include_web=include_web)
                extra_results = list(
                    await asyncio.gather(
                        *(
                            _check(source, active_fetcher, candidate, on_result)
                            for candidate in candidates
                            for source in extra_sources
                        )
                    )
                )
                expanded.extend(candidates)
                results.extend(extra_results)
                await _enrich(extra_results, active_fetcher, avatar_hash, store)
                frontier_results = extra_results
                current_kind = probe_kind

    profiles = [result.profile for result in results if result.profile is not None]
    links = correlate(profiles)
    clusters = build_clusters(profiles, links)
    coverage: dict[str, int] = {}
    for result in results:
        coverage[result.status] = coverage.get(result.status, 0) + 1

    return PivotReport(
        target=target,
        kind=kind,
        results=results,
        links=links,
        expanded=expanded,
        clusters=clusters,
        coverage=coverage,
    )


async def _enrich(results: list[CheckResult], fetcher: Fetcher, avatar_hash: bool, store) -> None:
    profiles = [result.profile for result in results if result.profile is not None]
    for profile in profiles:
        enrich_profile(profile)
        ents = profile_entities(profile)
        if ents:
            profile.extra["extracted_entities"] = [{"kind": e.kind, "value": e.value} for e in ents]
        if store is not None and (profile.lang is None or profile.timezone is None):
            hints = store.profile_hints(profile.source, profile.username)
            if hints:
                profile.lang = profile.lang or hints.get("lang")
                profile.timezone = profile.timezone or hints.get("timezone")
    if avatar_hash and profiles:
        await hash_avatars(fetcher, profiles)


def profile_entities(profile: Profile) -> list:
    # Declarative web.* profiles expose page templates, not user-authored text.
    if profile.source.startswith("web."):
        return []
    ents = extract_entities(profile.bio, profile.source, profile.username)
    for field in profile.extra.get("fields") or []:
        if isinstance(field, dict):
            ents.extend(extract_entities(field.get("value"), profile.source, profile.username))
    for key in ("public_email", "email", "location"):
        ents.extend(extract_entities(profile.extra.get(key), profile.source, profile.username))
    ents.extend(_extra_entities(profile))
    return ents


def _extra_entities(profile: Profile) -> list:
    """Entities derived from structured profile extras (keys, DIDs, EXIF, ENS)."""
    out: list = []
    extra = profile.extra or {}

    def add(kind: str, value: object, context: str | None = None) -> None:
        if isinstance(value, str) and value.strip():
            out.append(
                Entity(
                    source=profile.source,
                    username=profile.username,
                    kind=kind,
                    value=value.strip(),
                    context=context,
                )
            )

    for key in extra.get("ssh_keys") or []:
        if isinstance(key, dict):
            add("ssh_key", key.get("fingerprint"), "SSH key published on profile")
    for key in extra.get("gpg_keys") or []:
        if isinstance(key, dict):
            add("pgp_fingerprint", key.get("key_id"), "GPG key published on profile")
            for email in key.get("emails") or []:
                add("email", email, "GPG key UID email")
    if extra.get("did"):
        add("did", extra.get("did"), "Bluesky DID")
    if extra.get("pubkey"):
        add("nostr_key", extra.get("pubkey"), "Nostr NIP-05 pubkey")
    if extra.get("eth_address"):
        add("eth", extra.get("eth_address"), "ENS resolved address")
    meta = extra.get("avatar_meta") or {}
    if isinstance(meta, dict):
        for key in ("gps", "coords"):
            add("coords", meta.get(key), "EXIF GPS from avatar")
        for key in ("author", "artist", "exif_artist", "comment", "description"):
            value = meta.get(key)
            if isinstance(value, str):
                out.extend(extract_entities(value, profile.source, profile.username))
    return out


_HANDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$")


def discovered_usernames(results: list[CheckResult], limit: int | None = MAX_EXPAND) -> list[str]:
    """Pull usernames linked from email sources (Gravatar accounts, Keybase proofs, EmailRep).

    Only *structured* link evidence is used. A profile's own username is trusted
    only when it comes from a username-kind source: email sources often derive
    the username from the address local part (e.g. ``simon@…`` -> ``simon``),
    which is not an account on other platforms and would pivot into strangers.
    """
    found: list[str] = []
    seen: set[str] = set()
    for result in results:
        profile: Profile | None = result.profile
        if profile is None:
            continue
        source = SOURCES.get(profile.source)
        if source is not None and source.kind == "username":
            _add(found, seen, profile.username)
        for account in profile.extra.get("accounts") or []:
            if isinstance(account, dict):
                _add(found, seen, account.get("username"))
                _add(found, seen, _username_from_url(account.get("url")))
            else:
                _add(found, seen, account)
        for proof in profile.extra.get("proofs") or []:
            if isinstance(proof, dict):
                _add(found, seen, proof.get("username"))
                _add(found, seen, _username_from_url(proof.get("url") or proof.get("proof_url")))
        for login in profile.extra.get("logins") or []:
            _add(found, seen, login)
        for handle in profile.extra.get("handle_history") or []:
            _add(found, seen, handle)
        nip05 = profile.extra.get("nip05")
        if isinstance(nip05, str):
            _add(found, seen, nip05.split("@", 1)[0])
    return found if limit in (None, 0) else found[:limit]


def discovered_emails(results: list[CheckResult], limit: int | None = MAX_EXPAND) -> list[str]:
    """Collect emails from structured profile fields (for reverse expansion).

    Bio-derived emails are deliberately excluded: a same-handle stranger's bio
    must not pull their address into the investigation.
    """
    found: list[str] = []
    seen: set[str] = set()
    for result in results:
        profile: Profile | None = result.profile
        if profile is None:
            continue
        candidates: list[str] = []
        for key in ("email", "public_email"):
            value = profile.extra.get(key)
            if isinstance(value, str):
                candidates.append(value)
        for key in profile.extra.get("gpg_keys") or []:
            if isinstance(key, dict):
                candidates.extend(str(email) for email in key.get("emails") or [])
        for value in candidates:
            email = value.strip().casefold()
            if "@" not in email or email in seen:
                continue
            seen.add(email)
            found.append(email)
    return found if limit in (None, 0) else found[:limit]


def _add(found: list[str], seen: set[str], value: object) -> None:
    if not isinstance(value, str):
        return
    handle = value.strip().lstrip("@").removesuffix("/")
    if (
        not handle
        or "@" in handle
        or " " in handle
        or handle.isdigit()
        or not _HANDLE_RE.match(handle)
    ):
        return
    key = handle.casefold()
    if key not in seen:
        seen.add(key)
        found.append(handle)


def _username_from_url(url: object) -> str | None:
    if not isinstance(url, str) or not url.startswith("http"):
        return None
    parsed = urlsplit(url)
    if parsed.query:
        # e.g. news.ycombinator.com/user?id=alice
        for key in ("id", "user", "username", "u", "acct", "name", "nick"):
            m = re.search(rf"(?:^|[&?]){key}=([^&]+)", parsed.query)
            if m:
                val = m.group(1).strip().lstrip("@")
                if val and val.casefold() not in IGNORE_URL_PARTS:
                    return val
    path = parsed.path.strip("/")
    if not path:
        return None
    parts = [p for p in path.split("/") if p]
    if not parts:
        return None
    for candidate in reversed(parts):
        cleaned = candidate.casefold().lstrip("@")
        stem = re.sub(r"\.(html?|php|json|xml|asp|aspx|jsp)$", "", cleaned)
        if stem and stem not in IGNORE_URL_PARTS:
            return candidate.lstrip("@")
    return None


IGNORE_URL_PARTS = {
    "user",
    "users",
    "profile",
    "profiles",
    "id",
    "in",
    "u",
    "account",
    "sigs",
    "activity",
    "search",
    "explore",
    "watch",
    "tag",
    "tags",
    "share",
    "embed",
    "home",
    "feed",
    "about",
    "settings",
    "messages",
    "status",
    "web",
    "www",
    "api",
    "posts",
    "comments",
    "media",
    "photos",
    "videos",
    "download",
    "static",
    "assets",
    "member",
    "members",
    "channel",
    "channels",
    "page",
    "pages",
}


def persist_pivot(store: Any, report: PivotReport) -> int:
    """Save a pivot report as a run. Shared by the CLI, TUI, and web app."""
    run_id = store.start_run("pivot", report.target)
    try:
        store.save_checks(run_id, report.results)
        store.save_profiles(run_id, report.profiles)
        store.save_links(run_id, report.links)
        store.save_clusters(run_id, report.clusters)
        store.save_entities(run_id, entities_for_profiles(report.profiles))
        store.record_profile_history(run_id, report.profiles)
    except Exception:
        store.finish_run(run_id, "error")
        raise
    store.finish_run(run_id)
    report.run_id = run_id
    return run_id


def entities_for_profiles(profiles: list[Profile]) -> list:
    entities = []
    for profile in profiles:
        entities.extend(profile_entities(profile))
        entities.extend(extract_entities(profile.website, profile.source, profile.username))
    return entities


def entities_for_posts(posts) -> list:
    return entities_from_posts(posts)
