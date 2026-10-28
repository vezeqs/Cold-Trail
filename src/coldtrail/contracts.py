"""Source contract testing: record real HTTP exchanges and replay them offline.

A *contract* describes what a healthy source must return for a known target:
a status plus required profile fields. Recording captures every raw HTTP
response the check touched (URL, status, body, content type) into a JSON
fixture. Verification replays those responses through the live source parser
and asserts the contract — so upstream API drift and parser regressions fail
loudly instead of silently thinning results.
"""

from __future__ import annotations

import base64
import json
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import respx

from .config import Settings
from .http import Fetcher
from .sources import SOURCES
from .store import Store


@dataclass(slots=True)
class Contract:
    source: str
    target: str
    status: str = "found"
    required: list[str] = field(default_factory=lambda: ["username", "url"])
    fixture: str | None = None


CONTRACTS: dict[str, Contract] = {
    "github": Contract("github", "octocat", required=["username", "url", "followers"]),
    "gitlab": Contract("gitlab", "gitlab-bot", required=["username", "url"]),
    "codeberg": Contract("codeberg", "forgejo", required=["username", "url"]),
    "stackoverflow": Contract("stackoverflow", "jon-skeet", required=["username", "url"]),
    "kaggle": Contract("kaggle", "kaggle", required=["username", "url"]),
    "huggingface": Contract("huggingface", "huggingface", required=["username", "url"]),
    "npm": Contract("npm", "npm", required=["username", "url"]),
    "pypi": Contract("pypi", "pypa", required=["username", "url"]),
    "devto": Contract("devto", "ben", required=["username", "url"]),
    "hackerone": Contract("hackerone", "hackerone", required=["username", "url"]),
    "crates": Contract("crates", "dtolnay", required=["username", "url"]),
    "dockerhub": Contract("dockerhub", "docker", required=["username", "url"]),
    "rubygems": Contract("rubygems", "sferik", required=["username", "url"]),
    "packagist": Contract("packagist", "symfony", required=["username", "url"]),
    "reddit": Contract("reddit", "spez", required=["username", "url"]),
    "hackernews": Contract("hackernews", "pg", required=["username", "url"]),
    "mastodon": Contract("mastodon", "Gargron@mastodon.social", required=["username", "url"]),
    "bluesky": Contract("bluesky", "bsky.app", required=["username", "url"]),
    "telegram": Contract("telegram", "telegram", required=["username", "url"]),
    "youtube": Contract("youtube", "@YouTube", required=["username", "url"]),
    "twitch": Contract("twitch", "twitch", required=["username", "url"]),
    "steam": Contract("steam", "gaben", required=["username", "url"]),
    "chesscom": Contract("chesscom", "hikaru", required=["username", "url"]),
    "lichess": Contract("lichess", "thibault", required=["username", "url"]),
    "roblox": Contract("roblox", "Roblox", required=["username", "url"]),
    "duolingo": Contract("duolingo", "duolingo", required=["username", "url"]),
    "tiktok": Contract("tiktok", "tiktok", required=["username", "url"]),
    "medium": Contract("medium", "medium", required=["username", "url"]),
    "substack": Contract("substack", "platformer", required=["username", "url"]),
    "linktree": Contract("linktree", "linktree", required=["username", "url"]),
    "matrix": Contract("matrix", "@alice:matrix.org", required=["username", "url"]),
    "nostr": Contract("nostr", "_@nostr.band", required=["username", "url"]),
    "ens": Contract("ens", "vitalik.eth", required=["username", "url"]),
    "gravatar": Contract("gravatar", "beau@dentedreality.com.au", required=["username", "url"]),
    "keybase": Contract("keybase", "chris", required=["username", "url"]),
    "pgp": Contract("pgp", "torvalds@linux-foundation.org", required=["username", "url"]),
    "github-commits": Contract(
        "github-commits", "torvalds@linux-foundation.org", required=["username", "url"]
    ),
    "hibp": Contract("hibp", "test@example.com", required=["username", "url"]),
    "emailrep": Contract("emailrep", "test@example.com", required=["username", "url"]),
    "hudsonrock": Contract("hudsonrock", "test@example.com", required=["username", "url"]),
    "leakcheck": Contract("leakcheck", "test@example.com", required=["username", "url"]),
    "libravatar": Contract("libravatar", "test@example.com", required=["username", "url"]),
    "threads": Contract("threads", "threads", required=["username", "url"]),
    "pinterest": Contract("pinterest", "pinterest", required=["username", "url"]),
    "tumblr": Contract("tumblr", "staff", required=["username", "url"]),
    "vk": Contract("vk", "vk", required=["username", "url"]),
    "snapchat": Contract("snapchat", "snapchat", required=["username", "url"]),
    "instagram": Contract("instagram", "instagram", required=["username", "url"]),
    "x": Contract("x", "x", required=["username", "url"]),
    "hunter": Contract("hunter", "test@example.com", required=["username", "url"]),
}

DEFAULT_FIXTURE_DIR = Path("tests") / "fixtures" / "contracts"


def fixture_path(source: str, directory: Path | None = None) -> Path:
    base = directory or DEFAULT_FIXTURE_DIR
    return base / f"{source}.json"


async def record_contract(
    source_name: str,
    settings: Settings,
    directory: Path | None = None,
    target: str | None = None,
) -> dict[str, Any]:
    """Probe a source live and persist every raw response as a replayable fixture."""
    contract = CONTRACTS.get(source_name)
    probe_target = target or (contract.target if contract else None)
    if not probe_target:
        raise ValueError(f"no contract target for {source_name!r}")
    source = SOURCES[source_name]
    directory = directory or DEFAULT_FIXTURE_DIR
    directory.mkdir(parents=True, exist_ok=True)
    with Store(directory / "_record.db") as store:
        run_id = store.start_run("contract", f"{source_name}:{probe_target}")
        fetcher = Fetcher(settings, store=store, run_id=run_id)
        try:
            result = await source.check(fetcher, probe_target)
        finally:
            await fetcher.close()
        rows = store.conn.execute(
            "SELECT url, status, body FROM raw WHERE run_id = ? ORDER BY id", (run_id,)
        ).fetchall()
        store.finish_run(run_id)
    exchanges = []
    for row in rows:
        try:
            body = zlib.decompress(bytes(row["body"]))
        except zlib.error:
            body = bytes(row["body"])
        exchanges.append(
            {
                "url": row["url"],
                "status": row["status"],
                "body_b64": base64.b64encode(body).decode(),
            }
        )
    payload = {
        "source": source_name,
        "target": probe_target,
        "observed_status": result.status,
        "profile": {
            "username": result.profile.username if result.profile else None,
            "url": result.profile.url if result.profile else None,
            "display_name": result.profile.display_name if result.profile else None,
            "followers": result.profile.followers if result.profile else None,
            "extra_keys": sorted((result.profile.extra or {}).keys()) if result.profile else [],
        },
        "exchanges": exchanges,
    }
    path = fixture_path(source_name, directory)
    path.write_text(json.dumps(payload, indent=2))
    return payload


def _field_value(profile: Any, name: str) -> Any:
    if profile is None:
        return None
    if name == "username":
        return profile.username
    if name == "url":
        return profile.url
    if name == "display_name":
        return profile.display_name
    if name == "followers":
        return profile.followers
    return (profile.extra or {}).get(name)


async def verify_contract(
    source_name: str, settings: Settings, directory: Path | None = None
) -> list[str]:
    """Replay a recorded fixture through the source parser and return contract problems."""
    path = fixture_path(source_name, directory)
    if not path.is_file():
        return [f"no fixture at {path}"]
    payload = json.loads(path.read_text())
    exchanges = payload.get("exchanges") or []
    if not exchanges:
        return [f"fixture {path} has no recorded exchanges"]
    with respx.mock(assert_all_called=False) as mock:
        for exchange in exchanges:
            body = base64.b64decode(exchange.get("body_b64") or "")
            mock.get(exchange["url"]).mock(
                return_value=httpx.Response(exchange.get("status", 200), content=body)
            )
        source = SOURCES[source_name]
        async with Fetcher(settings) as fetcher:
            try:
                result = await source.check(fetcher, payload.get("target") or "")
            except Exception as exc:
                return [f"{source_name}: check raised {type(exc).__name__}: {exc}"]
    return validate_result(source_name, result)


def validate_result(source_name: str, result: Any) -> list[str]:
    """Check a CheckResult against the source's contract."""
    contract = CONTRACTS.get(source_name) or Contract(source_name, "")
    problems: list[str] = []
    if result.status != contract.status:
        problems.append(
            f"{source_name}: expected status {contract.status!r}, got {result.status!r}"
        )
    if contract.status == "found":
        if result.profile is None:
            problems.append(f"{source_name}: found without a profile")
        else:
            for field_name in contract.required:
                value = _field_value(result.profile, field_name)
                if value in (None, "", []):
                    problems.append(f"{source_name}: required field {field_name!r} is empty")
    return problems


async def verify_live(source_name: str, settings: Settings, target: str | None = None) -> list[str]:
    """Probe a source live and validate the contract (requires network)."""
    contract = CONTRACTS.get(source_name) or Contract(source_name, "")
    probe_target = target or contract.target
    if not probe_target:
        return [f"{source_name}: no contract target configured"]
    async with Fetcher(settings) as fetcher:
        try:
            result = await SOURCES[source_name].check(fetcher, probe_target)
        except Exception as exc:
            return [f"{source_name}: check raised {type(exc).__name__}: {exc}"]
    return validate_result(source_name, result)


async def verify_all(
    settings: Settings, directory: Path | None = None, sources: list[str] | None = None
) -> dict[str, list[str]]:
    names = sources or sorted(CONTRACTS)
    return {
        name: await verify_contract(name, settings, directory) for name in names if name in SOURCES
    }
