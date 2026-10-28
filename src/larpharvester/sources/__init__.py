from __future__ import annotations

import warnings
from importlib.metadata import entry_points

from ..config import Settings
from ..sites import load_sites, slugify
from . import (  # noqa: F401
    bluesky,
    chesscom,
    codeberg,
    crates,
    devto,
    dockerhub,
    duolingo,
    emailrep,
    ens,
    github,
    github_commits,
    gitlab,
    gravatar,
    hackernews,
    hackerone,
    hibp,
    hudsonrock,
    huggingface,
    hunter,
    instagram,
    kaggle,
    keybase,
    leakcheck,
    libravatar,
    lichess,
    linktree,
    mastodon,
    matrix,
    medium,
    nostr,
    npm,
    packagist,
    pgp,
    pinterest,
    pypi,
    reddit,
    roblox,
    rubygems,
    snapchat,
    stackoverflow,
    steam,
    substack,
    telegram,
    threads,
    tiktok,
    tumblr,
    twitch,
    vk,
    x,
    youtube,
)
from .base import REGISTRY, Source
from .declarative import DeclarativeSource

GROUPS = ("social", "dev", "email", "web", "misc")


def load_declarative(path=None) -> int:
    settings = Settings()
    sites = load_sites(path or settings.sites_path)
    count = 0
    for site in sites:
        if slugify(site.name) in REGISTRY:
            continue
        source = DeclarativeSource(site)
        if source.name not in REGISTRY:
            REGISTRY[source.name] = source
            count += 1
    _refresh()
    return count


def load_plugins() -> int:
    try:
        discovered = entry_points(group="larpharvester.sources")
    except TypeError:
        return 0
    count = 0
    for entry in discovered:
        try:
            loaded = entry.load()
        except Exception as exc:
            warnings.warn(
                f"larpharvester plugin {entry.name!r} failed to load: {exc}",
                stacklevel=2,
            )
            continue
        candidates = loaded if isinstance(loaded, (list, tuple)) else [loaded]
        for candidate in candidates:
            if isinstance(candidate, type) and issubclass(candidate, Source):
                instance = candidate()
                if instance.name and instance.name not in REGISTRY:
                    REGISTRY[instance.name] = instance
                    count += 1
    _refresh()
    return count


def _refresh() -> None:
    SOURCES.clear()
    SOURCES.update(sorted(REGISTRY.items()))
    CURATED.clear()
    CURATED.update({n: s for n, s in SOURCES.items() if s.group != "web"})


def sync(sites_path=None) -> int:
    """Load declarative sites from a custom path (config `sites_path` support)."""
    if sites_path is None:
        return 0
    return load_declarative(sites_path)


SOURCES: dict[str, Source] = {}
CURATED: dict[str, Source] = {}

load_declarative()
load_plugins()

__all__ = ["SOURCES", "CURATED", "GROUPS", "Source", "sync"]
