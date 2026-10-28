from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Status = Literal["found", "not_found", "error", "blocked"]
Kind = Literal["username", "email"]


@dataclass(slots=True)
class Profile:
    source: str
    username: str
    url: str
    display_name: str | None = None
    bio: str | None = None
    avatar: str | None = None
    avatar_hash: str | None = None
    website: str | None = None
    created_at: str | None = None
    followers: int | None = None
    lang: str | None = None
    timezone: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Post:
    source: str
    username: str
    post_id: str
    url: str
    created_at: str | None = None
    text: str | None = None
    metrics: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class CheckResult:
    source: str
    target: str
    status: Status
    profile: Profile | None = None
    detail: str | None = None


@dataclass(slots=True)
class Link:
    a: Profile
    b: Profile
    score: float
    reasons: list[str]


@dataclass(slots=True)
class Cluster:
    key: str
    profiles: list[Profile]
    score: float
    reasons: list[str]


@dataclass(slots=True)
class Entity:
    source: str
    username: str
    kind: str
    value: str
    context: str | None = None


@dataclass(slots=True)
class Edge:
    platform: str
    actor: str
    target: str
    direction: str = "follows"


@dataclass(slots=True)
class ProfileChange:
    source: str
    username: str
    field: str
    old_value: str | None
    new_value: str | None
    observed_at: str


@dataclass(slots=True)
class PivotReport:
    target: str
    kind: Kind
    results: list[CheckResult]
    links: list[Link]
    expanded: list[str] = field(default_factory=list)
    clusters: list[Cluster] = field(default_factory=list)
    coverage: dict[str, int] = field(default_factory=dict)
    run_id: int | None = None

    @property
    def profiles(self) -> list[Profile]:
        return [r.profile for r in self.results if r.profile is not None]
