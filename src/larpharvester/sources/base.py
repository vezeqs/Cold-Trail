from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from ..models import CheckResult, Edge, Kind, Post, Profile

if TYPE_CHECKING:
    from ..http import Fetcher

REGISTRY: dict[str, Source] = {}


def register(cls: type[Source]) -> type[Source]:
    """Register a source class so the CLI and pivot engine can discover it."""
    instance = cls()
    if not instance.name:
        raise ValueError(f"{cls.__name__} must define a name")
    REGISTRY[instance.name] = instance
    return cls


class Source(ABC):
    """A public-data source that can be probed for a username or email."""

    name: str = ""
    label: str = ""
    kind: Kind = "username"
    group: str = "misc"
    homepage: str = ""
    supports_posts: bool = False
    requires_auth: bool = False

    @abstractmethod
    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        """Probe the source and report whether the target exists there."""

    async def posts(
        self,
        fetcher: Fetcher,
        target: str,
        limit: int,
        *,
        since: str | None = None,
    ) -> list[Post]:
        """Fetch recent public posts. Sources that have none simply return []."""
        return []

    async def follows(self, fetcher: Fetcher, target: str, limit: int = 100) -> list[Edge]:
        """Fetch public follow relationships, where the platform exposes them."""
        return []

    # -- result helpers -----------------------------------------------------

    def ok(self, target: str, profile: Profile) -> CheckResult:
        return CheckResult(self.name, target, "found", profile=profile)

    def missing(self, target: str, detail: str | None = None) -> CheckResult:
        return CheckResult(self.name, target, "not_found", detail=detail)

    def blocked(self, target: str, detail: str) -> CheckResult:
        return CheckResult(self.name, target, "blocked", detail=detail)

    def failed(self, target: str, detail: str) -> CheckResult:
        return CheckResult(self.name, target, "error", detail=detail)
