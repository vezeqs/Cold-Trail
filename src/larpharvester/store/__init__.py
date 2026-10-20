from __future__ import annotations

from .base import StoreBase
from .caches import CachesMixin
from .cases import CasesMixin
from .maintenance import MaintenanceMixin
from .queries import QueriesMixin
from .runs import RunsMixin
from .schema import SCHEMA_VERSION
from .writes import WritesMixin


class Store(
    RunsMixin,
    WritesMixin,
    QueriesMixin,
    CachesMixin,
    CasesMixin,
    MaintenanceMixin,
    StoreBase,
):
    """SQLite persistence: runs, profiles, posts, links, clusters, entities,
    edges, history, cursors, HTTP cache, raw captures, probe cache, audit,
    cases, tags, and notes. Method groups live in store/{runs,writes,queries,
    caches,cases,maintenance}.py; schema and migrations in store/{schema,base}.py."""


__all__ = ["SCHEMA_VERSION", "Store"]
