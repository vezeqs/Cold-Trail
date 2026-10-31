from __future__ import annotations

import contextlib
import os
import sqlite3
from pathlib import Path
from typing import Any, Self

from ..utils import json_loads, parse_dt
from .schema import COLUMNS, FTS, POSTS_AU_TRIGGER, SCHEMA, SCHEMA_VERSION


class StoreError(RuntimeError):
    """The database could not be opened, migrated, or is not a database."""


class StoreBase:
    """Connection lifecycle, migrations, and row helpers shared by every mixin."""

    def __init__(self, path: Path) -> None:
        path = Path(path).expanduser()
        self.path = path
        # Create the database (and its WAL/SHM sidecars) owner-only from the
        # first syscall; a chmod after connect leaves a readable window.
        previous_umask = os.umask(0o077)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(path)
        except (OSError, sqlite3.Error) as exc:
            raise StoreError(f"cannot open database {path}: {exc}") from exc
        finally:
            os.umask(previous_umask)
        self.conn.row_factory = sqlite3.Row
        try:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA foreign_keys=ON")
            self.conn.execute("PRAGMA busy_timeout=5000")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self._migrate()
        except sqlite3.Error as exc:
            self.conn.close()
            raise StoreError(f"cannot use database {path}: {exc}") from exc
        self._secure_files()

    def _secure_files(self) -> None:
        """Restrict the database and its WAL/SHM sidecars to the current user.

        Investigations contain sensitive personal data; a default umask can
        leave the SQLite file world-readable on shared hosts.
        """
        for candidate in (
            self.path,
            Path(f"{self.path}-wal"),
            Path(f"{self.path}-shm"),
        ):
            with contextlib.suppress(OSError):
                if candidate.exists():
                    os.chmod(candidate, 0o600)
        with contextlib.suppress(OSError):
            if self.path.parent.name == "coldtrail":
                os.chmod(self.path.parent, 0o700)

    def _migrate(self) -> None:
        current_version = self.conn.execute("PRAGMA user_version").fetchone()[0]
        if current_version >= SCHEMA_VERSION:
            trigger = self.conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='trigger' AND name='posts_au'"
            ).fetchone()
            if trigger is None:
                self.conn.execute(POSTS_AU_TRIGGER)
                self.conn.commit()
            return
        self.conn.executescript(SCHEMA)
        self._rebuild_entities()
        for table, columns in COLUMNS.items():
            for name, decl in columns.items():
                self._ensure_column(table, name, decl)
        self._rebuild_profiles()
        # Re-run the DDL so indexes attached to rebuilt tables are recreated.
        self.conn.executescript(SCHEMA)
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_posts_created_ts ON posts(created_ts)")
        self._backfill_post_timestamps()
        self.conn.executescript(FTS)
        # Keep the update trigger narrow: tombstone/metrics updates must not churn FTS.
        self.conn.execute("DROP TRIGGER IF EXISTS posts_au")
        self.conn.execute(POSTS_AU_TRIGGER)
        if current_version < SCHEMA_VERSION:
            with contextlib.suppress(sqlite3.OperationalError):
                self.conn.execute("INSERT INTO posts_fts(posts_fts) VALUES('rebuild')")
            self.conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        self.conn.commit()

    def _unique_indexes(self, table: str) -> list[dict[str, str]]:
        """Return unique indexes as ``{column: collation}`` maps.

        Introspecting ``PRAGMA index_xinfo`` is stable across SQLite versions and
        avoids guessing from the formatted ``sqlite_master`` SQL.
        """
        indexes: list[dict[str, str]] = []
        for row in self.conn.execute(f"PRAGMA index_list({table})"):
            if not row["unique"]:
                continue
            columns: dict[str, str] = {}
            for info in self.conn.execute(f"PRAGMA index_xinfo({row['name']})"):
                if info["name"]:
                    columns[info["name"]] = (info["coll"] or "BINARY").upper()
            indexes.append(columns)
        return indexes

    def _rebuild_entities(self) -> None:
        """Upgrade the entities table to per-profile uniqueness on pre-v3 databases."""
        indexes = self._unique_indexes("entities")
        current = {"run_id", "source", "username", "kind", "value"}
        if any(set(columns) == current for columns in indexes):
            return
        if not any(set(columns) == {"run_id", "kind", "value"} for columns in indexes):
            return
        with self.conn:
            self.conn.execute("ALTER TABLE entities RENAME TO entities_old")
            self.conn.execute(
                """CREATE TABLE entities_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    username TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    context TEXT,
    UNIQUE(run_id, source, username, kind, value)
)"""
            )
            self.conn.execute(
                """INSERT OR IGNORE INTO entities_new
                   (id, run_id, source, username, kind, value, context)
                   SELECT id, run_id, source, username, kind, value, context
                   FROM entities_old"""
            )
            self.conn.execute("DROP TABLE entities_old")
            self.conn.execute("ALTER TABLE entities_new RENAME TO entities")

    def _rebuild_profiles(self) -> None:
        """Make profile identity case-insensitive (schema v5).

        ``Alice`` and ``alice`` are the same account on every supported platform.
        The old unique constraint was case-sensitive while every query used
        ``COLLATE NOCASE``, which produced duplicate profiles and inconsistent
        history/diff output.
        """
        indexes = self._unique_indexes("profiles")
        for columns in indexes:
            if {"run_id", "source", "username"} <= set(columns) and columns.get(
                "username"
            ) == "NOCASE":
                return
        with self.conn:
            self.conn.execute(
                """DELETE FROM profiles WHERE id NOT IN (
                       SELECT MAX(id) FROM profiles GROUP BY run_id, source, lower(username)
                   )"""
            )
            self.conn.execute("ALTER TABLE profiles RENAME TO profiles_old")
            self.conn.execute(
                """CREATE TABLE profiles_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    username TEXT NOT NULL COLLATE NOCASE,
    url TEXT NOT NULL,
    display_name TEXT,
    bio TEXT,
    avatar TEXT,
    avatar_hash TEXT,
    website TEXT,
    created_at TEXT,
    followers INTEGER,
    lang TEXT,
    timezone TEXT,
    extra_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(run_id, source, username)
)"""
            )
            self.conn.execute(
                """INSERT OR IGNORE INTO profiles_new
                   (id, run_id, source, username, url, display_name, bio, avatar,
                    avatar_hash, website, created_at, followers, lang, timezone, extra_json)
                   SELECT id, run_id, source, username, url, display_name, bio, avatar,
                          avatar_hash, website, created_at, followers, lang, timezone, extra_json
                   FROM profiles_old"""
            )
            self.conn.execute("DROP TABLE profiles_old")
            self.conn.execute("ALTER TABLE profiles_new RENAME TO profiles")

    def _ensure_column(self, table: str, column: str, decl: str) -> None:
        existing = {row["name"] for row in self.conn.execute(f"PRAGMA table_info({table})")}
        if column not in existing:
            self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")

    def _backfill_post_timestamps(self) -> None:
        """Normalize pre-v6 post timestamps into epoch seconds.

        Timeline ordering used to compare raw source strings, so timestamps with
        different UTC offsets sorted lexicographically instead of chronologically.
        """
        rows = self.conn.execute(
            "SELECT id, created_at FROM posts WHERE created_ts IS NULL AND created_at IS NOT NULL"
        ).fetchall()
        updates = []
        for row in rows:
            parsed = parse_dt(row["created_at"])
            if parsed is not None:
                updates.append((int(parsed.timestamp()), row["id"]))
        if updates:
            self.conn.executemany("UPDATE posts SET created_ts = ? WHERE id = ?", updates)

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- row helpers --------------------------------------------------------

    @staticmethod
    def _profile_row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["extra"] = json_loads(item.pop("extra_json"), {})
        return item

    @staticmethod
    def _post_row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["metrics"] = json_loads(item.pop("metrics_json"), {})
        return item
