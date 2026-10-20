from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from .schema import COLUMNS, FTS, POSTS_AU_TRIGGER, SCHEMA, SCHEMA_VERSION


class StoreBase:
    """Connection lifecycle, migrations, and row helpers shared by every mixin."""

    def __init__(self, path: Path) -> None:
        path = Path(path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self._migrate()

    def _migrate(self) -> None:
        current_version = self.conn.execute("PRAGMA user_version").fetchone()[0]
        self.conn.executescript(SCHEMA)
        self._rebuild_entities()
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_entities_value ON entities(value)")
        for table, columns in COLUMNS.items():
            for name, decl in columns.items():
                self._ensure_column(table, name, decl)
        self.conn.executescript(FTS)
        # Keep the update trigger narrow: tombstone/metrics updates must not churn FTS.
        self.conn.execute("DROP TRIGGER IF EXISTS posts_au")
        self.conn.execute(POSTS_AU_TRIGGER)
        if current_version < SCHEMA_VERSION:
            with contextlib.suppress(sqlite3.OperationalError):
                self.conn.execute("INSERT INTO posts_fts(posts_fts) VALUES('rebuild')")
            self.conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        self.conn.commit()

    def _rebuild_entities(self) -> None:
        """Upgrade the entities table to per-profile uniqueness on pre-v3 databases."""
        row = self.conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='entities'"
        ).fetchone()
        if row is None or "UNIQUE(run_id, kind, value)" not in (row["sql"] or ""):
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

    def _ensure_column(self, table: str, column: str, decl: str) -> None:
        existing = {row["name"] for row in self.conn.execute(f"PRAGMA table_info({table})")}
        if column not in existing:
            self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> StoreBase:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- row helpers --------------------------------------------------------

    @staticmethod
    def _profile_row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["extra"] = json.loads(item.pop("extra_json"))
        return item

    @staticmethod
    def _post_row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["metrics"] = json.loads(item.pop("metrics_json"))
        return item
