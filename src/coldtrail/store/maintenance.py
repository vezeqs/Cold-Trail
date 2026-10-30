from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any


class MaintenanceMixin:
    conn: Any
    path: Any

    if TYPE_CHECKING:
        # Declared for type checkers only; the methods come from sibling mixins.
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any] | None: ...
        def checks(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]: ...
        def profiles(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]: ...
        def posts(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]: ...
        def links(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]: ...
        def clusters(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]: ...
        def entities(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]: ...
        def edges(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]: ...
        def history(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]: ...
        def attachments(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]: ...

    def export_run(self, run_id: int) -> dict[str, Any]:
        run = self.run(run_id)
        if run is None:
            raise KeyError(f"run {run_id} not found")
        return {
            "run": run,
            "checks": self.checks(run_id, limit=10_000_000),
            "profiles": self.profiles(run_id, limit=None),
            "posts": self.posts(run_id, limit=None),
            "links": self.links(run_id, limit=10_000_000),
            "clusters": self.clusters(run_id, limit=10_000_000),
            "entities": self.entities(run_id, limit=10_000_000),
            "edges": self.edges(run_id, limit=10_000_000),
            "history": self.history(run_id, limit=10_000_000),
            "attachments": self.attachments(run_id=run_id, limit=10_000_000),
        }

    def stats(self) -> dict[str, int]:
        tables = (
            "runs",
            "checks",
            "profiles",
            "posts",
            "links",
            "clusters",
            "entities",
            "edges",
            "profile_history",
            "cases",
            "notes",
            "tags",
            "attachments",
        )
        return {
            table: self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in tables
        }

    def check_stats(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """SELECT source, status, COUNT(*) AS count FROM checks
               GROUP BY source, status ORDER BY source, status"""
        ).fetchall()
        return [dict(row) for row in rows]

    def set_profile_timezone(self, source: str, username: str, timezone: str) -> None:
        with self.conn:
            self.conn.execute(
                """UPDATE profiles SET timezone = ?
                   WHERE source = ? AND username = ? COLLATE NOCASE""",
                (timezone, source, username),
            )

    def profile_hints(self, source: str, username: str) -> dict[str, Any]:
        """Latest stored lang/timezone for a profile, used to revive correlation signals."""
        row = self.conn.execute(
            """SELECT lang, timezone FROM profiles
               WHERE source = ? AND username = ? COLLATE NOCASE
                 AND (lang IS NOT NULL OR timezone IS NOT NULL)
               ORDER BY run_id DESC, id DESC LIMIT 1""",
            (source, username),
        ).fetchone()
        return dict(row) if row else {}

    def prune(self, days: int) -> int:
        if days <= 0:
            return 0
        cutoff = f"-{days} days"
        old_runs = [
            row["id"]
            for row in self.conn.execute(
                "SELECT id FROM runs WHERE datetime(started_at) < datetime('now', ?)",
                (cutoff,),
            )
        ]
        attachments: list[str] = []
        with self.conn:
            if old_runs:
                placeholders = ",".join("?" for _ in old_runs)
                attachments = [
                    row["sha256"]
                    for row in self.conn.execute(
                        f"SELECT sha256 FROM attachments WHERE run_id IN ({placeholders})",
                        old_runs,
                    )
                ]
                self.conn.execute(
                    f"DELETE FROM attachments WHERE run_id IN ({placeholders})", old_runs
                )
            cursor = self.conn.execute(
                "DELETE FROM runs WHERE datetime(started_at) < datetime('now', ?)", (cutoff,)
            )
            self.conn.execute(
                "DELETE FROM raw WHERE datetime(fetched_at) < datetime('now', ?)", (cutoff,)
            )
            self.conn.execute(
                "DELETE FROM http_cache WHERE datetime(fetched_at) < datetime('now', ?)",
                (cutoff,),
            )
            self.conn.execute(
                "DELETE FROM probe_cache WHERE datetime(checked_at) < datetime('now', ?)",
                (cutoff,),
            )
            self.conn.execute(
                "DELETE FROM audit WHERE datetime(at) < datetime('now', ?)", (cutoff,)
            )
        for digest in set(attachments):
            still_referenced = self.conn.execute(
                "SELECT 1 FROM attachments WHERE sha256 = ? LIMIT 1", (digest,)
            ).fetchone()
            if still_referenced:
                continue
            blob = self.path.parent / "evidence" / digest[:2] / digest
            with contextlib.suppress(OSError):
                blob.unlink()
        return cursor.rowcount

    def vacuum(self) -> None:
        self.conn.execute("VACUUM")

    def db_info(self) -> dict[str, Any]:
        size = self.path.stat().st_size if self.path.exists() else 0
        version = self.conn.execute("PRAGMA user_version").fetchone()[0]
        mode = None
        with contextlib.suppress(OSError):
            mode = oct(self.path.stat().st_mode & 0o777)
        return {"path": str(self.path), "size": size, "user_version": version, "mode": mode}
