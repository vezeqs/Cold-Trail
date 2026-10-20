from __future__ import annotations

from typing import Any

from ..utils import now_iso


class RunsMixin:
    conn: Any

    def start_run(self, kind: str, target: str) -> int:
        with self.conn:
            cursor = self.conn.execute(
                "INSERT INTO runs (kind, target, started_at) VALUES (?, ?, ?)",
                (kind, target, now_iso()),
            )
        return int(cursor.lastrowid)

    def finish_run(self, run_id: int, status: str = "ok") -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE runs SET finished_at = ?, status = ? WHERE id = ?",
                (now_iso(), status, run_id),
            )

    def runs(self, limit: int = 25, offset: int = 0) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM runs ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset)
        ).fetchall()
        return [dict(row) for row in rows]

    def count_runs(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0])

    def run(self, run_id: int) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        return dict(row) if row else None
