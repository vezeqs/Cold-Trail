from __future__ import annotations

import json
from typing import Any

from ..utils import json_loads, now_iso


class CasesMixin:
    conn: Any

    def audit_log(self, command: str, target: str | None, args: dict[str, Any]) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO audit (at, command, target, args_json) VALUES (?, ?, ?, ?)",
                (now_iso(), command, target, json.dumps(args, ensure_ascii=False, default=str)),
            )

    def audit(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["args"] = json_loads(item.pop("args_json"), {})
            out.append(item)
        return out

    def create_case(self, name: str, notes: str | None = None) -> int:
        name = name.strip()
        if not name:
            raise ValueError("case name must be non-empty")
        if len(name) > 120:
            raise ValueError("case name must be at most 120 characters")
        with self.conn:
            cursor = self.conn.execute(
                "INSERT INTO cases (name, created_at, notes) VALUES (?, ?, ?)",
                (name, now_iso(), notes),
            )
        return int(cursor.lastrowid)

    def add_to_case(self, case_id: int, run_id: int) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT OR IGNORE INTO case_runs (case_id, run_id) VALUES (?, ?)",
                (case_id, run_id),
            )

    def cases(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """SELECT c.*, COUNT(cr.run_id) AS runs
               FROM cases c LEFT JOIN case_runs cr ON cr.case_id = c.id
               GROUP BY c.id ORDER BY c.id DESC"""
        ).fetchall()
        return [dict(row) for row in rows]

    def case(self, name: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM cases WHERE name = ? COLLATE NOCASE", (name,)
        ).fetchone()
        if row is None:
            return None
        case = dict(row)
        runs = self.conn.execute(
            """SELECT r.* FROM runs r JOIN case_runs cr ON cr.run_id = r.id
               WHERE cr.case_id = ? ORDER BY r.id""",
            (case["id"],),
        ).fetchall()
        case["runs"] = [dict(run) for run in runs]
        return case

    def add_tag(self, target_type: str, target: str, tag: str) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT OR IGNORE INTO tags (target_type, target, tag) VALUES (?, ?, ?)",
                (target_type, target, tag),
            )

    def tags(
        self, target_type: str | None = None, target: str | None = None
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if target_type:
            clauses.append("target_type = ?")
            params.append(target_type)
        if target:
            clauses.append("target = ? COLLATE NOCASE")
            params.append(target)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self.conn.execute(f"SELECT * FROM tags {where} ORDER BY id DESC", params).fetchall()
        return [dict(row) for row in rows]

    def add_note(self, target_type: str, target: str, note: str) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO notes (target_type, target, note, created_at) VALUES (?, ?, ?, ?)",
                (target_type, target, note, now_iso()),
            )

    def notes(
        self, target_type: str | None = None, target: str | None = None
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if target_type:
            clauses.append("target_type = ?")
            params.append(target_type)
        if target:
            clauses.append("target = ? COLLATE NOCASE")
            params.append(target)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self.conn.execute(f"SELECT * FROM notes {where} ORDER BY id DESC", params).fetchall()
        return [dict(row) for row in rows]

    # -- attachments (evidence) ---------------------------------------------

    def add_attachment(
        self,
        *,
        run_id: int | None,
        target_type: str,
        target: str | None,
        sha256: str,
        filename: str,
        media_type: str,
        size: int,
        note: str | None,
    ) -> int:
        with self.conn:
            cursor = self.conn.execute(
                """INSERT INTO attachments
                   (run_id, target_type, target, sha256, filename, media_type,
                    size, note, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id,
                    target_type,
                    target,
                    sha256,
                    filename,
                    media_type,
                    size,
                    note,
                    now_iso(),
                ),
            )
        return int(cursor.lastrowid)

    def attachments(
        self,
        run_id: int | None = None,
        target_type: str | None = None,
        target: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if run_id is not None:
            clauses.append("run_id = ?")
            params.append(run_id)
        if target_type:
            clauses.append("target_type = ?")
            params.append(target_type)
        if target:
            clauses.append("target = ? COLLATE NOCASE")
            params.append(target)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([limit, offset])
        rows = self.conn.execute(
            f"SELECT * FROM attachments {where} ORDER BY id DESC LIMIT ? OFFSET ?", params
        ).fetchall()
        return [dict(row) for row in rows]

    def attachment(self, attachment_id: int) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM attachments WHERE id = ?", (attachment_id,)
        ).fetchone()
        return dict(row) if row else None
