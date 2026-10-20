from __future__ import annotations

import json
import re
import sqlite3
from typing import Any


class QueriesMixin:
    conn: Any
    _profile_row: Any
    _post_row: Any

    def checks(self, run_id: int | None = None, limit: int = 200) -> list[dict[str, Any]]:
        if run_id is None:
            rows = self.conn.execute(
                "SELECT * FROM checks ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM checks WHERE run_id = ? ORDER BY id LIMIT ?", (run_id, limit)
            ).fetchall()
        return [dict(row) for row in rows]

    def profiles(
        self,
        run_id: int | None = None,
        source: str | None = None,
        username: str | None = None,
        limit: int | None = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if run_id is not None:
            clauses.append("run_id = ?")
            params.append(run_id)
        if source:
            clauses.append("source = ?")
            params.append(source)
        if username:
            clauses.append("username = ? COLLATE NOCASE")
            params.append(username)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM profiles {where} ORDER BY id DESC"
        if limit is not None:
            sql += " LIMIT ? OFFSET ?"
            params.extend([limit, offset])
        rows = self.conn.execute(sql, params).fetchall()
        return [self._profile_row(row) for row in rows]

    def posts(
        self,
        run_id: int | None = None,
        username: str | None = None,
        source: str | None = None,
        limit: int | None = 100,
        since: str | None = None,
        include_deleted: bool = True,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if run_id is not None:
            clauses.append("run_id = ?")
            params.append(run_id)
        if username:
            clauses.append("username = ? COLLATE NOCASE")
            params.append(username)
        if source:
            clauses.append("source = ?")
            params.append(source)
        if since:
            clauses.append("created_at >= ?")
            params.append(since)
        if not include_deleted:
            clauses.append("deleted_at IS NULL")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM posts {where} ORDER BY id DESC"
        if limit is not None:
            sql += " LIMIT ?"
            params.append(limit)
        rows = self.conn.execute(sql, params).fetchall()
        return [self._post_row(row) for row in rows]

    def links(self, run_id: int | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if run_id is None:
            rows = self.conn.execute(
                "SELECT * FROM links ORDER BY score DESC LIMIT ?", (limit,)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM links WHERE run_id = ? ORDER BY score DESC LIMIT ?",
                (run_id, limit),
            ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["reasons"] = json.loads(item.pop("reasons_json"))
            out.append(item)
        return out

    def clusters(self, run_id: int | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if run_id is None:
            rows = self.conn.execute(
                "SELECT * FROM clusters ORDER BY size DESC LIMIT ?", (limit,)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM clusters WHERE run_id = ? ORDER BY size DESC LIMIT ?",
                (run_id, limit),
            ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["reasons"] = json.loads(item.pop("reasons_json"))
            members = self.conn.execute(
                """SELECT source, username FROM cluster_members
                   WHERE run_id = ? AND cluster_key = ? ORDER BY source, username""",
                (item["run_id"], item["cluster_key"]),
            ).fetchall()
            item["members"] = [dict(m) for m in members]
            out.append(item)
        return out

    def entities(
        self,
        run_id: int | None = None,
        kind: str | None = None,
        value: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if run_id is not None:
            clauses.append("run_id = ?")
            params.append(run_id)
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if value:
            clauses.append("value LIKE ?")
            params.append(f"%{value}%")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        rows = self.conn.execute(
            f"SELECT * FROM entities {where} ORDER BY id DESC LIMIT ?", params
        ).fetchall()
        return [dict(row) for row in rows]

    def edges(
        self,
        run_id: int | None = None,
        platform: str | None = None,
        actor: str | None = None,
        target: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if run_id is not None:
            clauses.append("run_id = ?")
            params.append(run_id)
        if platform:
            clauses.append("platform = ?")
            params.append(platform)
        if actor:
            clauses.append("actor = ? COLLATE NOCASE")
            params.append(actor)
        if target:
            clauses.append("target = ? COLLATE NOCASE")
            params.append(target)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        rows = self.conn.execute(
            f"SELECT * FROM edges {where} ORDER BY id DESC LIMIT ?", params
        ).fetchall()
        return [dict(row) for row in rows]

    def history(
        self,
        run_id: int | None = None,
        source: str | None = None,
        username: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if run_id is not None:
            clauses.append("run_id = ?")
            params.append(run_id)
        if source:
            clauses.append("source = ?")
            params.append(source)
        if username:
            clauses.append("username = ? COLLATE NOCASE")
            params.append(username)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        rows = self.conn.execute(
            f"SELECT * FROM profile_history {where} ORDER BY id DESC LIMIT ?", params
        ).fetchall()
        return [dict(row) for row in rows]

    def search(self, query: str, limit: int = 50) -> list[dict[str, Any]]:
        # Sanitize query tokens: keep only alphanumeric and basic terms, escape quotes
        tokens = [
            token.replace('"', '""')
            for token in query.split()
            if re.sub(r"[^\w]", "", token).strip()
        ]
        if not tokens:
            return []
        match = " AND ".join(f'"{token}"' for token in tokens)
        try:
            rows = self.conn.execute(
                """SELECT p.*, bm25(posts_fts) AS rank
                   FROM posts_fts JOIN posts p ON p.id = posts_fts.rowid
                   WHERE posts_fts MATCH ? ORDER BY rank LIMIT ?""",
                (match, limit),
            ).fetchall()
        except sqlite3.OperationalError:
            return []
        out = []
        for row in rows:
            item = self._post_row(row)
            out.append(item)
        return out

    def timeline(self, run_id: int | None = None, limit: int = 500) -> list[dict[str, Any]]:
        rows = self.posts(run_id=run_id, limit=limit)
        return sorted(rows, key=lambda row: row["created_at"] or "")
