from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from ..utils import epoch_seconds


def _like_pattern(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


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
        until: str | None = None,
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
            since_ts = epoch_seconds(since)
            if since_ts is not None:
                clauses.append("created_ts >= ?")
                params.append(since_ts)
            else:
                clauses.append("created_at >= ?")
                params.append(since)
        if until:
            until_ts = epoch_seconds(until)
            if until_ts is not None:
                clauses.append("created_ts <= ?")
                params.append(until_ts)
            else:
                clauses.append("created_at <= ?")
                params.append(until)
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

    def search(
        self,
        query: str,
        limit: int = 50,
        *,
        prefix: bool = False,
        source: str | None = None,
        username: str | None = None,
    ) -> list[dict[str, Any]]:
        # Sanitize query tokens: keep only alphanumeric and basic terms, escape quotes
        tokens = [
            token.replace('"', '""')
            for token in query.split()
            if re.sub(r"[^\w]", "", token).strip()
        ]
        if not tokens:
            return []
        terms = [f'"{token}"*' if prefix else f'"{token}"' for token in tokens]
        clauses = ["posts_fts MATCH ?"]
        params: list[Any] = [" AND ".join(terms)]
        if source:
            clauses.append("p.source = ?")
            params.append(source)
        if username:
            clauses.append("p.username = ? COLLATE NOCASE")
            params.append(username)
        params.append(limit)
        try:
            rows = self.conn.execute(
                f"""SELECT p.*, bm25(posts_fts) AS rank,
                           snippet(posts_fts, 0, '', '', '…', 12) AS snippet
                    FROM posts_fts JOIN posts p ON p.id = posts_fts.rowid
                    WHERE {' AND '.join(clauses)} ORDER BY rank LIMIT ?""",
                params,
            ).fetchall()
        except sqlite3.OperationalError:
            return []
        return [self._post_row(row) for row in rows]

    def search_profiles(self, query: str, limit: int = 100) -> list[dict[str, Any]]:
        pattern = _like_pattern(query.strip())
        rows = self.conn.execute(
            """SELECT * FROM profiles
               WHERE username LIKE ? ESCAPE '\\'
                  OR display_name LIKE ? ESCAPE '\\'
                  OR bio LIKE ? ESCAPE '\\'
                  OR website LIKE ? ESCAPE '\\'
               ORDER BY id DESC LIMIT ?""",
            (pattern, pattern, pattern, pattern, limit),
        ).fetchall()
        return [self._profile_row(row) for row in rows]

    def search_entities(self, query: str, limit: int = 100) -> list[dict[str, Any]]:
        pattern = _like_pattern(query.strip())
        rows = self.conn.execute(
            """SELECT * FROM entities
               WHERE value LIKE ? ESCAPE '\\' OR context LIKE ? ESCAPE '\\'
               ORDER BY id DESC LIMIT ?""",
            (pattern, pattern, limit),
        ).fetchall()
        return [dict(row) for row in rows]

    def search_all(
        self,
        query: str,
        limit: int = 50,
        *,
        prefix: bool = False,
        source: str | None = None,
        username: str | None = None,
    ) -> dict[str, list[dict[str, Any]]]:
        return {
            "posts": self.search(
                query, limit=limit, prefix=prefix, source=source, username=username
            ),
            "profiles": self.search_profiles(query, limit=limit),
            "entities": self.search_entities(query, limit=limit),
        }

    def timeline(
        self,
        run_id: int | None = None,
        limit: int | None = 500,
        since: str | None = None,
        until: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return posts in chronological order, newest window first in SQL."""
        clauses: list[str] = []
        params: list[Any] = []
        if run_id is not None:
            clauses.append("run_id = ?")
            params.append(run_id)
        for value, operator in ((since, ">="), (until, "<=")):
            if not value:
                continue
            stamp = epoch_seconds(value)
            if stamp is not None:
                clauses.append(f"created_ts {operator} ?")
                params.append(stamp)
            else:
                clauses.append(f"created_at {operator} ?")
                params.append(value)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (
            f"SELECT * FROM posts {where} "
            "ORDER BY created_ts IS NULL, created_ts DESC, id DESC"
        )
        if limit is not None:
            sql += " LIMIT ?"
            params.append(limit)
        rows = self.conn.execute(sql, params).fetchall()
        return [self._post_row(row) for row in reversed(rows)]
