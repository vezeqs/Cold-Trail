from __future__ import annotations

import zlib
from typing import Any

from ..utils import now_iso


class CachesMixin:
    conn: Any

    def get_cursor(self, source: str, username: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM cursors WHERE source = ? AND username = ? COLLATE NOCASE",
            (source, username),
        ).fetchone()
        return dict(row) if row else None

    def set_cursor(self, source: str, username: str, cursor: str, last_seen_at: str) -> None:
        with self.conn:
            self.conn.execute(
                """INSERT INTO cursors (source, username, cursor, last_seen_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(source, username) DO UPDATE SET
                     cursor=excluded.cursor, last_seen_at=excluded.last_seen_at""",
                (source, username, cursor, last_seen_at),
            )

    def probe_get(self, source: str, target: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM probe_cache WHERE source = ? AND target = ?",
            (source, target),
        ).fetchone()
        return dict(row) if row else None

    def probe_put(self, source: str, target: str, status: str, detail: str | None) -> None:
        with self.conn:
            self.conn.execute(
                """INSERT INTO probe_cache (source, target, status, detail, checked_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(source, target) DO UPDATE SET
                     status=excluded.status, detail=excluded.detail,
                     checked_at=excluded.checked_at""",
                (source, target, status, detail, now_iso()),
            )

    def cache_get(self, url: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM http_cache WHERE url = ?", (url,)).fetchone()
        if row is None:
            return None
        item = dict(row)
        try:
            item["body"] = zlib.decompress(item["body"])
        except zlib.error:
            return None
        return item

    def cache_put(
        self,
        url: str,
        status: int,
        body: bytes,
        content_type: str,
        etag: str,
        last_modified: str,
        fetched_at: str,
        final_url: str | None = None,
    ) -> None:
        with self.conn:
            self.conn.execute(
                """INSERT INTO http_cache
                   (url, status, content_type, etag, last_modified, body, fetched_at, final_url)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(url) DO UPDATE SET
                     status=excluded.status, content_type=excluded.content_type,
                     etag=excluded.etag, last_modified=excluded.last_modified,
                     body=excluded.body, fetched_at=excluded.fetched_at,
                     final_url=excluded.final_url""",
                (
                    url,
                    status,
                    content_type,
                    etag,
                    last_modified,
                    zlib.compress(body),
                    fetched_at,
                    final_url or url,
                ),
            )

    def raw_put(self, url: str, status: int, body: bytes, run_id: int | None) -> None:
        compressed = zlib.compress(body)
        with self.conn:
            existing = self.conn.execute(
                "SELECT id FROM raw WHERE url = ? AND status = ? AND body = ? LIMIT 1",
                (url, status, compressed),
            ).fetchone()
            if existing:
                return
            self.conn.execute(
                "INSERT INTO raw (url, status, body, fetched_at, run_id) VALUES (?, ?, ?, ?, ?)",
                (url, status, compressed, now_iso(), run_id),
            )

    def raw_get(self, url: str) -> dict[str, Any] | None:
        rows = self.conn.execute(
            "SELECT * FROM raw WHERE url = ? ORDER BY id DESC", (url,)
        ).fetchall()
        for row in rows:
            item = dict(row)
            try:
                item["body"] = zlib.decompress(item["body"])
            except zlib.error:
                continue
            return item
        return None
