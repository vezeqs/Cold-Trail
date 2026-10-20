from __future__ import annotations

import json
from typing import Any

from ..models import (
    CheckResult,
    Cluster,
    Edge,
    Entity,
    Link,
    Post,
    Profile,
    ProfileChange,
)
from ..utils import now_iso


class WritesMixin:
    conn: Any

    def save_checks(self, run_id: int, results: list[CheckResult]) -> None:
        with self.conn:
            self.conn.executemany(
                """INSERT INTO checks (run_id, source, target, status, detail)
                   VALUES (?, ?, ?, ?, ?)""",
                [(run_id, r.source, r.target, r.status, r.detail) for r in results],
            )

    def save_profiles(self, run_id: int, profiles: list[Profile]) -> None:
        with self.conn:
            self.conn.executemany(
                """INSERT INTO profiles
                   (run_id, source, username, url, display_name, bio, avatar, avatar_hash,
                    website, created_at, followers, lang, timezone, extra_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(run_id, source, username) DO UPDATE SET
                     url=excluded.url, display_name=excluded.display_name, bio=excluded.bio,
                     avatar=excluded.avatar, avatar_hash=excluded.avatar_hash,
                     website=excluded.website, created_at=excluded.created_at,
                     followers=excluded.followers, lang=excluded.lang,
                     timezone=excluded.timezone, extra_json=excluded.extra_json""",
                [
                    (
                        run_id,
                        p.source,
                        p.username,
                        p.url,
                        p.display_name,
                        p.bio,
                        p.avatar,
                        p.avatar_hash,
                        p.website,
                        p.created_at,
                        p.followers,
                        p.lang,
                        p.timezone,
                        json.dumps(p.extra, ensure_ascii=False),
                    )
                    for p in profiles
                ],
            )

    def save_posts(self, run_id: int, posts: list[Post]) -> None:
        with self.conn:
            self.conn.executemany(
                """INSERT INTO posts
                   (run_id, source, username, post_id, url, created_at, text, metrics_json,
                    fetched_at, deleted_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                   ON CONFLICT(run_id, source, post_id) DO UPDATE SET
                     url=excluded.url, created_at=excluded.created_at, text=excluded.text,
                     metrics_json=excluded.metrics_json, fetched_at=excluded.fetched_at,
                     deleted_at=NULL""",
                [
                    (
                        run_id,
                        p.source,
                        p.username,
                        p.post_id,
                        p.url,
                        p.created_at,
                        p.text,
                        json.dumps(p.metrics, ensure_ascii=False),
                        now_iso(),
                    )
                    for p in posts
                ],
            )

    def mark_missing_posts(
        self,
        source: str,
        username: str,
        seen_ids: set[str],
        run_id: int,
        *,
        since: str | None = None,
    ) -> int:
        """Mark previously stored posts that are no longer returned as deleted."""
        clauses = [
            "source = ?",
            "username = ? COLLATE NOCASE",
            "deleted_at IS NULL",
            "run_id <= ?",
        ]
        params: list[Any] = [source, username, run_id]
        if since:
            clauses.append("created_at >= ?")
            params.append(since)
        where = " AND ".join(clauses)
        rows = self.conn.execute(
            f"SELECT post_id FROM posts WHERE {where}",
            params,
        ).fetchall()
        missing = [row["post_id"] for row in rows if row["post_id"] not in seen_ids]
        if not missing:
            return 0
        with self.conn:
            self.conn.executemany(
                """UPDATE posts SET deleted_at = ?
                   WHERE source = ? AND username = ? COLLATE NOCASE AND post_id = ?""",
                [(now_iso(), source, username, post_id) for post_id in missing],
            )
        return len(missing)

    def save_links(self, run_id: int, links: list[Link]) -> None:
        with self.conn:
            self.conn.executemany(
                """INSERT OR IGNORE INTO links
                   (run_id, source_a, username_a, source_b, username_b, score, reasons_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        run_id,
                        link.a.source,
                        link.a.username,
                        link.b.source,
                        link.b.username,
                        round(link.score, 3),
                        json.dumps(link.reasons, ensure_ascii=False),
                    )
                    for link in links
                ],
            )

    def save_clusters(self, run_id: int, clusters: list[Cluster]) -> None:
        with self.conn:
            for cluster in clusters:
                self.conn.execute(
                    """INSERT OR REPLACE INTO clusters
                       (run_id, cluster_key, score, size, reasons_json)
                       VALUES (?, ?, ?, ?, ?)""",
                    (
                        run_id,
                        cluster.key,
                        round(cluster.score, 3),
                        len(cluster.profiles),
                        json.dumps(cluster.reasons, ensure_ascii=False),
                    ),
                )
                self.conn.executemany(
                    """INSERT OR IGNORE INTO cluster_members
                       (run_id, cluster_key, source, username) VALUES (?, ?, ?, ?)""",
                    [(run_id, cluster.key, p.source, p.username) for p in cluster.profiles],
                )

    def save_entities(self, run_id: int, entities: list[Entity]) -> None:
        with self.conn:
            self.conn.executemany(
                """INSERT OR IGNORE INTO entities
                   (run_id, source, username, kind, value, context)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                [(run_id, e.source, e.username, e.kind, e.value, e.context) for e in entities],
            )

    def save_edges(self, run_id: int, edges: list[Edge]) -> None:
        with self.conn:
            self.conn.executemany(
                """INSERT OR IGNORE INTO edges
                   (run_id, platform, actor, target, direction) VALUES (?, ?, ?, ?, ?)""",
                [(run_id, e.platform, e.actor, e.target, e.direction) for e in edges],
            )

    def record_profile_history(self, run_id: int, profiles: list[Profile]) -> list[ProfileChange]:
        changes: list[ProfileChange] = []
        observed = now_iso()
        for profile in profiles:
            previous = self.conn.execute(
                """SELECT * FROM profiles
                   WHERE source = ? AND username = ? COLLATE NOCASE AND run_id < ?
                   ORDER BY run_id DESC, id DESC LIMIT 1""",
                (profile.source, profile.username, run_id),
            ).fetchone()
            if previous is None:
                continue
            for field in (
                "display_name",
                "bio",
                "avatar",
                "avatar_hash",
                "website",
                "followers",
                "lang",
                "timezone",
            ):
                old = previous[field]
                new = getattr(profile, field)
                if str(old) != str(new):
                    changes.append(
                        ProfileChange(
                            source=profile.source,
                            username=profile.username,
                            field=field,
                            old_value=str(old) if old is not None else None,
                            new_value=str(new) if new is not None else None,
                            observed_at=observed,
                        )
                    )
        if changes:
            with self.conn:
                self.conn.executemany(
                    """INSERT INTO profile_history
                       (run_id, source, username, field, old_value, new_value, observed_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    [
                        (
                            run_id,
                            c.source,
                            c.username,
                            c.field,
                            c.old_value,
                            c.new_value,
                            c.observed_at,
                        )
                        for c in changes
                    ],
                )
        return changes
