"""Regression tests for the 0.2.x fix round: source selection, discovery
heuristics, cache robustness, tombstone windows, and store split surface."""

from __future__ import annotations

import zlib

import pytest

from coldtrail.models import CheckResult, Edge, Entity, Post, Profile
from coldtrail.pivot import (
    _username_from_url,
    discovered_usernames,
    select_sources,
)
from coldtrail.store import Store


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "t.db") as db:
        yield db


def profile(**kwargs) -> Profile:
    defaults = {
        "source": "github",
        "username": "alice",
        "url": "https://github.com/alice",
        "display_name": "Alice",
        "bio": "first bio",
        "extra": {},
    }
    return Profile(**{**defaults, **kwargs})


# -- select_sources kind enforcement -----------------------------------------


def test_select_sources_rejects_wrong_kind_named_source():
    with pytest.raises(ValueError, match="not usable for email"):
        select_sources(["github"], "email")


def test_select_sources_rejects_unknown_and_reports():
    with pytest.raises(ValueError, match="unknown source"):
        select_sources(["not-a-source"], "username")


def test_select_sources_group_resolves_to_kind_only():
    picked = select_sources(["social"], "username")
    assert picked
    assert all(source.kind == "username" for source in picked)


def test_select_sources_all_keyword_respects_kind():
    picked = select_sources(["all"], "email")
    assert picked
    assert all(source.kind == "email" for source in picked)


# -- URL handle extraction ----------------------------------------------------


def test_username_from_url_query_param():
    assert _username_from_url("https://news.ycombinator.com/user?id=pg") == "pg"


def test_username_from_url_skips_subresource_segments():
    assert _username_from_url("https://keybase.io/alice/sigs") == "alice"
    assert _username_from_url("https://www.linkedin.com/in/alice") == "alice"
    assert _username_from_url("https://steamcommunity.com/id/alice/") == "alice"


def test_username_from_url_rejects_structural_paths():
    assert _username_from_url("https://example.com/user") is None
    assert _username_from_url("https://example.com/") is None
    assert _username_from_url("not-a-url") is None


def test_discovered_usernames_filters_and_dedupes():
    results = [
        CheckResult(
            "gravatar",
            "a@x.com",
            "found",
            profile=Profile(
                source="gravatar",
                username="alice",
                url="https://gravatar.com/alice",
                extra={
                    "accounts": [
                        {"username": "Alice"},
                        {"username": "bob smith"},
                        {"username": "12345"},
                        {"username": "a@b.com"},
                        {"url": "https://mastodon.social/@bob_"},
                    ]
                },
            ),
        )
    ]
    found = discovered_usernames(results)
    assert "alice" in [f.casefold() for f in found]
    assert "bob_" in found
    assert "bob smith" not in found
    assert "12345" not in found
    assert not any("@" in f for f in found)


def test_discovered_usernames_limit():
    results = [
        CheckResult(
            "emailrep",
            "a@x.com",
            "found",
            profile=Profile(
                source="emailrep",
                username="root",
                url="https://emailrep.io/a@x.com",
                extra={"accounts": [{"username": f"u{i}"} for i in range(10)]},
            ),
        )
    ]
    assert len(discovered_usernames(results, limit=3)) == 3
    # The email-source username ("root") is not trusted; only the 10 accounts expand.
    assert len(discovered_usernames(results, limit=0)) == 10


# -- HTTP cache robustness -----------------------------------------------------


def test_cache_get_tolerates_corrupt_body(store):
    url = "https://example.test/page"
    store.cache_put(url, 200, b"ok-body", "text/html", "", "", "2024-01-01T00:00:00Z")
    assert store.cache_get(url)["body"] == b"ok-body"
    with store.conn:
        store.conn.execute("UPDATE http_cache SET body = ? WHERE url = ?", (b"not-zlib", url))
    assert store.cache_get(url) is None


def test_cache_final_url_roundtrip(store):
    store.cache_put(
        "https://example.test/a",
        200,
        b"x",
        "text/html",
        "",
        "",
        "2024-01-01T00:00:00Z",
        final_url="https://example.test/redirected",
    )
    assert store.cache_get("https://example.test/a")["final_url"] == (
        "https://example.test/redirected"
    )


def test_raw_dedupes_identical_captures(store):
    store.raw_put("https://example.test/r", 200, b"same", None)
    store.raw_put("https://example.test/r", 200, b"same", None)
    row = store.conn.execute("SELECT COUNT(*) AS n FROM raw").fetchone()
    assert row["n"] == 1


# -- tombstone window ----------------------------------------------------------


def test_mark_missing_respects_since_window(store):
    r1 = store.start_run("harvest", "github:alice")
    store.save_posts(
        r1,
        [
            Post(
                source="github",
                username="alice",
                post_id="old",
                url="https://x/1",
                created_at="2020-01-01T00:00:00Z",
                text="old",
            ),
            Post(
                source="github",
                username="alice",
                post_id="recent",
                url="https://x/2",
                created_at="2024-06-01T00:00:00Z",
                text="recent",
            ),
        ],
    )
    r2 = store.start_run("harvest", "github:alice")
    # The re-fetch only covered 2023+; "old" is outside the window and must not
    # be tombstoned even though it is absent from seen_ids.
    marked = store.mark_missing_posts("github", "alice", set(), r2, since="2023-01-01T00:00:00Z")
    assert marked == 1
    posts = {p["post_id"]: p for p in store.posts()}
    assert posts["old"]["deleted_at"] is None
    assert posts["recent"]["deleted_at"] is not None


def test_include_deleted_filter(store):
    rid = store.start_run("harvest", "github:alice")
    store.save_posts(
        rid,
        [
            Post(
                source="github",
                username="alice",
                post_id="p1",
                url="https://x/1",
                created_at="2024-01-01T00:00:00Z",
                text="kept",
            )
        ],
    )
    r2 = store.start_run("harvest", "github:alice")
    store.mark_missing_posts("github", "alice", set(), r2, since="2020-01-01")
    assert store.posts(include_deleted=False) == []
    assert len(store.posts(include_deleted=True)) == 1


# -- entities: shared values across profiles -----------------------------------


def test_same_entity_value_from_two_profiles_both_persist(store):
    rid = store.start_run("pivot", "alice")
    store.save_entities(
        rid,
        [
            Entity("github", "alice", "btc", "bc1qshared"),
            Entity("gitlab", "alice", "btc", "bc1qshared"),
        ],
    )
    rows = store.entities(run_id=rid, kind="btc")
    assert len(rows) == 2
    assert {r["source"] for r in rows} == {"github", "gitlab"}


# -- profile hints -------------------------------------------------------------


def test_profile_hints_returns_lang_and_timezone(store):
    rid = store.start_run("pivot", "alice")
    store.save_profiles(rid, [profile(lang="fr", timezone="+02:00")])
    hints = store.profile_hints("github", "alice")
    assert hints.get("lang") == "fr"
    assert hints.get("timezone") == "+02:00"


def test_profile_hints_empty_when_no_signals(store):
    rid = store.start_run("pivot", "alice")
    store.save_profiles(rid, [profile()])
    assert store.profile_hints("github", "alice") == {}
    assert store.profile_hints("github", "nobody") == {}


# -- edges target filter -------------------------------------------------------


def test_edges_target_filter(store):
    rid = store.start_run("graph", "github:alice")
    store.save_edges(
        rid,
        [
            Edge("github", "alice", "bob"),
            Edge("github", "alice", "carol"),
            Edge("github", "dave", "bob"),
        ],
    )
    assert {e["actor"] for e in store.edges(target="bob")} == {"alice", "dave"}
    assert len(store.edges(actor="alice")) == 2


# -- FTS stays in sync on update ------------------------------------------------


def test_fts_reflects_updated_post_text(store):
    rid = store.start_run("harvest", "github:alice")
    post = Post(
        source="github",
        username="alice",
        post_id="p1",
        url="https://x/1",
        created_at="2024-01-01T00:00:00Z",
        text="alpha beta",
    )
    store.save_posts(rid, [post])
    assert store.search("alpha")
    with store.conn:
        store.conn.execute("UPDATE posts SET text = 'gamma delta' WHERE post_id = 'p1'")
    assert store.search("gamma")
    assert store.search("alpha") == []


# -- compressed garbage never escapes raw_get ------------------------------------


def test_raw_get_tolerates_corrupt_body(store):
    with store.conn:
        store.conn.execute(
            "INSERT INTO raw (url, status, body, fetched_at, run_id) VALUES (?, ?, ?, ?, NULL)",
            ("https://example.test/raw", 200, zlib.compress(b"fine"), "2024-01-01T00:00:00Z"),
        )
        store.conn.execute(
            "INSERT INTO raw (url, status, body, fetched_at, run_id) VALUES (?, ?, ?, ?, NULL)",
            ("https://example.test/raw", 500, b"junk", "2024-01-02T00:00:00Z"),
        )
    # Most recent row is corrupt -> fall back to the previous valid capture
    assert store.raw_get("https://example.test/raw")["body"] == b"fine"


# -- corpus size in user-facing help matches the loaded web group -----------------


def test_pivot_web_help_states_real_corpus_size():
    """The --web help must name the web-group size, not the curated+web total.

    A stale hardcoded number (482) shipped while the corpus was 432 sites;
    derive the invariant instead of trusting the string.
    """
    from coldtrail.cli.collect import WEB_CORPUS_COUNT
    from coldtrail.sources import SOURCES

    web_count = sum(1 for source in SOURCES.values() if source.group == "web")
    assert WEB_CORPUS_COUNT == web_count > 0
    # The help text embeds exactly that number.
    from typer.testing import CliRunner

    from coldtrail.cli import app

    result = CliRunner(env={"COLUMNS": "200", "TERM": "dumb"}).invoke(app, ["pivot", "--help"])
    assert result.exit_code == 0
    flat = " ".join(result.output.replace("│", " ").split())
    assert f"{web_count}-site web corpus" in flat
    assert f"{len(SOURCES)}-site web corpus" not in flat


def test_pivot_page_states_real_corpus_size(tmp_path):
    """The /pivot page must not hardcode a stale web-corpus number."""
    from fastapi.testclient import TestClient

    from coldtrail.config import Settings
    from coldtrail.sources import SOURCES
    from coldtrail.web import create_app

    web_count = sum(1 for source in SOURCES.values() if source.group == "web")
    settings = Settings.load()
    settings.db_path = tmp_path / "pivot-page.db"
    client = TestClient(create_app(settings))
    response = client.get("/pivot")
    assert response.status_code == 200
    assert f"{web_count}-site web corpus" in response.text
    assert "482-site web corpus" not in response.text


# -- docs site primary nav is identical across pages ----------------------------


def test_docs_pages_share_primary_nav():
    """Every docs page must expose the same primary navigation links.

    sources.html shipped without the Comparison and Privacy nav links; assert
    the link set is uniform so a page cannot silently drop routes again.
    """
    import re
    from pathlib import Path

    docs = Path(__file__).resolve().parent.parent / "docs"
    pages = ["index.html", "quickstart.html", "sources.html", "comparison.html", "privacy.html"]
    navs = {}
    for name in pages:
        html = (docs / name).read_text(encoding="utf-8")
        block = re.search(r'<div class="nav-links">(.*?)</div>', html, re.S)
        assert block, f"{name} missing nav-links div"
        navs[name] = re.findall(r'href="([^"]+)"', block.group(1))
    reference = navs["index.html"]
    for name, links in navs.items():
        assert links == reference, f"{name} nav differs: {links} != {reference}"


def test_docs_sitemap_lists_main_pages():
    """sitemap.xml must cover every indexable docs page (404 is noindex)."""
    import re
    from pathlib import Path

    docs = Path(__file__).resolve().parent.parent / "docs"
    sitemap = (docs / "sitemap.xml").read_text(encoding="utf-8")
    listed = set(re.findall(r"<loc>https://vezeqs\.github\.io/Cold-Trail/([^<]*)</loc>", sitemap))
    expected = {"", "quickstart.html", "sources.html", "comparison.html", "privacy.html"}
    assert listed == expected
    # 404 must stay out of the index
    assert "noindex" in (docs / "404.html").read_text(encoding="utf-8")


# -- timeline ordering and schema v6 ----------------------------------------


def test_timeline_orders_by_instant_not_string(store):
    run_id = store.start_run("harvest", "alice")
    store.save_posts(
        run_id,
        [
            # 10:00+02:00 is 08:00Z, earlier than 09:00Z even though it sorts later as text.
            Post("github", "alice", "offset", "u1", "2024-01-01T10:00:00+02:00", "a"),
            Post("github", "alice", "utc", "u2", "2024-01-01T09:00:00+00:00", "b"),
        ],
    )
    assert [row["post_id"] for row in store.timeline(run_id=run_id)] == ["offset", "utc"]


def test_timeline_limit_returns_newest_window(store):
    run_id = store.start_run("harvest", "alice")
    store.save_posts(
        run_id,
        [
            Post("github", "alice", "p1", "u1", "2024-01-01T00:00:00Z", "one"),
            Post("github", "alice", "p2", "u2", "2024-01-02T00:00:00Z", "two"),
            Post("github", "alice", "p3", "u3", "2024-01-03T00:00:00Z", "three"),
        ],
    )
    assert [row["post_id"] for row in store.timeline(limit=2)] == ["p2", "p3"]
    assert [
        row["post_id"]
        for row in store.timeline(since="2024-01-02T00:00:00Z", until="2024-01-02T23:59:59Z")
    ] == ["p2"]


def test_v5_posts_migrate_to_epoch_timestamps(tmp_path):
    import sqlite3

    path = tmp_path / "v5.db"
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            target TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            status TEXT NOT NULL DEFAULT 'running'
        );
        CREATE TABLE profiles (
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
        );
        CREATE TABLE posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
            source TEXT NOT NULL,
            username TEXT NOT NULL,
            post_id TEXT NOT NULL,
            url TEXT NOT NULL,
            created_at TEXT,
            text TEXT,
            metrics_json TEXT NOT NULL DEFAULT '{}',
            fetched_at TEXT,
            deleted_at TEXT,
            UNIQUE(run_id, source, post_id)
        );
        PRAGMA user_version = 5;
        """
    )
    conn.execute(
        "INSERT INTO runs(kind, target, started_at) "
        "VALUES ('harvest', 'alice', '2024-01-01T00:00:00Z')"
    )
    conn.execute(
        "INSERT INTO posts(run_id, source, username, post_id, url, created_at) "
        "VALUES (1, 'github', 'alice', 'p1', 'u', '2024-01-01T10:00:00+02:00')"
    )
    conn.commit()
    conn.close()

    with Store(path) as store:
        assert store.conn.execute("PRAGMA user_version").fetchone()[0] == 7
        row = store.conn.execute("SELECT created_ts FROM posts").fetchone()
        assert row["created_ts"] == 1704096000
        assert [post["post_id"] for post in store.timeline()] == ["p1"]
