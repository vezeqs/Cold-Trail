from __future__ import annotations

import json

import pytest

from coldtrail.models import CheckResult, Link, Post, Profile
from coldtrail.store import Store


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "test.db") as db:
        yield db


def make_profile(**kwargs) -> Profile:
    defaults = {
        "source": "github",
        "username": "alice",
        "url": "https://github.com/alice",
        "display_name": "Alice",
        "bio": "hi",
        "extra": {"public_repos": 3},
    }
    return Profile(**{**defaults, **kwargs})


def test_run_lifecycle(store):
    run_id = store.start_run("pivot", "alice")
    assert store.run(run_id)["status"] == "running"
    store.finish_run(run_id)
    run = store.run(run_id)
    assert run["status"] == "ok"
    assert run["finished_at"]
    assert [r["id"] for r in store.runs()] == [run_id]


def test_profiles_roundtrip(store):
    run_id = store.start_run("pivot", "alice")
    store.save_profiles(run_id, [make_profile()])
    rows = store.profiles(run_id=run_id)
    assert len(rows) == 1
    assert rows[0]["username"] == "alice"
    assert rows[0]["extra"] == {"public_repos": 3}


def test_saving_same_profile_twice_is_idempotent(store):
    run_id = store.start_run("pivot", "alice")
    store.save_profiles(run_id, [make_profile()])
    store.save_profiles(run_id, [make_profile()])
    assert len(store.profiles(run_id=run_id)) == 1


def test_posts_roundtrip_and_username_filter(store):
    run_id = store.start_run("harvest", "github:alice")
    post = Post(
        source="github",
        username="alice",
        post_id="1",
        url="https://github.com/alice",
        text="PushEvent",
        metrics={"commits": 2},
    )
    store.save_posts(run_id, [post])
    rows = store.posts(username="ALICE")
    assert len(rows) == 1
    assert rows[0]["metrics"] == {"commits": 2}
    assert store.posts(username="bob") == []


def test_links_roundtrip(store):
    run_id = store.start_run("pivot", "alice")
    link = Link(a=make_profile(), b=make_profile(source="gitlab"), score=0.7, reasons=["same bio"])
    store.save_links(run_id, [link])
    rows = store.links(run_id=run_id)
    assert len(rows) == 1
    assert rows[0]["reasons"] == ["same bio"]
    assert rows[0]["score"] == 0.7


def test_checks_are_stored(store):
    run_id = store.start_run("pivot", "alice")
    store.save_checks(
        run_id,
        [
            CheckResult("github", "alice", "found", profile=make_profile()),
            CheckResult("reddit", "alice", "not_found"),
            CheckResult("keybase", "alice@example.com", "error", detail="boom"),
        ],
    )
    rows = store.checks(run_id=run_id)
    assert [row["status"] for row in rows] == ["found", "not_found", "error"]
    assert rows[2]["detail"] == "boom"


def test_export_run(store):
    run_id = store.start_run("pivot", "alice")
    store.save_profiles(run_id, [make_profile()])
    store.finish_run(run_id)
    payload = store.export_run(run_id)
    assert payload["run"]["target"] == "alice"
    assert len(payload["profiles"]) == 1
    assert json.loads(json.dumps(payload))["run"]["id"] == run_id


def test_export_missing_run_raises(store):
    with pytest.raises(KeyError):
        store.export_run(999)


def test_profile_identity_is_case_insensitive(store):
    run_id = store.start_run("pivot", "alice")
    store.save_profiles(run_id, [make_profile(username="Alice")])
    store.save_profiles(run_id, [make_profile(username="alice", bio="updated")])
    rows = store.profiles(run_id=run_id)
    assert len(rows) == 1
    assert rows[0]["bio"] == "updated"


def test_history_matches_previous_username_case_insensitively(store):
    first = store.start_run("pivot", "Alice")
    store.save_profiles(first, [make_profile(username="Alice")])
    second = store.start_run("pivot", "alice")
    profile = make_profile(username="alice", bio="new bio")
    store.save_profiles(second, [profile])
    changes = store.record_profile_history(second, [profile])
    assert [change.field for change in changes] == ["bio"]
    assert changes[0].old_value == "hi"
    assert changes[0].new_value == "new bio"


def test_v4_profiles_migrate_to_case_insensitive_identity(tmp_path):
    import sqlite3

    path = tmp_path / "old.db"
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
            username TEXT NOT NULL,
            url TEXT NOT NULL,
            display_name TEXT,
            bio TEXT,
            avatar TEXT,
            website TEXT,
            created_at TEXT,
            followers INTEGER,
            extra_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(run_id, source, username)
        );
        PRAGMA user_version = 4;
        """
    )
    conn.execute(
        "INSERT INTO runs(kind, target, started_at) "
        "VALUES ('pivot', 'Alice', '2024-01-01T00:00:00Z')"
    )
    conn.execute(
        """INSERT INTO profiles(run_id, source, username, url, bio)
           VALUES (1, 'github', 'Alice', 'https://github.com/Alice', 'old')"""
    )
    conn.execute(
        """INSERT INTO profiles(run_id, source, username, url, bio)
           VALUES (1, 'github', 'alice', 'https://github.com/alice', 'new')"""
    )
    conn.commit()
    conn.close()

    with Store(path) as store:
        rows = store.profiles(run_id=1)
        assert len(rows) == 1
        assert rows[0]["bio"] == "new"
        store.save_profiles(1, [make_profile(username="ALICE", bio="latest")])
        rows = store.profiles(run_id=1)
        assert len(rows) == 1
        assert rows[0]["bio"] == "latest"
        assert store.conn.execute("PRAGMA user_version").fetchone()[0] == 6
