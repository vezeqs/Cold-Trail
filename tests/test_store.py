from __future__ import annotations

import json

import pytest

from larpharvester.models import CheckResult, Link, Post, Profile
from larpharvester.store import Store


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
