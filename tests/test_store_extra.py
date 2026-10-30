from __future__ import annotations

import pytest

from coldtrail.models import Cluster, Edge, Entity, Post, Profile
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


def test_fts_search(store):
    run_id = store.start_run("harvest", "github:alice")
    store.save_posts(
        run_id,
        [
            Post(source="github", username="alice", post_id="1", url="u1", text="alpha beta"),
            Post(source="github", username="alice", post_id="2", url="u2", text="gamma delta"),
        ],
    )
    assert [row["post_id"] for row in store.search("alpha")] == ["1"]
    assert [row["post_id"] for row in store.search("alpha beta")] == ["1"]
    assert store.search("omega") == []


def test_search_snippets_filters_and_prefix(store):
    run_id = store.start_run("harvest", "github:alice")
    store.save_posts(
        run_id,
        [
            Post(source="github", username="alice", post_id="1", url="u1", text="alpha beta"),
            Post(source="gitlab", username="alice", post_id="2", url="u2", text="alphabet soup"),
        ],
    )
    rows = store.search("alpha")
    assert rows[0]["snippet"]
    assert {row["post_id"] for row in store.search("alph", prefix=True)} == {"1", "2"}
    assert [row["post_id"] for row in store.search("alpha", source="github")] == ["1"]
    assert store.search("alpha", source="reddit") == []
    assert [row["post_id"] for row in store.search("alpha", username="ALICE")] == ["1"]


def test_search_profiles_entities_and_all(store):
    run_id = store.start_run("pivot", "alice")
    store.save_profiles(run_id, [profile(bio="alpha researcher")])
    store.save_entities(
        run_id, [Entity("github", "alice", "email", "alpha@example.com", "profile bio")]
    )
    assert [row["username"] for row in store.search_profiles("alpha")] == ["alice"]
    assert [row["value"] for row in store.search_entities("alpha@example.com")] == [
        "alpha@example.com"
    ]
    combined = store.search_all("alpha")
    assert combined["profiles"] and combined["entities"]


def test_profile_history(store):
    first = store.start_run("pivot", "alice")
    store.save_profiles(first, [profile(bio="first bio")])
    store.finish_run(first)

    second = store.start_run("pivot", "alice")
    store.save_profiles(second, [profile(bio="second bio")])
    changes = store.record_profile_history(second, [profile(bio="second bio")])

    assert len(changes) == 1
    assert changes[0].field == "bio"
    assert changes[0].old_value == "first bio"
    assert changes[0].new_value == "second bio"
    assert store.history(username="alice")[0]["field"] == "bio"


def test_entities_and_edges(store):
    run_id = store.start_run("pivot", "alice")
    store.save_entities(
        run_id,
        [Entity(source="github", username="alice", kind="email", value="a@b.com")],
    )
    store.save_edges(
        run_id, [Edge(platform="bluesky", actor="alice", target="bob", direction="follows")]
    )
    assert store.entities(kind="email")[0]["value"] == "a@b.com"
    assert store.edges(actor="alice")[0]["target"] == "bob"


def test_clusters_roundtrip(store):
    run_id = store.start_run("pivot", "alice")
    a = profile()
    b = profile(source="gitlab")
    store.save_clusters(
        run_id,
        [Cluster(key="k1", profiles=[a, b], score=0.8, reasons=["same avatar"])],
    )
    rows = store.clusters(run_id=run_id)
    assert rows[0]["size"] == 2
    assert {member["source"] for member in rows[0]["members"]} == {"github", "gitlab"}


def test_cases_tags_notes(store):
    case_id = store.create_case("op-x", "notes")
    run_id = store.start_run("pivot", "alice")
    store.add_to_case(case_id, run_id)
    assert store.case("OP-X")["runs"][0]["id"] == run_id
    assert store.cases()[0]["runs"] == 1

    store.add_tag("profile", "github:alice", "suspect")
    store.add_note("profile", "github:alice", "check this")
    assert store.tags(target="github:alice")[0]["tag"] == "suspect"
    assert store.notes(target="github:alice")[0]["note"] == "check this"


def test_cursor_roundtrip(store):
    assert store.get_cursor("reddit", "alice") is None
    store.set_cursor("reddit", "alice", "t3_1", "2024-01-01T00:00:00+00:00")
    assert store.get_cursor("reddit", "ALICE")["cursor"] == "t3_1"


def test_cache_and_raw_roundtrip(store):
    store.cache_put(
        "https://x", 200, b"hello", "text/plain", "etag", "", "2024-01-01T00:00:00+00:00"
    )
    cached = store.cache_get("https://x")
    assert cached["body"] == b"hello"
    assert cached["etag"] == "etag"

    store.raw_put("https://x", 200, b'{"a":1}', None)
    assert store.raw_get("https://x")["body"] == b'{"a":1}'


def test_probe_cache(store):
    store.probe_put("github", "alice", "not_found", None)
    assert store.probe_get("github", "alice")["status"] == "not_found"


def test_export_is_not_truncated(store):
    run_id = store.start_run("harvest", "github:alice")
    store.save_posts(
        run_id,
        [
            Post(source="github", username="alice", post_id=str(index), url="u", text="t")
            for index in range(25)
        ],
    )
    payload = store.export_run(run_id)
    assert len(payload["posts"]) == 25


def test_prune(store):
    from coldtrail.evidence import add_evidence, evidence_path

    run_id = store.start_run("pivot", "old")
    evidence = add_evidence(store, data=b"old evidence", filename="old.txt", run_id=run_id)
    blob = evidence_path(store, evidence["sha256"])
    store.audit_log("pivot", "old", {"argv": []})
    store.conn.execute("UPDATE runs SET started_at = '2000-01-01T00:00:00+00:00'")
    store.conn.execute("UPDATE audit SET at = '2000-01-01T00:00:00+00:00'")
    store.conn.commit()
    assert store.prune(30) == 1
    assert store.run(run_id) is None
    assert not blob.exists()
    assert store.audit() == []


def test_check_stats(store):
    run_id = store.start_run("pivot", "alice")
    from coldtrail.models import CheckResult

    store.save_checks(
        run_id,
        [CheckResult("github", "alice", "found"), CheckResult("reddit", "alice", "blocked")],
    )
    stats = {(row["source"], row["status"]): row["count"] for row in store.check_stats()}
    assert stats[("github", "found")] == 1
    assert stats[("reddit", "blocked")] == 1
