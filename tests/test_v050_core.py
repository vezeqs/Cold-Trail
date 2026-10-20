"""v0.5.0 Phase 1: persistence, watch, diff, and streaming-export tests."""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from typer.testing import CliRunner

from larpharvester.cli import app
from larpharvester.config import Settings
from larpharvester.correlate import diff_runs
from larpharvester.http import Fetcher
from larpharvester.models import CheckResult, PivotReport, Post, Profile, ProfileChange
from larpharvester.report import iter_csv, iter_jsonl, to_csv, to_jsonl
from larpharvester.sources import SOURCES
from larpharvester.store import Store
from larpharvester.watch import watch

runner = CliRunner()


def profile(**kwargs) -> Profile:
    defaults = {
        "source": "github",
        "username": "alice",
        "url": "https://github.com/alice",
        "display_name": "Alice",
        "bio": "bio",
        "extra": {},
    }
    return Profile(**{**defaults, **kwargs})


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(db_path=tmp_path / "t.db", requests_per_second=0, jitter=0)


# -- history normalization ---------------------------------------------------


def test_history_ignores_none_to_empty_string(settings):
    with Store(settings.db_path) as store:
        first = store.start_run("pivot", "alice")
        store.save_profiles(first, [profile(bio=None)])
        store.finish_run(first)
        second = store.start_run("pivot", "alice")
        store.save_profiles(second, [profile(bio="")])
        changes = store.record_profile_history(second, [profile(bio="")])
    assert changes == []


def test_history_records_none_to_value_and_value_to_none(settings):
    with Store(settings.db_path) as store:
        first = store.start_run("pivot", "alice")
        store.save_profiles(first, [profile(bio=None)])
        store.finish_run(first)
        second = store.start_run("pivot", "alice")
        store.save_profiles(second, [profile(bio="new bio")])
        changes = store.record_profile_history(second, [profile(bio="new bio")])
        assert [(c.field, c.old_value, c.new_value) for c in changes] == [("bio", None, "new bio")]
        third = store.start_run("pivot", "alice")
        store.save_profiles(third, [profile(bio=None)])
        changes = store.record_profile_history(third, [profile(bio=None)])
        assert [(c.field, c.old_value, c.new_value) for c in changes] == [("bio", "new bio", None)]


# -- watch: shared fetcher + alert dedupe ------------------------------------


async def test_watch_shares_one_fetcher_per_cycle_and_dedupes(settings, monkeypatch):
    store = Store(settings.db_path)
    fetchers: list[Fetcher] = []
    report_profile = profile()

    async def fake_pivot(
        target, *, settings, sources=None, expand=False, store=None, fetcher=None, **kwargs
    ):
        fetchers.append(fetcher)
        return PivotReport(
            target=target,
            kind="username",
            results=[CheckResult("github", target, "found", profile=report_profile)],
            links=[],
            expanded=[],
            clusters=[],
            coverage={"found": 1},
        )

    async def fake_harvest(
        source_name, username, *, settings, limit, store=None, run_id=None, fetcher=None, **kwargs
    ):
        fetchers.append(fetcher)
        return CheckResult(source_name, username, "found", profile=report_profile), []

    change = ProfileChange("github", "alice", "bio", None, "new bio", "2024-01-01T00:00:00Z")
    monkeypatch.setattr("larpharvester.watch.pivot", fake_pivot)
    monkeypatch.setattr("larpharvester.watch.harvest", fake_harvest)
    monkeypatch.setattr(store, "record_profile_history", lambda run_id, profiles: [change])

    dispatched: list[tuple[str, str]] = []

    class FakeAlerter:
        name = "fake"

        async def send(self, title: str, body: str) -> bool:
            dispatched.append((title, body))
            return True

    cycles = await watch(
        "alice",
        settings=settings,
        store=store,
        interval=0,
        iterations=2,
        alerters=[FakeAlerter()],
    )
    store.close()

    assert cycles == 2
    # One pivot + one harvest per cycle, and both share that cycle's fetcher.
    assert len(fetchers) == 4
    assert fetchers[0] is fetchers[1]
    assert fetchers[2] is fetchers[3]
    assert fetchers[0] is not fetchers[2]
    # The identical profile change is dispatched only once.
    assert len(dispatched) == 1


# -- GitLab exact user selection ---------------------------------------------


@respx.mock
async def test_gitlab_posts_uses_exact_username_match(settings):
    respx.get("https://gitlab.com/api/v4/users", params={"username": "alice"}).mock(
        return_value=httpx.Response(
            200,
            json=[
                {"id": 1, "username": "alice2"},
                {"id": 2, "username": "alice"},
            ],
        )
    )
    events_route = respx.get(
        "https://gitlab.com/api/v4/users/2/events", params={"per_page": 5, "page": 1}
    ).mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "id": 10,
                    "created_at": "2024-01-01T00:00:00Z",
                    "action_name": "pushed",
                    "target_title": "repo",
                    "project_id": 5,
                }
            ],
        )
    )
    async with Fetcher(settings) as fetcher:
        posts = await SOURCES["gitlab"].posts(fetcher, "alice", 5)
    assert events_route.called
    assert posts and posts[0].post_id == "10"


# -- recluster --save --------------------------------------------------------


def test_recluster_save_persists_links_and_clusters(tmp_path):
    db = tmp_path / "t.db"
    with Store(db) as store:
        run_id = store.start_run("pivot", "alice")
        shared_bio = "distinctive rust security researcher profile text"
        store.save_profiles(
            run_id,
            [
                profile(bio=shared_bio),
                profile(source="gitlab", url="https://gitlab.com/alice", bio=shared_bio),
            ],
        )
        store.finish_run(run_id)
    result = runner.invoke(app, ["--db", str(db), "recluster", "--run", str(run_id), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["saved"] is True
    assert len(payload["links"]) == 1
    with Store(db) as store:
        assert len(store.links(run_id=run_id)) == 1
        assert len(store.clusters(run_id=run_id)) == 1


# -- diff --------------------------------------------------------------------


def test_diff_runs_reports_changes(tmp_path):
    db = tmp_path / "t.db"
    with Store(db) as store:
        first = store.start_run("pivot", "alice")
        store.save_profiles(first, [profile(bio="old bio")])
        store.save_entities(first, [])
        store.save_posts(
            first,
            [Post("github", "alice", "p1", "https://x/1", "2024-01-01T00:00:00Z", "hello")],
        )
        store.finish_run(first)

        second = store.start_run("pivot", "alice")
        store.save_profiles(
            second,
            [profile(bio="new bio"), profile(source="gitlab", url="https://gitlab.com/alice")],
        )
        store.save_posts(
            second,
            [Post("github", "alice", "p2", "https://x/2", "2024-02-01T00:00:00Z", "world")],
        )
        store.finish_run(second)

        payload = diff_runs(store, first, second)

    assert [row["source"] for row in payload["profiles"]["added"]] == ["gitlab"]
    assert payload["profiles"]["changed"][0]["fields"]["bio"] == ["old bio", "new bio"]
    assert payload["posts"]["added"] == [{"source": "github", "post_id": "p2"}]
    assert payload["posts"]["removed"] == [{"source": "github", "post_id": "p1"}]


def test_diff_runs_serializes_links(tmp_path):
    from larpharvester.models import Link

    db = tmp_path / "t.db"
    with Store(db) as store:
        first = store.start_run("pivot", "alice")
        a = profile()
        b = profile(source="gitlab", url="https://gitlab.com/alice")
        store.save_profiles(first, [a, b])
        store.save_links(first, [Link(a, b, 0.9, ["same avatar"])])
        store.finish_run(first)

        second = store.start_run("pivot", "alice")
        store.save_profiles(second, [a, b])
        store.finish_run(second)

        payload = diff_runs(store, first, second)

    assert payload["links"]["removed"] == [
        {
            "source_a": "github",
            "username_a": "alice",
            "source_b": "gitlab",
            "username_b": "alice",
            "score": 0.9,
            "reasons": ["same avatar"],
        }
    ]
    assert payload["links"]["added"] == []


def test_cli_diff_json(tmp_path):
    db = tmp_path / "t.db"
    with Store(db) as store:
        first = store.start_run("pivot", "alice")
        store.save_profiles(first, [profile()])
        store.finish_run(first)
        second = store.start_run("pivot", "alice")
        store.save_profiles(second, [profile(), profile(source="gitlab", username="alice")])
        store.finish_run(second)
    result = runner.invoke(app, ["--db", str(db), "diff", "1", "2", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["profiles"]["added"]
    assert runner.invoke(app, ["--db", str(db), "diff", "1", "999"]).exit_code == 1


# -- streaming exports -------------------------------------------------------


def test_iter_jsonl_matches_to_jsonl():
    payload = {
        "run": {"id": 1, "kind": "pivot", "target": "alice"},
        "profiles": [{"source": "github", "username": "alice"}],
        "posts": [{"source": "github", "post_id": "p1"}],
    }
    assert "\n".join(iter_jsonl(payload)) == to_jsonl(payload)


def test_iter_csv_streams_header_then_rows():
    payload = {
        "profiles": [
            {"source": "github", "username": "alice"},
            {"source": "gitlab", "username": "alice"},
        ]
    }
    chunks = list(iter_csv(payload, "profiles"))
    assert chunks[0].startswith("source,username")
    assert len(chunks) == 3  # header + 2 rows
    assert "".join(chunks) == to_csv(payload, "profiles")
