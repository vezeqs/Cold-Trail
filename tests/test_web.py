"""Web UI and JSON API tests. No network: TestClient against a seeded SQLite db."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

import larpharvester.web.app as web_app
from larpharvester.config import Settings
from larpharvester.models import (
    CheckResult,
    Cluster,
    Edge,
    Entity,
    Link,
    PivotReport,
    Post,
    Profile,
)
from larpharvester.store import Store
from larpharvester.web import create_app


def _profile(**kwargs) -> Profile:
    defaults = {
        "source": "github",
        "username": "alice",
        "url": "https://github.com/alice",
        "display_name": "Alice",
        "bio": "security researcher",
        "followers": 12,
        "extra": {},
    }
    return Profile(**{**defaults, **kwargs})


@pytest.fixture
def settings(tmp_path) -> Settings:
    base = Settings.load()
    base.db_path = tmp_path / "web.db"
    return base


@pytest.fixture
def seeded(settings):
    profile = _profile()
    with Store(settings.db_path) as store:
        run_id = store.start_run("pivot", "alice")
        store.save_checks(
            run_id,
            [
                CheckResult("github", "alice", "found", profile=profile),
                CheckResult("reddit", "alice", "not_found", detail="no such user"),
                CheckResult("twitter", "alice", "blocked", detail="bot wall"),
            ],
        )
        store.save_profiles(run_id, [profile])
        store.save_posts(
            run_id,
            [
                Post(
                    source="github",
                    username="alice",
                    post_id="p1",
                    url="https://example.test/p1",
                    created_at="2024-01-01T00:00:00Z",
                    text="hello crypto wallet world",
                )
            ],
        )
        store.save_links(
            run_id,
            [
                Link(
                    _profile(),
                    _profile(source="gitlab", url="https://gitlab.com/alice"),
                    0.7,
                    ["same bio"],
                )
            ],
        )
        store.save_clusters(run_id, [Cluster("github:alice", [profile], 0.7, ["same bio"])])
        store.save_entities(run_id, [Entity("github", "alice", "email", "a@example.com")])
        store.save_edges(run_id, [Edge("github", "alice", "bob")])
        store.record_profile_history(run_id, [profile])
        store.add_tag("profile", "github:alice", "suspect")
        store.add_note("profile", "github:alice", "check the avatar")
        store.create_case("op-x")
        store.finish_run(run_id)
    return 1


@pytest.fixture
def client(settings) -> TestClient:
    return TestClient(create_app(settings))


# -- pages ------------------------------------------------------------------


def test_dashboard_renders(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "Dashboard" in response.text
    assert "larpharvester" in response.text


def test_dashboard_with_data(client, seeded):
    response = client.get("/")
    assert response.status_code == 200
    assert "alice" in response.text
    assert "crypto" not in response.text  # posts are not on the dashboard


def test_runs_list_and_pagination(client, seeded):
    response = client.get("/runs?page=1&per_page=10")
    assert response.status_code == 200
    assert "Run" in response.text
    response = client.get("/runs?page=99")
    assert response.status_code == 200


def test_run_detail_shows_every_section(client, seeded):
    response = client.get("/runs/1")
    assert response.status_code == 200
    body = response.text
    for needle in (
        "Inferred identities",
        "Correlated pairs",
        "Profiles",
        "Entities",
        "Follow edges",
        "Posts",
        "Checks",
        "a@example.com",
    ):
        assert needle in body, needle


def test_run_detail_history_section(client, settings):
    old = _profile(bio="old bio")
    new = _profile(bio="new bio")
    with Store(settings.db_path) as store:
        first = store.start_run("pivot", "alice")
        store.save_profiles(first, [old])
        store.record_profile_history(first, [old])
        store.finish_run(first)
        second = store.start_run("pivot", "alice")
        store.save_profiles(second, [new])
        store.record_profile_history(second, [new])
        store.finish_run(second)
    body = client.get(f"/runs/{second}").text
    assert "Profile changes" in body
    assert "old bio" in body and "new bio" in body


def test_run_detail_404(client):
    assert client.get("/runs/12345").status_code == 404
    assert "404" in client.get("/runs/12345").text


def test_exports(client, seeded):
    json_response = client.get("/runs/1/export?format=json")
    assert json_response.status_code == 200
    assert json_response.headers["content-type"].startswith("application/json")
    assert "attachment" in json_response.headers["content-disposition"]
    payload = json_response.json()
    assert payload["run"]["target"] == "alice"
    assert payload["profiles"][0]["username"] == "alice"

    jsonl = client.get("/runs/1/export?format=jsonl")
    assert jsonl.status_code == 200
    types = {line.split('"')[3] for line in jsonl.text.splitlines() if line}
    assert {"run", "check", "profile", "post", "link", "cluster", "entity"} <= types

    csv_response = client.get("/runs/1/export?format=csv&table=profiles")
    assert csv_response.status_code == 200
    assert "alice" in csv_response.text

    html_response = client.get("/runs/1/export?format=html")
    assert html_response.status_code == 200
    assert "alice" in html_response.text

    redacted = client.get("/runs/1/export?format=json&redact=true").json()
    assert redacted["profiles"][0]["username"] != "alice"

    assert client.get("/runs/999/export?format=json").status_code == 404
    assert client.get("/runs/1/export?format=nope").status_code == 422


def test_search_page(client, seeded):
    response = client.get("/search?q=crypto")
    assert response.status_code == 200
    assert "1 result" in response.text
    empty = client.get("/search?q=")
    assert empty.status_code == 200
    nonsense = client.get("/search?q=%22%22")
    assert nonsense.status_code == 200


def test_sources_page(client):
    response = client.get("/sources?group=email")
    assert response.status_code == 200
    assert "gravatar" in response.text
    assert "reddit" not in response.text


def test_cases_page(client, seeded):
    response = client.get("/cases")
    assert response.status_code == 200
    assert "op-x" in response.text
    assert "suspect" in response.text


def test_pivot_form(client):
    response = client.get("/pivot")
    assert response.status_code == 200
    assert "Run pivot" in response.text


def test_security_headers(client):
    response = client.get("/")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in response.headers["content-security-policy"]


# -- JSON API ---------------------------------------------------------------


def test_api_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert client.get("/healthz").json()["status"] == "ok"


def test_api_stats(client, seeded):
    payload = client.get("/api/stats").json()
    assert payload["stats"]["runs"] == 1
    assert payload["stats"]["profiles"] == 1


def test_api_runs_and_detail(client, seeded):
    listing = client.get("/api/runs").json()
    assert listing["total"] == 1
    assert listing["runs"][0]["target"] == "alice"
    detail = client.get("/api/runs/1").json()
    assert detail["run"]["id"] == 1
    assert client.get("/api/runs/999").status_code == 404


def test_api_search(client, seeded):
    payload = client.get("/api/search?q=crypto").json()
    assert payload["results"][0]["username"] == "alice"
    assert client.get("/api/search").status_code == 422


def test_api_sources(client):
    payload = client.get("/api/sources?group=social").json()
    assert payload
    assert {row["group"] for row in payload} == {"social"}
    assert client.get("/api/sources").json()


# -- pivot jobs -------------------------------------------------------------


async def _fake_pivot(target, *, settings, store=None, **kwargs):
    profile = Profile(
        source="github",
        username=target,
        url=f"https://github.com/{target}",
        display_name=target,
        bio="hi",
        extra={},
    )
    return PivotReport(
        target=target,
        kind="username",
        results=[
            CheckResult("github", target, "found", profile=profile),
            CheckResult("reddit", target, "not_found"),
        ],
        links=[],
        expanded=[],
        clusters=[],
        coverage={"found": 1, "not_found": 1},
    )


def _wait_job(client: TestClient, job_id: str, timeout: float = 10.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        payload = client.get(f"/api/jobs/{job_id}").json()
        if payload["status"] in ("done", "error"):
            return payload
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not finish: {payload}")


def test_pivot_form_creates_job_and_persists_run(client, settings, monkeypatch):
    monkeypatch.setattr(web_app, "run_pivot", _fake_pivot)
    response = client.post(
        "/pivot",
        data={"target": "bob", "scope": "curated"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith("/jobs/")
    job_id = location.rsplit("/", 1)[-1]
    job = _wait_job(client, job_id)
    assert job["status"] == "done", job
    assert job["run_id"] == 1
    page = client.get(f"/jobs/{job_id}")
    assert page.status_code == 200
    assert "Open run" in page.text
    with Store(settings.db_path) as store:
        assert store.profiles(run_id=1)[0]["username"] == "bob"


def test_api_pivot_endpoint(client, settings, monkeypatch):
    monkeypatch.setattr(web_app, "run_pivot", _fake_pivot)
    response = client.post("/api/pivot", json={"target": "carol", "expand": False})
    assert response.status_code == 202
    job = _wait_job(client, response.json()["job_id"])
    assert job["status"] == "done"
    with Store(settings.db_path) as store:
        assert store.profiles(run_id=job["run_id"])[0]["username"] == "carol"


def test_pivot_job_failure_is_reported(client, monkeypatch):
    async def exploding_pivot(target, *, settings, store=None, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(web_app, "run_pivot", exploding_pivot)
    response = client.post("/api/pivot", json={"target": "dave"})
    job = _wait_job(client, response.json()["job_id"])
    assert job["status"] == "error"
    assert "boom" in job["error"]
    page = client.get(f"/jobs/{job['id']}")
    assert page.status_code == 200
    assert "boom" in page.text


def test_job_404(client):
    assert client.get("/jobs/doesnotexist").status_code == 404
    assert client.get("/api/jobs/doesnotexist").status_code == 404


def test_custom_scope_requires_sources(client):
    response = client.post(
        "/pivot",
        data={"target": "alice", "scope": "custom", "sources": ""},
        follow_redirects=False,
    )
    assert response.status_code == 400


def test_export_rejects_unknown_csv_table(client, seeded):
    assert client.get("/runs/1/export?format=csv&table=nope").status_code == 422
    assert client.get("/runs/1/export?format=csv&table=profiles").status_code == 200


def test_javascript_urls_are_not_rendered_as_links(client, settings):
    evil = _profile(url="javascript:alert(1)")
    with Store(settings.db_path) as store:
        run_id = store.start_run("pivot", "alice")
        store.save_profiles(run_id, [evil])
        store.save_posts(
            run_id,
            [
                Post(
                    source="github",
                    username="alice",
                    post_id="p1",
                    url="javascript:alert(2)",
                    created_at="2024-01-01T00:00:00Z",
                    text="x",
                )
            ],
        )
        store.finish_run(run_id)
    body = client.get(f"/runs/{run_id}").text
    assert 'href="javascript:' not in body
    assert 'href="#"' in body


def test_health_reports_503_when_db_is_unusable(tmp_path):
    broken = Settings.load()
    broken.db_path = tmp_path  # a directory: sqlite cannot open it
    response = TestClient(create_app(broken)).get("/healthz")
    assert response.status_code == 503
    assert response.json()["status"] == "error"
