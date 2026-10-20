"""Web UI and JSON API tests. No network: TestClient against a seeded SQLite db."""

from __future__ import annotations

import json
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


# -- 0.4.0: graph, SSE, tools, cases CRUD, new formats ----------------------


def test_run_graph_endpoint(client, seeded):
    payload = client.get("/api/runs/1/graph").json()
    ids = {node["id"] for node in payload["nodes"]}
    assert "github:alice" in ids
    assert any(node["id"].startswith("entity:email:") for node in payload["nodes"])
    kinds = {edge["kind"] for edge in payload["edges"]}
    assert "correlation" in kinds
    assert client.get("/api/runs/999/graph").status_code == 404


def test_new_export_formats(client, seeded):
    md = client.get("/runs/1/export?format=md")
    assert md.status_code == 200
    assert "# OSINT Dossier" in md.text

    stix = client.get("/runs/1/export?format=stix")
    assert stix.status_code == 200
    bundle = json.loads(stix.text)
    assert bundle["type"] == "bundle"

    maltego = client.get("/runs/1/export?format=maltego")
    assert maltego.status_code == 200
    assert "SourceValue" in maltego.text


async def _streaming_fake_pivot(target, *, settings, store=None, on_result=None, **kwargs):
    profile = Profile(
        source="github",
        username=target,
        url=f"https://github.com/{target}",
        display_name=target,
        bio="hi",
        extra={},
    )
    result = CheckResult("github", target, "found", profile=profile)
    if on_result is not None:
        on_result(result)
    return PivotReport(
        target=target,
        kind="username",
        results=[result],
        links=[],
        expanded=[],
        clusters=[],
        coverage={"found": 1},
    )


def test_sse_stream_replays_events_and_done(client, monkeypatch):
    monkeypatch.setattr(web_app, "run_pivot", _streaming_fake_pivot)
    response = client.post("/api/pivot", json={"target": "erin"})
    job_id = response.json()["job_id"]
    job = _wait_job(client, job_id)
    assert job["status"] == "done"
    events: list[str] = []
    with client.stream("GET", f"/api/jobs/{job_id}/stream") as stream:
        for line in stream.iter_lines():
            if line:
                events.append(line)
    joined = "\n".join(events)
    assert "event: check" in joined
    assert "event: done" in joined
    assert '"status": "done"' in joined
    assert "github" in joined
    assert client.get("/api/jobs/nope/stream").status_code == 404


def test_job_api_includes_events(client, monkeypatch):
    monkeypatch.setattr(web_app, "run_pivot", _streaming_fake_pivot)
    response = client.post("/api/pivot", json={"target": "frank"})
    job = _wait_job(client, response.json()["job_id"])
    assert job["events"]
    assert job["events"][0]["source"] == "github"
    assert job["found_count"] == 1


def test_tools_page(client):
    response = client.get("/tools")
    assert response.status_code == 200
    assert "OSINT Workbench" in response.text


def test_tools_run_phone(client):
    response = client.post(
        "/tools/run", data={"tool": "phone", "target": "+14155552671", "limit": 10}
    )
    assert response.status_code == 200
    assert "e164" in response.text


def test_tools_run_dorks(client):
    response = client.post("/tools/run", data={"tool": "dorks", "target": "alice"})
    assert response.status_code == 200
    assert "google" in response.text


def test_tools_run_rejects_unknown_tool(client):
    response = client.post("/tools/run", data={"tool": "nope", "target": "x"})
    assert response.status_code == 422


def test_tools_run_harvest_persists(client, settings, monkeypatch):
    import larpharvester.web.app as app_module

    async def fake_harvest(source, target, *, settings, limit, store=None, **kwargs):
        from larpharvester.models import CheckResult, Post, Profile

        profile = Profile(
            source=source,
            username=target,
            url=f"https://example.test/{target}",
            display_name=target,
            extra={},
        )
        return (
            CheckResult(source, target, "found", profile=profile),
            [
                Post(
                    source=source,
                    username=target,
                    post_id="p1",
                    url="https://example.test/p1",
                    created_at="2024-01-01T00:00:00Z",
                    text="hello world",
                )
            ],
        )

    monkeypatch.setattr(app_module, "run_harvest", fake_harvest)
    response = client.post(
        "/tools/run", data={"tool": "harvest", "target": "alice", "source": "github"}
    )
    assert response.status_code == 200
    assert "Saved as run" in response.text
    with Store(settings.db_path) as store:
        assert store.posts()[0]["text"] == "hello world"


def test_cases_crud_flow(client, seeded):
    created = client.post(
        "/cases/new", data={"name": "op-aurora", "notes": "test case"}, follow_redirects=False
    )
    assert created.status_code == 303
    page = client.get("/cases")
    assert "op-aurora" in page.text

    attached = client.post(
        "/cases/add-run", data={"case_name": "op-aurora", "run_id": 1}, follow_redirects=False
    )
    assert attached.status_code == 303

    tagged = client.post(
        "/tags/new",
        data={"target_type": "profile", "target": "github:alice", "tag": "primary"},
        follow_redirects=False,
    )
    assert tagged.status_code == 303

    noted = client.post(
        "/notes/new",
        data={"target_type": "profile", "target": "github:alice", "note": "shared avatar"},
        follow_redirects=False,
    )
    assert noted.status_code == 303

    page = client.get("/cases")
    assert "primary" in page.text
    assert "shared avatar" in page.text


def test_cases_add_run_unknown_case(client):
    response = client.post("/cases/add-run", data={"case_name": "nope", "run_id": 1})
    assert response.status_code == 404


def test_pivot_form_accepts_depth(client, monkeypatch):
    captured: dict = {}

    async def fake_pivot(target, *, settings, store=None, on_result=None, **kwargs):
        captured.update(kwargs)
        return PivotReport(
            target=target,
            kind="username",
            results=[],
            links=[],
            expanded=[],
            clusters=[],
            coverage={},
        )

    monkeypatch.setattr(web_app, "run_pivot", fake_pivot)
    response = client.post(
        "/pivot",
        data={"target": "grace", "scope": "curated", "depth": 2, "expand": "true"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    job = _wait_job(client, response.headers["location"].rsplit("/", 1)[-1])
    assert job["status"] == "done"
    assert captured["depth"] == 2
    assert captured["expand"] is True


def test_jsonl_export_is_streamed(client, seeded):
    response = client.get("/runs/1/export?format=jsonl")
    assert response.status_code == 200
    assert response.text.splitlines()
    assert '"type": "profile"' in response.text


# -- 0.5.0: auth, diff, case dossiers, rate limiting, one-click pivot --------


@pytest.fixture
def auth_client(settings):
    settings.web_token = "sekret"
    return TestClient(create_app(settings))


def test_auth_redirects_pages_and_rejects_api(auth_client):
    response = auth_client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert auth_client.get("/api/stats").status_code == 401
    assert auth_client.get("/healthz").status_code == 200


def test_auth_accepts_bearer_and_api_key(auth_client):
    bearer = {"Authorization": "Bearer sekret"}
    api_key = {"X-API-Key": "sekret"}
    assert auth_client.get("/api/stats", headers=bearer).status_code == 200
    assert auth_client.get("/api/stats", headers=api_key).status_code == 200
    wrong = {"Authorization": "Bearer wrong"}
    assert auth_client.get("/api/stats", headers=wrong).status_code == 401


def test_login_cookie_flow(auth_client):
    response = auth_client.post(
        "/login", data={"token": "sekret"}, follow_redirects=False
    )
    assert response.status_code == 303
    assert auth_client.get("/").status_code == 200
    bad = auth_client.post("/login", data={"token": "nope"}, follow_redirects=False)
    assert bad.status_code == 401


def test_diff_api_and_page(client, settings):
    with Store(settings.db_path) as store:
        first = store.start_run("pivot", "alice")
        store.save_profiles(first, [Profile("github", "alice", "https://x/a", extra={})])
        store.finish_run(first)
        second = store.start_run("pivot", "alice")
        store.save_profiles(
            second,
            [
                Profile("github", "alice", "https://x/a", extra={}),
                Profile("gitlab", "alice", "https://x/b", extra={}),
            ],
        )
        store.finish_run(second)
    payload = client.get("/api/diff?a=1&b=2").json()
    assert payload["profiles"]["added"][0]["source"] == "gitlab"
    page = client.get("/diff?a=1&b=2")
    assert page.status_code == 200
    assert "Run diff" in page.text
    assert client.get("/api/diff?a=1&b=999").status_code == 404
    assert client.get("/diff?a=1&b=999").status_code == 404


def test_case_detail_and_dossier_export(client, seeded):
    client.post("/cases/new", data={"name": "op-aurora"}, follow_redirects=False)
    client.post(
        "/cases/add-run",
        data={"case_name": "op-aurora", "run_id": 1},
        follow_redirects=False,
    )
    page = client.get("/cases/op-aurora")
    assert page.status_code == 200
    assert "op-aurora" in page.text
    assert "alice" in page.text

    payload = client.get("/cases/op-aurora/export?format=json").json()
    assert payload["run"]["id"] == "case:op-aurora"
    assert payload["profiles"]
    assert client.get("/cases/op-aurora/export?format=md").status_code == 200
    assert client.get("/cases/nope").status_code == 404
    assert client.get("/cases/nope/export?format=json").status_code == 404


def test_run_page_has_one_click_pivot_forms(client, seeded):
    body = client.get("/runs/1").text
    assert 'action="/pivot"' in body
    assert 'name="target" value="alice"' in body


def test_rate_limit_on_pivot(settings, monkeypatch):
    import larpharvester.web.app as app_module

    monkeypatch.setattr(app_module, "RATE_LIMIT", 1)
    monkeypatch.setattr(app_module, "run_pivot", _fake_pivot)
    client = TestClient(create_app(settings))
    first = client.post("/api/pivot", json={"target": "alice"})
    assert first.status_code == 202
    second = client.post("/api/pivot", json={"target": "bob"})
    assert second.status_code == 429
