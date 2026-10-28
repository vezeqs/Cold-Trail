"""Regression tests for the external review findings."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from coldtrail.cli import app
from coldtrail.config import Settings
from coldtrail.harvest import collect_follows, harvest
from coldtrail.http import FetchError
from coldtrail.integrations import ToolError, run_tool
from coldtrail.models import Profile
from coldtrail.report import to_html
from coldtrail.security import ensure_public_target, is_public_host
from coldtrail.sources.base import Source
from coldtrail.store import Store
from coldtrail.web import create_app

runner = CliRunner()


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(db_path=tmp_path / "t.db", requests_per_second=0, jitter=0)


def test_private_targets_are_blocked():
    assert is_public_host("8.8.8.8")
    assert not is_public_host("127.0.0.1")
    assert not is_public_host("localhost")
    with pytest.raises(ValueError):
        ensure_public_target("http://127.0.0.1/admin")
    assert ensure_public_target("https://8.8.8.8/path") == "8.8.8.8"


def test_dossier_links_allowlist_http_and_https():
    payload = {
        "run": {"id": 1, "kind": "pivot", "target": "alice"},
        "profiles": [
            {
                "source": "bad",
                "username": "alice",
                "url": " java\tscript:alert(1)",
                "display_name": "Alice",
            },
            {
                "source": "good",
                "username": "alice",
                "url": "https://example.com/alice",
                "display_name": "Alice",
            },
        ],
    }
    rendered = to_html(payload)
    assert "javascript:" not in rendered.casefold()
    assert 'href=" java' not in rendered.casefold()
    assert 'href="https://example.com/alice"' in rendered


class _BrokenPosts(Source):
    name = "broken"
    label = "Broken"

    async def check(self, fetcher, target):
        return self.ok(target, Profile(source=self.name, username=target, url="https://x.test"))

    async def posts(self, fetcher, target, limit, *, since=None):
        raise FetchError("simulated network failure")

    async def follows(self, fetcher, target, limit=100):
        raise FetchError("simulated network failure")


async def test_harvest_and_follows_survive_fetch_errors(settings, monkeypatch):
    monkeypatch.setattr("coldtrail.harvest.SOURCES", {"broken": _BrokenPosts()})
    result, posts = await harvest("broken", "alice", settings=settings, limit=5)
    assert result.status == "found"
    assert posts == []
    result, edges = await collect_follows("broken", "alice", settings=settings, limit=5)
    assert result.status == "found"
    assert edges == []


def test_api_docs_is_self_hosted(settings):
    client = TestClient(create_app(settings))
    response = client.get("/api/docs")
    assert response.status_code == 200
    assert "/api/runs" in response.text
    assert "cdn.jsdelivr" not in response.text


def test_batch_invalid_source_is_a_clean_cli_error(settings):
    result = runner.invoke(
        app, ["--db", str(settings.db_path), "batch", "alice", "-s", "does-not-exist"]
    )
    assert result.exit_code == 2
    assert "unknown source" in result.output
    assert "Traceback" not in result.output


def test_web_domain_tool_blocks_private_targets(settings):
    client = TestClient(create_app(settings))
    response = client.post(
        "/tools/run",
        data={"tool": "domain", "target": "127.0.0.1", "source": "github", "limit": 5},
    )
    assert response.status_code == 400
    assert "private" in response.text.casefold()


def test_external_tool_web_does_not_read_local_files(settings, monkeypatch):
    monkeypatch.setattr("coldtrail.integrations.shutil.which", lambda binary: "/bin/true")
    with pytest.raises(ToolError):
        run_tool("exiftool", "README.md", allow_file_paths=False)


def test_store_reopen_keeps_trigger(settings):
    with Store(settings.db_path) as store:
        assert store.conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='trigger' AND name='posts_au'"
        ).fetchone()
    with Store(settings.db_path) as store:
        assert store.conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='trigger' AND name='posts_au'"
        ).fetchone()
