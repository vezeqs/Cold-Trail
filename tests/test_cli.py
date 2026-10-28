from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from coldtrail.cli import app
from coldtrail.models import Post, Profile
from coldtrail.sources.base import Source

runner = CliRunner()


class FakeSource(Source):
    name = "fake"
    label = "Fake"
    kind = "username"

    async def check(self, fetcher, target):
        return self.ok(
            target,
            Profile(
                source=self.name,
                username=target,
                url=f"https://fake.example/{target}",
                display_name="Alice",
                bio="Security researcher and occasional CTF player.",
                avatar="https://fake.example/a.png",
            ),
        )

    async def posts(self, fetcher, target, limit, *, since=None):
        return [
            Post(
                source=self.name,
                username=target,
                post_id="1",
                url="https://fake.example/1",
                created_at="2024-01-01T00:00:00Z",
                text="hello world",
            )
        ]


class FakeEmailSource(Source):
    name = "fake-email"
    label = "Fake email"
    kind = "email"
    group = "email"

    async def check(self, fetcher, target):
        return self.ok(
            target,
            Profile(
                source=self.name,
                username="alice",
                url="https://email.example/alice",
                extra={"accounts": [{"username": "alice"}]},
            ),
        )


@pytest.fixture
def fake_sources(monkeypatch):
    fake = {"fake": FakeSource()}
    monkeypatch.setattr("coldtrail.pivot.SOURCES", fake)
    monkeypatch.setattr("coldtrail.harvest.SOURCES", fake)
    monkeypatch.setattr("coldtrail.cli.collect.SOURCES", fake)
    return fake


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "coldtrail" in result.output


def test_sources_json():
    result = runner.invoke(app, ["sources", "--json"])
    assert result.exit_code == 0
    names = {row["name"] for row in json.loads(result.output)}
    assert {"github", "reddit", "gravatar", "keybase", "bluesky"} <= names


def test_pivot_json_persists_and_queries(tmp_path, fake_sources):
    db = tmp_path / "test.db"
    result = runner.invoke(app, ["--db", str(db), "pivot", "alice", "--json", "--no-avatar-hash"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["target"] == "alice"
    assert payload["kind"] == "username"
    assert payload["results"][0]["status"] == "found"
    assert payload["run_id"] == 1

    stored = runner.invoke(app, ["--db", str(db), "profiles", "--json"])
    assert stored.exit_code == 0
    rows = json.loads(stored.output)
    assert rows[0]["username"] == "alice"
    assert rows[0]["source"] == "fake"


def test_pivot_no_save_does_not_create_a_run(tmp_path, fake_sources):
    db = tmp_path / "test.db"
    result = runner.invoke(
        app, ["--db", str(db), "pivot", "alice", "--json", "--no-avatar-hash", "--no-save"]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["run_id"] is None
    assert runner.invoke(app, ["--db", str(db), "runs", "--json"]).output.strip() == "[]"


def test_pivot_unknown_source_fails(tmp_path, fake_sources):
    result = runner.invoke(app, ["--db", str(tmp_path / "x.db"), "pivot", "alice", "-s", "nope"])
    assert result.exit_code != 0
    assert "unknown source" in result.output


def test_pivot_email_without_expand_uses_email_sources(tmp_path, monkeypatch):
    monkeypatch.setattr("coldtrail.pivot.SOURCES", {"fake-email": FakeEmailSource()})
    result = runner.invoke(
        app,
        [
            "--db",
            str(tmp_path / "x.db"),
            "pivot",
            "a@example.com",
            "--json",
            "--no-save",
            "--no-avatar-hash",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["kind"] == "email"
    assert {row["source"] for row in payload["results"]} == {"fake-email"}


def test_harvest_json(tmp_path, fake_sources):
    db = tmp_path / "test.db"
    result = runner.invoke(
        app, ["--db", str(db), "harvest", "alice", "-s", "fake", "-n", "5", "--json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["check"]["status"] == "found"
    assert payload["posts"][0]["text"] == "hello world"
    assert payload["run_id"] == 1

    stored = runner.invoke(app, ["--db", str(db), "posts", "--json"])
    assert json.loads(stored.output)[0]["username"] == "alice"


def test_harvest_rejects_email_source(tmp_path):
    result = runner.invoke(
        app, ["--db", str(tmp_path / "x.db"), "harvest", "alice", "-s", "gravatar"]
    )
    assert result.exit_code != 0
    assert "email source" in result.output


def test_runs_and_export(tmp_path, fake_sources):
    db = tmp_path / "test.db"
    runner.invoke(app, ["--db", str(db), "pivot", "alice", "--json", "--no-avatar-hash"])
    runs = runner.invoke(app, ["--db", str(db), "runs", "--json"])
    assert json.loads(runs.output)[0]["kind"] == "pivot"

    out = tmp_path / "export.json"
    result = runner.invoke(app, ["--db", str(db), "export", "1", "-o", str(out)])
    assert result.exit_code == 0, result.output
    payload = json.loads(out.read_text())
    assert payload["run"]["target"] == "alice"
    assert payload["checks"][0]["source"] == "fake"


def test_export_missing_run_exits_nonzero(tmp_path):
    result = runner.invoke(app, ["--db", str(tmp_path / "x.db"), "export", "42"])
    assert result.exit_code == 1


def test_pivot_hides_non_matching_checks_by_default(tmp_path, monkeypatch):
    from coldtrail.sources.base import Source

    class Found(Source):
        name = "found-src"
        label = "Found"
        group = "social"

        async def check(self, fetcher, target):
            return self.ok(
                target,
                Profile(source=self.name, username=target, url=f"https://x/{target}"),
            )

    class Missing(Source):
        name = "missing-src"
        label = "Missing"
        group = "social"

        async def check(self, fetcher, target):
            return self.missing(target, "no such user")

    fake = {"found-src": Found(), "missing-src": Missing()}
    monkeypatch.setattr("coldtrail.pivot.SOURCES", fake)
    monkeypatch.setattr("coldtrail.cli.collect.SOURCES", fake)

    base = ["--db", str(tmp_path / "t.db"), "pivot", "alice"]
    default = runner.invoke(app, base)
    assert default.exit_code == 0, default.output
    assert "missing-src" not in default.output
    assert "non-matching checks hidden" in default.output

    full = runner.invoke(app, [*base, "--all-checks"])
    assert full.exit_code == 0, full.output
    assert "missing-src" in full.output


def test_sources_query_filter():
    result = runner.invoke(app, ["sources", "-q", "mastodon"])
    assert result.exit_code == 0, result.output
    assert "mastodon" in result.output
    assert "github" not in result.output


def test_menu_exits_cleanly():
    result = runner.invoke(app, ["menu"], input="0\n")
    assert result.exit_code == 0, result.output
    assert "ColdTrail menu" in result.output
