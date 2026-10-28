"""Tests for 0.4.0 workflows: multi-hop expansion, streaming callbacks,
batch pivoting, and cross-run re-clustering."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from coldtrail.cli import app
from coldtrail.config import Settings
from coldtrail.models import Profile
from coldtrail.pivot import pivot
from coldtrail.sources.base import Source

runner = CliRunner()


class UserSource(Source):
    name = "user-src"
    label = "User Source"
    group = "social"

    def __init__(self) -> None:
        self.seen: list[str] = []

    async def check(self, fetcher, target):
        self.seen.append(target)
        # Structured links only: email profiles advertise an account, username
        # profiles advertise an email field.
        if "@" in target:
            handle = target.split("@", 1)[0] + "-alt"
            return self.ok(
                target,
                Profile(
                    source=self.name,
                    username=handle,
                    url=f"https://user.example/{handle}",
                    bio=f"reach me at {target}",
                    extra={"accounts": [{"username": handle}]},
                ),
            )
        return self.ok(
            target,
            Profile(
                source=self.name,
                username=target,
                url=f"https://user.example/{target}",
                bio=f"contact {target}@example.com",
                extra={"email": f"{target}@example.com"},
            ),
        )


class EmailSource(Source):
    name = "email-src"
    label = "Email Source"
    kind = "email"
    group = "email"

    def __init__(self) -> None:
        self.seen: list[str] = []

    async def check(self, fetcher, target):
        self.seen.append(target)
        handle = target.split("@", 1)[0] + "-hop"
        return self.ok(
            target,
            Profile(
                source=self.name,
                username=handle,
                url=f"https://email.example/{handle}",
                bio=f"{target}",
                extra={"accounts": [{"username": handle}]},
            ),
        )


@pytest.fixture
def settings(tmp_path):
    return Settings(db_path=tmp_path / "t.db", requests_per_second=0, jitter=0)


async def test_depth_one_expands_once(settings, monkeypatch):
    user, email = UserSource(), EmailSource()
    monkeypatch.setattr("coldtrail.pivot.SOURCES", {user.name: user, email.name: email})
    report = await pivot("alice", settings=settings, expand=True, depth=1, avatar_hash=False)
    # One hop: email discovered from the username profile.
    assert "alice@example.com" in report.expanded
    assert all("@" in target for target in email.seen)


async def test_depth_two_adds_second_hop(settings, monkeypatch):
    user, email = UserSource(), EmailSource()
    monkeypatch.setattr("coldtrail.pivot.SOURCES", {user.name: user, email.name: email})
    report = await pivot("alice", settings=settings, expand=True, depth=2, avatar_hash=False)
    assert "alice@example.com" in report.expanded
    # Second hop: the email source advertised alice-hop, which user-src probed.
    assert "alice-hop" in report.expanded
    assert "alice-hop" in user.seen


async def test_depth_does_not_reprobe_visited_targets(settings, monkeypatch):
    user, email = UserSource(), EmailSource()
    monkeypatch.setattr("coldtrail.pivot.SOURCES", {user.name: user, email.name: email})
    await pivot("alice", settings=settings, expand=True, depth=3, avatar_hash=False)
    assert user.seen.count("alice") == 1


async def test_on_result_streams_every_check(settings, monkeypatch):
    user, email = UserSource(), EmailSource()
    monkeypatch.setattr("coldtrail.pivot.SOURCES", {user.name: user, email.name: email})
    streamed: list[tuple[str, str, str]] = []
    report = await pivot(
        "alice",
        settings=settings,
        expand=True,
        depth=2,
        avatar_hash=False,
        on_result=lambda res: streamed.append((res.source, res.target, res.status)),
    )
    assert len(streamed) == len(report.results)
    assert {row[0] for row in streamed} == {"user-src", "email-src"}


# -- CLI --------------------------------------------------------------------


def test_cli_batch_json(tmp_path, monkeypatch):
    user, email = UserSource(), EmailSource()
    monkeypatch.setattr("coldtrail.pivot.SOURCES", {user.name: user, email.name: email})
    result = runner.invoke(
        app,
        ["--db", str(tmp_path / "t.db"), "batch", "alice", "bob", "--json"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert [report["target"] for report in payload] == ["alice", "bob"]
    assert all(report["run_id"] for report in payload)


def test_cli_batch_from_file(tmp_path, monkeypatch):
    user, email = UserSource(), EmailSource()
    monkeypatch.setattr("coldtrail.pivot.SOURCES", {user.name: user, email.name: email})
    targets = tmp_path / "targets.txt"
    targets.write_text("# comment\nalice\n\nbob\n")
    result = runner.invoke(
        app,
        ["--db", str(tmp_path / "t.db"), "batch", "-f", str(targets), "--json"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert [report["target"] for report in payload] == ["alice", "bob"]


def test_cli_batch_requires_targets(tmp_path):
    result = runner.invoke(app, ["--db", str(tmp_path / "t.db"), "batch"])
    assert result.exit_code != 0


def test_cli_recluster(tmp_path):
    from coldtrail.models import CheckResult
    from coldtrail.store import Store

    db = tmp_path / "t.db"
    with Store(db) as store:
        run_id = store.start_run("pivot", "alice")
        profile = Profile(
            source="github",
            username="alice",
            url="https://github.com/alice",
            display_name="Alice",
            bio="distinctive rust security researcher profile text",
            extra={},
        )
        other = Profile(
            source="gitlab",
            username="alice",
            url="https://gitlab.com/alice",
            display_name="Alice",
            bio="distinctive rust security researcher profile text",
            extra={},
        )
        store.save_checks(run_id, [CheckResult("github", "alice", "found", profile=profile)])
        store.save_profiles(run_id, [profile, other])
        store.finish_run(run_id)

    result = runner.invoke(app, ["--db", str(db), "recluster", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["profiles"] == 2
    assert len(payload["links"]) == 1
    assert len(payload["clusters"]) == 1
