"""Regression tests for the Twitch boilerplate / false-correlation bug found
during the v0.5.0 live investigation."""

from __future__ import annotations

import httpx
import pytest
import respx
from typer.testing import CliRunner

from coldtrail.cli import app
from coldtrail.config import Settings
from coldtrail.correlate import correlate, is_boilerplate_bio, score_pair
from coldtrail.http import Fetcher
from coldtrail.models import Profile
from coldtrail.sources import SOURCES

runner = CliRunner()

FOUND_PAGE = (
    "<html><head><title>simonw - Twitch</title>"
    '<meta property="og:profile:username" content="simonw">'
    '<meta property="og:type" content="profile">'
    '<meta name="twitter:description" content="simonw streams live on Twitch! '
    'Check out their videos, sign up to chat, and join their community.">'
    "</head><body></body></html>"
)

MISSING_PAGE = (
    "<html><head><title>Twitch</title>"
    '<meta property="og:title" content="Twitch">'
    '<meta name="twitter:description" content="Twitch is the world\'s leading '
    'video platform and community for gamers.">'
    '<link rel="canonical" href="https://www.twitch.tv/simonw">'
    "</head><body></body></html>"
)


def _html(text: str) -> httpx.Response:
    return httpx.Response(200, text=text, headers={"content-type": "text/html"})


@pytest.fixture
def settings(tmp_path):
    return Settings(db_path=tmp_path / "t.db", requests_per_second=0, jitter=0)


@respx.mock
async def test_twitch_found_requires_profile_metadata(settings):
    respx.get("https://www.twitch.tv/simonw").mock(return_value=_html(FOUND_PAGE))
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["twitch"].check(fetcher, "simonw")
    assert result.status == "found"
    assert result.profile.username == "simonw"
    # Template description must not be stored as a bio.
    assert result.profile.bio is None
    assert result.profile.display_name is None
    assert result.profile.extra["profile_username"] == "simonw"


@respx.mock
async def test_twitch_missing_shell_is_not_found(settings):
    respx.get("https://www.twitch.tv/simonw").mock(return_value=_html(MISSING_PAGE))
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["twitch"].check(fetcher, "simonw")
    assert result.status == "not_found"


@respx.mock
async def test_twitch_mismatched_profile_username_is_not_found(settings):
    page = FOUND_PAGE.replace('content="simonw"', 'content="someoneelse"', 1)
    respx.get("https://www.twitch.tv/simonw").mock(return_value=_html(page))
    async with Fetcher(settings) as fetcher:
        result = await SOURCES["twitch"].check(fetcher, "simonw")
    assert result.status == "not_found"


def test_boilerplate_bio_detection():
    assert is_boilerplate_bio(
        "simonw streams live on Twitch! Check out their videos, sign up to chat, "
        "and join their community."
    )
    assert is_boilerplate_bio(
        "Twitch is the world's leading video platform and community for gamers."
    )
    assert not is_boilerplate_bio("Building Datasette and tools for data journalism.")


def test_boilerplate_bios_never_form_links():
    twitch = Profile(
        source="twitch",
        username="simonw",
        url="https://www.twitch.tv/simonw",
        bio="simonw streams live on Twitch! Check out their videos, sign up to chat, "
        "and join their community.",
    )
    github = Profile(
        source="github",
        username="simonw",
        url="https://github.com/simonw",
        bio="simonw streams live on Twitch! Check out their videos, sign up to chat, "
        "and join their community.",
    )
    assert score_pair(twitch, github)[0] < 0.5
    assert correlate([twitch, github]) == []


def test_short_handle_only_bio_is_not_a_mention():
    a = Profile(source="github", username="simonw", url="https://x/a", bio="simonw")
    b = Profile(
        source="twitch",
        username="simonw",
        url="https://x/b",
        bio="simonw - Twitch",
    )
    score, reasons = score_pair(a, b)
    assert score < 0.5
    assert not any("bio" in reason for reason in reasons)


def test_pivot_json_includes_profiles_and_entities(tmp_path, monkeypatch):
    import json

    import coldtrail.cli.collect as collect_module
    from coldtrail.models import CheckResult, PivotReport

    profile = Profile(
        source="github",
        username="alice",
        url="https://github.com/alice",
        bio="contact alice@example.com",
        extra={},
    )

    async def fake_pivot(target, **kwargs):
        return PivotReport(
            target=target,
            kind="username",
            results=[CheckResult("github", target, "found", profile=profile)],
            links=[],
            expanded=[],
            clusters=[],
            coverage={"found": 1},
        )

    monkeypatch.setattr(collect_module, "run_pivot", fake_pivot)
    result = runner.invoke(
        app, ["--db", str(tmp_path / "t.db"), "pivot", "alice", "--json", "--no-save"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["profiles"][0]["username"] == "alice"

    jsonl = runner.invoke(
        app, ["--db", str(tmp_path / "t.db"), "pivot", "alice", "--jsonl", "--no-save"]
    )
    assert jsonl.exit_code == 0, jsonl.output
    types = {json.loads(line)["type"] for line in jsonl.output.splitlines() if line}
    assert {"check", "profile", "entity"} <= types
