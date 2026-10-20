"""TUI tests via Textual's headless pilot. No network, no real terminal."""

from __future__ import annotations

import pytest
from textual.widgets import DataTable, Input

import larpharvester.tui.app as tui_app
from larpharvester.config import Settings
from larpharvester.models import CheckResult, PivotReport, Post, Profile
from larpharvester.store import Store
from larpharvester.tui import LarpharvesterTUI


@pytest.fixture
def settings(tmp_path) -> Settings:
    base = Settings.load()
    base.db_path = tmp_path / "tui.db"
    return base


@pytest.fixture
def seeded(settings):
    with Store(settings.db_path) as store:
        run_id = store.start_run("pivot", "alice")
        profile = Profile(
            source="github",
            username="alice",
            url="https://github.com/alice",
            display_name="Alice",
            bio="security researcher",
            extra={},
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
                    text="hello crypto world",
                )
            ],
        )
        store.finish_run(run_id)
    return 1


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


async def test_tui_dashboard_and_browse(settings, seeded):
    app = LarpharvesterTUI(settings)
    async with app.run_test() as pilot:
        await pilot.pause()
        dashboard = app.query_one("#dash-runs", DataTable)
        assert dashboard.row_count == 1
        browse = app.query_one("#browse-runs", DataTable)
        assert browse.row_count == 1
        browse.focus()
        await pilot.press("enter")
        await pilot.pause()
        assert app.query_one("#browse-profiles", DataTable).row_count == 1
        assert app.query_one("#browse-posts", DataTable).row_count == 1


async def test_tui_search(settings, seeded):
    app = LarpharvesterTUI(settings)
    async with app.run_test() as pilot:
        await pilot.pause()
        app.run_search("crypto")
        await pilot.pause()
        table = app.query_one("#search-results", DataTable)
        assert table.row_count == 1
        app.run_search("no-such-token")
        await pilot.pause()
        assert table.row_count == 0


async def test_tui_pivot_worker_persists(settings, seeded, monkeypatch):
    monkeypatch.setattr(tui_app, "run_pivot", _fake_pivot)
    app = LarpharvesterTUI(settings)
    async with app.run_test() as pilot:
        await pilot.pause()
        app.query_one("#target", Input).value = "bob"
        app.start_pivot()
        await app.workers.wait_for_complete()
        await pilot.pause()
        results = app.query_one("#pivot-results", DataTable)
        assert results.row_count == 2
        status = str(app.query_one("#pivot-status").renderable)
        assert "run #2" in status
    with Store(settings.db_path) as store:
        assert store.profiles(run_id=2)[0]["username"] == "bob"


async def test_tui_pivot_worker_reports_failure(settings, seeded, monkeypatch):
    async def exploding_pivot(target, *, settings, store=None, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(tui_app, "run_pivot", exploding_pivot)
    app = LarpharvesterTUI(settings)
    async with app.run_test() as pilot:
        await pilot.pause()
        app.query_one("#target", Input).value = "bob"
        app.start_pivot()
        await app.workers.wait_for_complete()
        await pilot.pause()
        status = str(app.query_one("#pivot-status").renderable)
        assert "pivot failed" in status
        assert "boom" in status


async def test_tui_pivot_requires_target(settings):
    app = LarpharvesterTUI(settings)
    async with app.run_test() as pilot:
        await pilot.pause()
        app.start_pivot()
        await pilot.pause()
        assert app.query_one("#pivot-results", DataTable).row_count == 0


async def test_tui_custom_scope_requires_sources(settings):
    app = LarpharvesterTUI(settings)
    async with app.run_test() as pilot:
        await pilot.pause()
        from textual.widgets import Select

        app.query_one("#scope", Select).value = "custom"
        await pilot.pause()
        assert not app.query_one("#sources-input", Input).has_class("hidden")
        app.query_one("#target", Input).value = "alice"
        app.start_pivot()
        await pilot.pause()
        assert app.query_one("#pivot-results", DataTable).row_count == 0
