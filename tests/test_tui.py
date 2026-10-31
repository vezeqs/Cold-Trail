"""TUI tests via Textual's headless pilot. No network, no real terminal."""

from __future__ import annotations

import pytest
from textual.widgets import DataTable, Input

import coldtrail.tui.app as tui_app
from coldtrail.config import Settings
from coldtrail.models import CheckResult, PivotReport, Post, Profile
from coldtrail.store import Store
from coldtrail.tui import ColdTrailTUI


def _static_text(widget) -> str:
    """Read a Static's text on Textual 2.x (renderable) and 8.x (content)."""
    renderable = getattr(widget, "renderable", None)
    if renderable is not None:
        return str(renderable)
    content = getattr(widget, "content", None)
    if content is not None:
        return str(content)
    return str(widget.render())


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
    app = ColdTrailTUI(settings)
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
    app = ColdTrailTUI(settings)
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
    app = ColdTrailTUI(settings)
    async with app.run_test() as pilot:
        await pilot.pause()
        app.query_one("#target", Input).value = "bob"
        app.start_pivot()
        await app.workers.wait_for_complete()
        await pilot.pause()
        results = app.query_one("#pivot-results", DataTable)
        assert results.row_count == 2
        status = _static_text(app.query_one("#pivot-status"))
        assert "run #2" in status
    with Store(settings.db_path) as store:
        assert store.profiles(run_id=2)[0]["username"] == "bob"


async def test_tui_pivot_worker_reports_failure(settings, seeded, monkeypatch):
    async def exploding_pivot(target, *, settings, store=None, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(tui_app, "run_pivot", exploding_pivot)
    app = ColdTrailTUI(settings)
    async with app.run_test() as pilot:
        await pilot.pause()
        app.query_one("#target", Input).value = "bob"
        app.start_pivot()
        await app.workers.wait_for_complete()
        await pilot.pause()
        status = _static_text(app.query_one("#pivot-status"))
        assert "pivot failed" in status
        assert "boom" in status


async def test_tui_pivot_requires_target(settings):
    app = ColdTrailTUI(settings)
    async with app.run_test() as pilot:
        await pilot.pause()
        app.start_pivot()
        await pilot.pause()
        assert app.query_one("#pivot-results", DataTable).row_count == 0


async def test_tui_custom_scope_requires_sources(settings):
    app = ColdTrailTUI(settings)
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


# -- 0.4.0: streaming, tools, cases -----------------------------------------


async def test_tui_streams_rows_as_checks_finish(settings, seeded, monkeypatch):
    async def streaming_pivot(target, *, settings, store=None, on_result=None, **kwargs):
        results = []
        for index in range(3):
            profile = Profile(
                source=f"src{index}",
                username=target,
                url=f"https://example.test/{index}",
                extra={},
            )
            result = CheckResult(f"src{index}", target, "found", profile=profile)
            results.append(result)
            if on_result is not None:
                on_result(result)
        return PivotReport(
            target=target,
            kind="username",
            results=results,
            links=[],
            expanded=[],
            clusters=[],
            coverage={"found": 3},
        )

    monkeypatch.setattr(tui_app, "run_pivot", streaming_pivot)
    app = ColdTrailTUI(settings)
    async with app.run_test() as pilot:
        await pilot.pause()
        app.query_one("#target", Input).value = "bob"
        app.start_pivot()
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert app.query_one("#pivot-results", DataTable).row_count == 3
        status = _static_text(app.query_one("#pivot-status"))
        assert "3 found" in status


async def test_tui_tools_phone(settings):
    from textual.widgets import Select

    app = ColdTrailTUI(settings)
    async with app.run_test() as pilot:
        await pilot.pause()
        app.query_one("#tool-select", Select).value = "phone"
        await pilot.pause()
        app.query_one("#tool-target", Input).value = "+14155552671"
        app.start_tool()
        await app.workers.wait_for_complete()
        await pilot.pause()
        output = _static_text(app.query_one("#tool-output"))
        assert "e164" in output


async def test_tui_tools_requires_target(settings):
    app = ColdTrailTUI(settings)
    async with app.run_test() as pilot:
        await pilot.pause()
        app.start_tool()
        await pilot.pause()
        assert _static_text(app.query_one("#tool-output")) == ""


async def test_tui_cases_create_and_list(settings):
    app = ColdTrailTUI(settings)
    async with app.run_test() as pilot:
        await pilot.pause()
        app.query_one("#case-name", Input).value = "op-aurora"
        app.create_case()
        await pilot.pause()
        cases = app.query_one("#cases-table", DataTable)
        assert cases.row_count == 1
        assert app.query_one("#case-name", Input).value == ""


async def test_tui_annotations_render(settings):
    with Store(settings.db_path) as store:
        store.add_tag("profile", "github:alice", "primary")
        store.add_note("profile", "github:alice", "shared avatar")
    app = ColdTrailTUI(settings)
    async with app.run_test() as pilot:
        await pilot.pause()
        annotations = app.query_one("#annotations-table", DataTable)
        assert annotations.row_count == 2


# -- 0.5.0: drill-down actions ----------------------------------------------


async def test_tui_action_pivot_row(settings, seeded, monkeypatch):
    monkeypatch.setattr(tui_app, "run_pivot", _fake_pivot)
    app = ColdTrailTUI(settings)
    async with app.run_test() as pilot:
        await pilot.pause()
        browse = app.query_one("#browse-runs", DataTable)
        browse.focus()
        await pilot.press("enter")
        await pilot.pause()
        profiles = app.query_one("#browse-profiles", DataTable)
        profiles.focus()
        await pilot.press("p")
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert app.query_one("#target", Input).value == "alice"
        assert app.query_one("#pivot-results", DataTable).row_count == 2


async def test_tui_action_harvest_row(settings, seeded, monkeypatch):
    from coldtrail.models import CheckResult

    async def fake_harvest(
        source_name, username, *, settings, limit, store=None, run_id=None, fetcher=None, **kwargs
    ):
        return CheckResult(source_name, username, "not_found"), []

    monkeypatch.setattr(tui_app, "run_harvest", fake_harvest)
    app = ColdTrailTUI(settings)
    async with app.run_test() as pilot:
        await pilot.pause()
        browse = app.query_one("#browse-runs", DataTable)
        browse.focus()
        await pilot.press("enter")
        await pilot.pause()
        profiles = app.query_one("#browse-profiles", DataTable)
        profiles.focus()
        await pilot.press("h")
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert app.query_one("#tool-target", Input).value == "alice"
        assert "not_found" in _static_text(app.query_one("#tool-output"))


async def test_tui_action_diff_runs(settings):
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
    app = ColdTrailTUI(settings)
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("d")
        await pilot.pause()
        output = _static_text(app.query_one("#tool-output"))
        assert '"run_a"' in output
        assert "gitlab" in output


async def test_tui_number_shortcuts_switch_tabs(settings):
    from textual.widgets import TabbedContent

    app = ColdTrailTUI(settings)
    async with app.run_test() as pilot:
        await pilot.pause()
        tabs = app.query_one(TabbedContent)
        await pilot.press("7")
        await pilot.pause()
        assert tabs.active == "tab-help"
        await pilot.press("2")
        await pilot.pause()
        assert tabs.active == "tab-pivot"
        await pilot.press("5")
        await pilot.pause()
        assert tabs.active == "tab-tools"
