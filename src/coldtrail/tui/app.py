"""Textual TUI for ColdTrail.

Tabs: Dashboard, Pivot (live streaming results), Browse, Search, Tools
(domain/ip/phone/dorks/breach/harvest), Cases (create cases, view tags/notes).

Pivots and tool runs execute in background worker threads so the UI stays
responsive; each worker opens its own Store connection (SQLite connections
are thread-bound).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from typing import Any

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Header,
    Input,
    LoadingIndicator,
    Select,
    Static,
    TabbedContent,
    TabPane,
)

from .. import __version__
from ..breach import full_breach_audit
from ..config import Settings
from ..correlate import diff_runs
from ..domain import asn_lookup, lookup_domain, ptr, rdap_ip, reverse_ip
from ..dorks import dorks as build_dorks
from ..harvest import harvest as run_harvest
from ..http import Fetcher
from ..phone import lookup as phone_lookup
from ..pivot import persist_pivot
from ..pivot import pivot as run_pivot
from ..store import Store

HELP_TEXT = """[bold]ColdTrail — quick guide[/bold]

[bold]Workflow[/bold]
  Pivot → Browse → Harvest → Graph → Cases → Export

[bold]Tabs[/bold]
  Dashboard  database counts, coverage, recent runs
  Pivot      probe a username/email (results stream in)
  Browse     pick a run to inspect profiles, posts, and evidence
  Search     full-text search over harvested posts
  Tools      domain / IP / phone / dorks / breach / harvest
  Cases      create cases; view tags and notes
  Help       this page

[bold]Keys[/bold]
  q  quit          r  refresh
  p  pivot the focused row
  h  harvest the focused row
  d  diff the two most recent runs
  1-7  jump to Dashboard/Pivot/Browse/Search/Tools/Cases/Help
  Enter  open the highlighted run in Browse

[bold]Common CLI commands[/bold]
  coldtrail pivot alice --expand --depth 2
  coldtrail harvest alice -s github -n 50
  coldtrail graph alice -s bluesky
  coldtrail menu
  coldtrail integrations
  coldtrail run sherlock alice
  coldtrail ingest export.json
  coldtrail evidence add screenshot.png --run 3
  coldtrail export 3 --format html -o dossier.html

[bold]Tips[/bold]
  Global options (--db, --concurrency, --max-requests) go before the command.
  pivot hides non-matching checks; add --all-checks to see everything.
  sources -q <text> filters the source registry.
"""


class ColdTrailTUI(App):
    TITLE = f"ColdTrail {__version__}"
    SUB_TITLE = "OSINT pivoting console"
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("p", "pivot_row", "Pivot row"),
        Binding("h", "harvest_row", "Harvest row"),
        Binding("d", "diff_runs", "Diff runs"),
        Binding("1", "show_tab('tab-dashboard')", "Dashboard", show=False),
        Binding("2", "show_tab('tab-pivot')", "Pivot", show=False),
        Binding("3", "show_tab('tab-browse')", "Browse", show=False),
        Binding("4", "show_tab('tab-search')", "Search", show=False),
        Binding("5", "show_tab('tab-tools')", "Tools", show=False),
        Binding("6", "show_tab('tab-cases')", "Cases", show=False),
        Binding("7", "show_tab('tab-help')", "Help", show=False),
    ]
    CSS = """
    Screen { background: #0e1116; color: #d7dee8; }
    Header { background: #151b23; }
    Footer { background: #151b23; }
    TabbedContent { height: 1fr; }
    TabPane { padding: 1 2; height: 1fr; }
    #stats-box {
        background: #151b23;
        border: solid #26303b;
        padding: 1 2;
        margin-bottom: 1;
        width: 100%;
    }
    #pivot-controls { height: auto; margin-bottom: 1; }
    #target { width: 36; }
    #scope { width: 26; }
    #sources-input { width: 52; }
    #expand, #variants, #avatar { width: auto; margin-right: 2; }
    #pivot-status { height: auto; margin: 1 0; color: #8b98a9; }
    #pivot-loading { height: 1; }
    #pivot-results { height: 1fr; }
    #dash-runs { height: 14; }
    #browse-runs { width: 38; }
    #browse-detail { width: 1fr; }
    #browse-profiles { height: 12; }
    #browse-posts { height: 1fr; }
    #browse-evidence { height: 8; }
    #search-q { width: 52; }
    #search-results { height: 1fr; }
    #tool-select { width: 30; }
    #tool-target { width: 1fr; }
    #tool-source { width: 26; }
    #tool-output {
        background: #151b23;
        border: solid #26303b;
        padding: 1 2;
        height: 1fr;
        overflow-y: auto;
    }
    #case-name { width: 40; }
    #cases-table { height: 12; margin-bottom: 1; }
    #annotations-table { height: 1fr; }
    #help-text { padding: 1 2; }
    DataTable { background: #0e1116; }
    """

    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self.settings = settings
        self._live_checked = 0
        self._live_found = 0

    # -- layout -------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent(initial="tab-dashboard"):
            with TabPane("Dashboard", id="tab-dashboard"):
                with VerticalScroll():
                    yield Static("loading…", id="stats-box")
                    yield DataTable(id="dash-runs")
            with TabPane("Pivot", id="tab-pivot"):
                with Vertical():
                    with Horizontal(id="pivot-controls"):
                        yield Input(placeholder="username or email", id="target")
                        yield Select(
                            [("curated", "curated"), ("web corpus", "web"), ("custom", "custom")],
                            value="curated",
                            allow_blank=False,
                            id="scope",
                        )
                        yield Button("Run", id="run-pivot", variant="primary")
                    with Horizontal():
                        yield Checkbox("expand", id="expand")
                        yield Checkbox("variants", id="variants")
                        yield Checkbox("avatar hash", value=False, id="avatar")
                    yield Input(
                        placeholder="custom sources: github, reddit, social, all",
                        id="sources-input",
                        classes="hidden",
                    )
                    yield Static("", id="pivot-status")
                    yield LoadingIndicator(id="pivot-loading")
                    yield DataTable(id="pivot-results")
            with TabPane("Browse", id="tab-browse"):
                with Horizontal():
                    yield DataTable(id="browse-runs")
                    with Vertical(id="browse-detail"):
                        yield DataTable(id="browse-profiles")
                        yield DataTable(id="browse-posts")
                        yield DataTable(id="browse-evidence")
            with TabPane("Search", id="tab-search"):
                with Vertical():
                    with Horizontal():
                        yield Input(placeholder="full-text search over posts", id="search-q")
                        yield Button("Search", id="search-btn")
                    yield DataTable(id="search-results")
            with TabPane("Tools", id="tab-tools"):
                with Vertical():
                    with Horizontal():
                        yield Select(
                            [
                                ("domain intel", "domain"),
                                ("ip intel", "ip"),
                                ("phone parse", "phone"),
                                ("dorks", "dorks"),
                                ("breach audit", "breach"),
                                ("harvest posts", "harvest"),
                            ],
                            value="domain",
                            allow_blank=False,
                            id="tool-select",
                        )
                        yield Button("Run tool", id="tool-run", variant="primary")
                    with Horizontal():
                        yield Input(
                            placeholder="domain / IP / phone / handle / email",
                            id="tool-target",
                        )
                        yield Input(placeholder="source (harvest)", id="tool-source")
                    yield Static("", id="tool-output", markup=False)
            with TabPane("Cases", id="tab-cases"):
                with Vertical():
                    with Horizontal():
                        yield Input(placeholder="new case name", id="case-name")
                        yield Button("Create case", id="case-create", variant="primary")
                    yield DataTable(id="cases-table")
                    yield DataTable(id="annotations-table")
            with TabPane("Help", id="tab-help"):
                with VerticalScroll():
                    yield Static(HELP_TEXT, id="help-text")
        yield Footer()

    def on_mount(self) -> None:
        dashboard = self.query_one("#dash-runs", DataTable)
        dashboard.add_columns("ID", "Kind", "Target", "Started", "Status")
        pivot_results = self.query_one("#pivot-results", DataTable)
        pivot_results.cursor_type = "row"
        pivot_results.add_columns("Source", "Status", "Target", "Handle", "URL")
        runs_table = self.query_one("#browse-runs", DataTable)
        runs_table.cursor_type = "row"
        runs_table.add_columns("ID", "Kind", "Target", "Status")
        profiles_table = self.query_one("#browse-profiles", DataTable)
        profiles_table.cursor_type = "row"
        profiles_table.add_columns("Source", "Username", "Name", "URL")
        posts_table = self.query_one("#browse-posts", DataTable)
        posts_table.cursor_type = "row"
        posts_table.add_columns("When", "Source", "Username", "Text")
        evidence_table = self.query_one("#browse-evidence", DataTable)
        evidence_table.cursor_type = "row"
        evidence_table.add_columns("File", "Size", "SHA-256", "Note")
        search_table = self.query_one("#search-results", DataTable)
        search_table.cursor_type = "row"
        search_table.add_columns("When", "Source", "Username", "Text")
        cases_table = self.query_one("#cases-table", DataTable)
        cases_table.cursor_type = "row"
        cases_table.add_columns("ID", "Name", "Runs", "Created")
        annotations_table = self.query_one("#annotations-table", DataTable)
        annotations_table.cursor_type = "row"
        annotations_table.add_columns("Kind", "Target", "Value", "When")
        self.query_one("#pivot-loading", LoadingIndicator).display = False
        self.refresh_data()
        self.refresh_cases()

    # -- actions ------------------------------------------------------------

    def action_show_tab(self, tab_id: str) -> None:
        self.query_one(TabbedContent).active = tab_id

    def action_refresh(self) -> None:
        self.refresh_data()
        self.refresh_cases()
        self.notify("refreshed")

    # -- drill-down actions -------------------------------------------------

    def _focused_row(self) -> tuple[str, list[str]] | None:
        widget = self.focused
        if not isinstance(widget, DataTable) or widget.row_count == 0:
            return None
        try:
            values = widget.get_row_at(widget.cursor_row)
        except Exception:
            return None
        return widget.id or "", [str(value) for value in values]

    def action_pivot_row(self) -> None:
        row = self._focused_row()
        if row is None:
            self.notify("focus a data row first", severity="warning")
            return
        table_id, values = row
        if table_id == "browse-profiles":
            target = values[1]
        elif table_id == "browse-posts":
            target = values[2]
        elif table_id == "pivot-results":
            target = values[3] or values[2]
        elif table_id == "search-results":
            target = values[2]
        elif table_id == "annotations-table" and len(values) > 1:
            target = values[1].split(":")[-1]
        else:
            self.notify("no pivotable row focused", severity="warning")
            return
        if not target:
            self.notify("selected row has no handle", severity="warning")
            return
        self.query_one(TabbedContent).active = "tab-pivot"
        self.query_one("#target", Input).value = target
        self.start_pivot()

    def action_harvest_row(self) -> None:
        row = self._focused_row()
        if row is None:
            self.notify("focus a data row first", severity="warning")
            return
        table_id, values = row
        if table_id == "browse-profiles":
            source, username = values[0], values[1]
        elif table_id == "browse-posts":
            source, username = values[1], values[2]
        elif table_id == "pivot-results":
            source, username = values[0], (values[3] or values[2])
        else:
            self.notify("no harvestable row focused", severity="warning")
            return
        self.query_one(TabbedContent).active = "tab-tools"
        self.query_one("#tool-select", Select).value = "harvest"
        self.query_one("#tool-source", Input).value = source
        self.query_one("#tool-target", Input).value = username
        self.start_tool()

    def action_diff_runs(self) -> None:
        with Store(self.settings.db_path) as store:
            runs = store.runs(limit=2)
            if len(runs) < 2:
                self.notify("need at least two runs to diff", severity="warning")
                return
            payload = diff_runs(store, runs[1]["id"], runs[0]["id"])
        self.query_one(TabbedContent).active = "tab-tools"
        self.query_one("#tool-output", Static).update(
            json.dumps(payload, indent=2, ensure_ascii=False, default=str)
        )
        self.notify(f"diff run #{runs[1]['id']} → #{runs[0]['id']}")

    def refresh_data(self) -> None:
        with Store(self.settings.db_path) as store:
            stats = store.stats()
            runs = store.runs(limit=50)
            health = store.check_stats()
            info = store.db_info()
        found = sum(row["count"] for row in health if row["status"] == "found")
        errors = sum(row["count"] for row in health if row["status"] in ("error", "blocked"))
        db_line = (
            f"[b]Database[/b] {info['path']}  ·  {info['size']} bytes"
            f"  ·  schema v{info['user_version']}"
        )
        self.query_one("#stats-box", Static).update(
            f"{db_line}\n"
            f"[b]Runs[/b] {stats['runs']}  [b]Checks[/b] {stats['checks']}  "
            f"[b]Profiles[/b] {stats['profiles']}  [b]Posts[/b] {stats['posts']}\n"
            f"[b]Links[/b] {stats['links']}  [b]Clusters[/b] {stats['clusters']}  "
            f"[b]Entities[/b] {stats['entities']}  [b]Cases[/b] {stats['cases']}  "
            f"[b]Evidence[/b] {stats['attachments']}\n"
            f"[green]{found} found[/green]  [red]{errors} blocked/error[/red]"
        )
        dashboard = self.query_one("#dash-runs", DataTable)
        dashboard.clear()
        for run in runs[:25]:
            dashboard.add_row(
                str(run["id"]),
                run["kind"],
                run["target"],
                (run["started_at"] or "")[:19],
                run["status"],
            )
        browse = self.query_one("#browse-runs", DataTable)
        browse.clear()
        for run in runs:
            browse.add_row(
                str(run["id"]), run["kind"], run["target"], run["status"], key=str(run["id"])
            )

    def refresh_cases(self) -> None:
        with Store(self.settings.db_path) as store:
            cases = store.cases()
            tags = store.tags()
            notes = store.notes()
        cases_table = self.query_one("#cases-table", DataTable)
        cases_table.clear()
        for case in cases:
            cases_table.add_row(
                str(case["id"]),
                case["name"],
                str(case["runs"]),
                (case["created_at"] or "")[:19],
            )
        annotations = self.query_one("#annotations-table", DataTable)
        annotations.clear()
        for tag in tags:
            annotations.add_row("tag", tag["target"], tag["tag"], "")
        for note in notes:
            annotations.add_row("note", note["target"], note["note"], note["created_at"][:19])

    # -- pivot --------------------------------------------------------------

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "scope":
            self.query_one("#sources-input", Input).set_class(event.value != "custom", "hidden")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "target":
            self.start_pivot()
        elif event.input.id == "search-q":
            self.run_search(event.value)
        elif event.input.id == "tool-target":
            self.start_tool()
        elif event.input.id == "case-name":
            self.create_case()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run-pivot":
            self.start_pivot()
        elif event.button.id == "search-btn":
            self.run_search(self.query_one("#search-q", Input).value)
        elif event.button.id == "tool-run":
            self.start_tool()
        elif event.button.id == "case-create":
            self.create_case()

    def start_pivot(self) -> None:
        target = self.query_one("#target", Input).value.strip()
        if not target:
            self.notify("enter a target first", severity="warning")
            return
        scope = str(self.query_one("#scope", Select).value)
        sources_text = self.query_one("#sources-input", Input).value
        names = [part for part in sources_text.replace(",", " ").split() if part] or None
        if scope == "custom" and not names:
            self.notify("custom scope needs source names", severity="warning")
            return
        if scope != "custom":
            names = None
        include_web = scope == "web"
        expand = self.query_one("#expand", Checkbox).value
        variants = self.query_one("#variants", Checkbox).value
        avatar = self.query_one("#avatar", Checkbox).value
        status = self.query_one("#pivot-status", Static)
        status.update(f"[yellow]probing {target}…[/yellow]")
        self.query_one("#pivot-loading", LoadingIndicator).display = True
        self.query_one("#pivot-results", DataTable).clear()
        self._live_checked = 0
        self._live_found = 0
        self.run_pivot_worker(target, names, include_web, expand, variants, avatar)

    def _pivot_row(self, result: Any) -> None:
        table = self.query_one("#pivot-results", DataTable)
        handle = result.profile.username if result.profile else ""
        url = result.profile.url if result.profile else ""
        table.add_row(result.source, result.status, result.target, handle, url)
        self._live_checked += 1
        if result.status == "found":
            self._live_found += 1
        self.query_one("#pivot-status", Static).update(
            f"[yellow]running…[/yellow] [green]{self._live_found} found[/green]"
            f" / {self._live_checked} checked"
        )

    @work(thread=True, exclusive=True, group="pivot")
    def run_pivot_worker(
        self,
        target: str,
        sources: list[str] | None,
        include_web: bool,
        expand: bool,
        variants: bool,
        avatar: bool,
    ) -> None:
        def on_result(result: Any) -> None:
            with contextlib.suppress(Exception):
                self.call_from_thread(self._pivot_row, result)

        try:
            store = Store(self.settings.db_path)
            try:
                report = asyncio.run(
                    run_pivot(
                        target,
                        settings=self.settings,
                        sources=sources,
                        expand=expand,
                        use_variants=variants,
                        include_web=include_web,
                        avatar_hash=avatar,
                        store=store,
                        on_result=on_result,
                    )
                )
                run_id = persist_pivot(store, report)
            finally:
                store.close()
            self.call_from_thread(self._pivot_finished, report, run_id, None)
        except Exception as exc:  # surface any failure in the UI
            self.call_from_thread(self._pivot_finished, None, None, f"{type(exc).__name__}: {exc}")

    def _pivot_finished(self, report: Any, run_id: int | None, error: str | None) -> None:
        self.query_one("#pivot-loading", LoadingIndicator).display = False
        status = self.query_one("#pivot-status", Static)
        if error:
            status.update(f"[red]pivot failed: {error}[/red]")
            return
        # Streaming normally populated the table already; reconcile from the
        # report so the final view is complete even if a callback was missed.
        table = self.query_one("#pivot-results", DataTable)
        if table.row_count != len(report.results):
            table.clear()
            for result in report.results:
                handle = result.profile.username if result.profile else ""
                url = result.profile.url if result.profile else ""
                table.add_row(result.source, result.status, result.target, handle, url)
        found = report.coverage.get("found", 0)
        status.update(
            f"[green]{found} found[/green] of {len(report.results)} checks  ·  "
            f"{len(report.clusters)} clusters  ·  saved as run #{run_id}"
        )
        self.refresh_data()

    # -- browse -------------------------------------------------------------

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id != "browse-runs":
            return
        try:
            run_id = int(str(event.row_key.value))
        except (TypeError, ValueError):
            return
        with Store(self.settings.db_path) as store:
            profiles = store.profiles(run_id=run_id, limit=500)
            posts = store.posts(run_id=run_id, limit=200)
            attachments = store.attachments(run_id=run_id, limit=200)
        profiles_table = self.query_one("#browse-profiles", DataTable)
        profiles_table.clear()
        for profile in profiles:
            profiles_table.add_row(
                profile["source"],
                profile["username"],
                profile["display_name"] or "",
                profile["url"],
            )
        posts_table = self.query_one("#browse-posts", DataTable)
        posts_table.clear()
        for post in posts:
            posts_table.add_row(
                (post["created_at"] or "")[:19],
                post["source"],
                post["username"],
                " ".join((post["text"] or "").split())[:120],
            )
        evidence_table = self.query_one("#browse-evidence", DataTable)
        evidence_table.clear()
        for attachment in attachments:
            evidence_table.add_row(
                attachment["filename"],
                f"{attachment['size']} B",
                attachment["sha256"][:12],
                attachment["note"] or "",
            )
        self.notify(
            f"run #{run_id}: {len(profiles)} profiles, {len(posts)} posts, "
            f"{len(attachments)} evidence"
        )

    # -- search -------------------------------------------------------------

    def run_search(self, query: str) -> None:
        query = query.strip()
        table = self.query_one("#search-results", DataTable)
        table.clear()
        if not query:
            return
        with Store(self.settings.db_path) as store:
            rows = store.search(query, limit=200)
        for row in rows:
            table.add_row(
                (row["created_at"] or "")[:19],
                row["source"],
                row["username"],
                " ".join((row["text"] or "").split())[:120],
            )
        self.notify(f"{len(rows)} results for {query!r}")

    # -- tools --------------------------------------------------------------

    def start_tool(self) -> None:
        tool = str(self.query_one("#tool-select", Select).value)
        target = self.query_one("#tool-target", Input).value.strip()
        source = self.query_one("#tool-source", Input).value.strip() or "github"
        if not target:
            self.notify("enter a tool target first", severity="warning")
            return
        self.query_one("#tool-output", Static).update(f"running {tool}…")
        self.run_tool_worker(tool, target, source)

    @work(thread=True, exclusive=True, group="tool")
    def run_tool_worker(self, tool: str, target: str, source: str) -> None:
        try:
            result: Any
            if tool == "domain":

                async def _run():
                    async with Fetcher(self.settings) as fetcher:
                        return await lookup_domain(fetcher, target, deep=True)

                result = asyncio.run(_run())
            elif tool == "ip":

                async def _run():
                    async with Fetcher(self.settings) as fetcher:
                        return {
                            "address": target,
                            "ptr": await ptr(fetcher, target),
                            "hostnames": await reverse_ip(
                                fetcher, target, self.settings.shodan_api_key
                            ),
                            "asn": await asn_lookup(fetcher, target),
                            "rdap": await rdap_ip(fetcher, target),
                        }

                result = asyncio.run(_run())
            elif tool == "phone":
                result = phone_lookup(target) or {"error": "invalid number"}
            elif tool == "dorks":
                result = build_dorks(target)
            elif tool == "breach":

                async def _run():
                    async with Fetcher(self.settings) as fetcher:
                        return await full_breach_audit(fetcher, target)

                result = asyncio.run(_run())
            elif tool == "harvest":
                store = Store(self.settings.db_path)
                try:
                    check, posts = asyncio.run(
                        run_harvest(source, target, settings=self.settings, limit=25, store=store)
                    )
                    run_id = store.start_run("harvest", f"{source}:{target}")
                    store.save_checks(run_id, [check])
                    if check.profile:
                        store.save_profiles(run_id, [check.profile])
                        store.record_profile_history(run_id, [check.profile])
                    store.save_posts(run_id, posts)
                    store.finish_run(run_id)
                finally:
                    store.close()
                result = {
                    "run_id": run_id,
                    "status": check.status,
                    "profile": check.profile.username if check.profile else None,
                    "posts": len(posts),
                }
            else:
                result = {"error": f"unknown tool {tool}"}
            self.call_from_thread(self._tool_finished, tool, result, None)
        except Exception as exc:
            self.call_from_thread(self._tool_finished, tool, None, f"{type(exc).__name__}: {exc}")

    def _tool_finished(self, tool: str, result: Any, error: str | None) -> None:
        output = self.query_one("#tool-output", Static)
        if error:
            output.update(f"{tool} failed: {error}")
            return
        text = json.dumps(result, indent=2, ensure_ascii=False, default=str)
        output.update(f"{tool}\n{text}")
        self.refresh_data()

    # -- cases --------------------------------------------------------------

    def create_case(self) -> None:
        name = self.query_one("#case-name", Input).value.strip()
        if not name:
            self.notify("enter a case name", severity="warning")
            return
        with Store(self.settings.db_path) as store:
            try:
                case_id = store.create_case(name)
            except Exception as exc:
                self.notify(f"could not create case: {exc}", severity="error")
                return
        self.query_one("#case-name", Input).value = ""
        self.refresh_cases()
        self.notify(f"created case #{case_id} {name}")


def run_tui(settings: Settings) -> None:
    if settings.retention_days:
        with Store(settings.db_path) as store:
            store.prune(settings.retention_days)
    ColdTrailTUI(settings).run()
