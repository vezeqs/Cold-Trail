"""Case aggregation and export tests."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from coldtrail.casework import merge_case_payload
from coldtrail.cli import app
from coldtrail.config import Settings
from coldtrail.evidence import add_evidence
from coldtrail.models import Profile
from coldtrail.store import Store

runner = CliRunner()


def _seed(tmp_path) -> Settings:
    settings = Settings(db_path=tmp_path / "t.db")
    with Store(settings.db_path) as store:
        first = store.start_run("pivot", "alice")
        profile = Profile(
            source="github",
            username="alice",
            url="https://github.com/alice",
            display_name="Alice",
            extra={},
        )
        store.save_profiles(first, [profile])
        add_evidence(store, data=b"case evidence", filename="shot.txt", run_id=first)
        store.finish_run(first)
        second = store.start_run("pivot", "alice")
        store.save_profiles(
            second,
            [profile, Profile(source="gitlab", username="alice", url="https://gitlab.com/alice")],
        )
        store.finish_run(second)
        case_id = store.create_case("op-alice")
        store.add_to_case(case_id, first)
        store.add_to_case(case_id, second)
    return settings


def test_merge_case_payload_dedupes_runs(tmp_path):
    settings = _seed(tmp_path)
    with Store(settings.db_path) as store:
        case = store.case("op-alice")
        payload = merge_case_payload(store, case)
    assert payload["run"]["id"] == "case:op-alice"
    assert {profile["source"] for profile in payload["profiles"]} == {"github", "gitlab"}
    assert len(payload["profiles"]) == 2  # github profile deduped across runs
    assert payload["attachments"][0]["filename"] == "shot.txt"


def test_case_export_cli_json_and_markdown(tmp_path):
    settings = _seed(tmp_path)
    db = str(settings.db_path)
    result = runner.invoke(app, ["--db", db, "case", "export", "op-alice", "--format", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["run"]["target"] == "op-alice"

    out = tmp_path / "case.md"
    result = runner.invoke(
        app, ["--db", db, "case", "export", "op-alice", "--format", "md", "-o", str(out)]
    )
    assert result.exit_code == 0, result.output
    text = out.read_text()
    assert "case:op-alice" in text
    assert "github" in text


def test_case_export_missing_case(tmp_path):
    settings = Settings(db_path=tmp_path / "t.db")
    result = runner.invoke(app, ["--db", str(settings.db_path), "case", "export", "nope"])
    assert result.exit_code == 1
    assert "no such case" in result.output
