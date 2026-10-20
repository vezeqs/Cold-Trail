"""Content-addressed evidence storage tests."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from larpharvester.cli import app
from larpharvester.config import Settings
from larpharvester.evidence import add_evidence, evidence_path, verify_evidence
from larpharvester.store import Store

runner = CliRunner()


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(db_path=tmp_path / "t.db", requests_per_second=0, jitter=0)


def test_add_evidence_is_content_addressed_and_deduped(settings, tmp_path):
    payload = b"same bytes"
    with Store(settings.db_path) as store:
        first = add_evidence(store, data=payload, filename="a.txt", run_id=None)
        second = add_evidence(store, data=payload, filename="b.txt", run_id=None)
        rows = store.attachments()
    assert first["sha256"] == second["sha256"]
    assert first["path"] == second["path"]
    assert len(rows) == 2  # two metadata rows, one blob
    assert evidence_path(store, first["sha256"]).read_bytes() == payload


def test_add_evidence_from_file_and_verify(settings, tmp_path):
    source = tmp_path / "note.txt"
    source.write_text("hello")
    with Store(settings.db_path) as store:
        payload = add_evidence(store, source_path=source, note="manual")
        assert payload["size"] == 5
        assert verify_evidence(store) == []
        # Corrupt the blob: verification must report a hash mismatch.
        evidence_path(store, payload["sha256"]).write_bytes(b"tampered")
        problems = verify_evidence(store)
    assert problems and "hash mismatch" in problems[0]["problem"]


def test_evidence_cli_add_list_export_verify(settings, tmp_path):
    source = tmp_path / "artifact.txt"
    source.write_text("artifact body")
    db = str(settings.db_path)

    added = runner.invoke(app, ["--db", db, "evidence", "add", str(source), "--json"])
    assert added.exit_code == 0, added.output
    payload = json.loads(added.output)
    assert payload["size"] == len(b"artifact body")

    listed = runner.invoke(app, ["--db", db, "evidence", "list", "--json"])
    assert listed.exit_code == 0, listed.output
    rows = json.loads(listed.output)
    assert rows[0]["filename"] == "artifact.txt"

    destination = tmp_path / "copy.txt"
    exported = runner.invoke(
        app, ["--db", db, "evidence", "export", str(payload["id"]), "-o", str(destination)]
    )
    assert exported.exit_code == 0, exported.output
    assert destination.read_text() == "artifact body"

    verified = runner.invoke(app, ["--db", db, "evidence", "verify", "--json"])
    assert verified.exit_code == 0, verified.output
    assert json.loads(verified.output)["problems"] == []


def test_evidence_verify_fails_on_missing_blob(settings, tmp_path):
    with Store(settings.db_path) as store:
        payload = add_evidence(store, data=b"gone", filename="gone.bin")
        evidence_path(store, payload["sha256"]).unlink()
    result = runner.invoke(app, ["--db", str(settings.db_path), "evidence", "verify", "--json"])
    assert result.exit_code == 1
    assert "missing file" in result.output


def test_export_run_includes_attachments(settings):
    with Store(settings.db_path) as store:
        run_id = store.start_run("pivot", "alice")
        add_evidence(store, data=b"x", filename="x.txt", run_id=run_id)
        store.finish_run(run_id)
        payload = store.export_run(run_id)
    assert payload["attachments"][0]["filename"] == "x.txt"
