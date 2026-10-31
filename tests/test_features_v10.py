"""Tests for the 0.10 features: config, schema, SARIF, and HTML diff."""

from __future__ import annotations

import json
import re
import stat
from dataclasses import asdict

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from coldtrail.cli import app
from coldtrail.config import Settings
from coldtrail.models import Entity, PivotReport, Profile
from coldtrail.store import Store
from coldtrail.web import create_app

runner = CliRunner()


@pytest.fixture
def seeded(tmp_path):
    db = tmp_path / "features.db"
    with Store(db) as store:
        baseline = store.start_run("pivot", "alice")
        store.save_profiles(baseline, [Profile("github", "alice", "https://github.com/alice")])
        store.save_entities(baseline, [Entity("github", "alice", "email", "alice@example.com")])
        store.finish_run(baseline)
        comparison = store.start_run("pivot", "alice")
        store.save_profiles(
            comparison,
            [
                Profile("github", "alice", "https://github.com/alice"),
                Profile("gitlab", "alice", "https://gitlab.com/alice"),
            ],
        )
        store.save_entities(
            comparison,
            [
                Entity("github", "alice", "email", "alice@example.com"),
                Entity("gitlab", "alice", "email", "alice@example.com"),
            ],
        )
        store.finish_run(comparison)
    return db, baseline, comparison


# -- config ----------------------------------------------------------------


def test_config_reports_provenance_and_redacts(tmp_path, monkeypatch):
    db = tmp_path / "config.db"
    result = runner.invoke(app, ["--db", str(db), "config", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    rows = {row["key"]: row for row in payload["settings"]}
    assert rows["db_path"]["value"] == str(db)
    assert rows["db_path"]["source"] == "flag"
    assert rows["github_token"]["value"] == "unset"
    assert rows["github_token"]["secret"] is True

    monkeypatch.setenv("GITHUB_TOKEN", "super-secret-token")
    result = runner.invoke(app, ["--db", str(db), "config", "--json"])
    assert result.exit_code == 0, result.output
    rows = {row["key"]: row for row in json.loads(result.output)["settings"]}
    assert rows["github_token"]["source"] == "env"
    assert rows["github_token"]["value"] == "set"
    assert "super-secret-token" not in result.output


def test_config_redacts_proxy_and_marks_toml(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text("timeout = 3.5\n", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "--config",
            str(config),
            "--db",
            str(tmp_path / "t.db"),
            "--proxy",
            "http://user:s3cret@proxy.test:8080",
            "config",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    rows = {row["key"]: row for row in payload["settings"]}
    assert rows["timeout"]["source"] == "config"
    assert rows["timeout"]["value"] == 3.5
    assert rows["proxy"]["source"] == "flag"
    assert rows["proxy"]["value"] == "http://[redacted]@proxy.test:8080"
    assert "s3cret" not in result.output


# -- schema ----------------------------------------------------------------


def test_schema_lists_names_and_emits_pivot_contract():
    result = runner.invoke(app, ["schema", "--list"])
    assert result.exit_code == 0
    names = set(result.output.split())
    assert {"pivot", "run", "diff", "doctor", "config", "sources", "stats"} <= names

    result = runner.invoke(app, ["schema", "pivot"])
    assert result.exit_code == 0
    schema = json.loads(result.output)
    assert schema["$schema"].endswith("2020-12/schema")
    report = asdict(PivotReport(target="alice", kind="username", results=[], links=[]))
    assert set(schema["required"]) <= set(report)

    result = runner.invoke(app, ["schema", "not-a-schema"])
    assert result.exit_code == 2
    assert "unknown schema" in result.output


def test_run_schema_matches_export_shape(seeded):
    db, run_id, _ = seeded
    with Store(db) as store:
        payload = store.export_run(run_id)
    result = runner.invoke(app, ["schema", "run"])
    schema = json.loads(result.output)
    assert set(schema["required"]) <= set(payload)


# -- SARIF -----------------------------------------------------------------


def test_sarif_export_filters_unsafe_urls(seeded):
    db, run_id, _ = seeded
    result = runner.invoke(app, ["--db", str(db), "export", str(run_id), "--format", "sarif"])
    assert result.exit_code == 0, result.output
    document = json.loads(result.output)
    assert document["version"] == "2.1.0"
    run = document["runs"][0]
    assert run["tool"]["driver"]["name"] == "ColdTrail"
    rule_ids = {item["ruleId"] for item in run["results"]}
    assert "coldtrail/profile" in rule_ids
    assert "coldtrail/entity/email" in rule_ids
    for item in run["results"]:
        for location in item.get("locations", []):
            uri = location["physicalLocation"]["artifactLocation"]["uri"]
            assert uri.startswith(("http://", "https://"))


def test_sarif_omits_javascript_urls(tmp_path):
    db = tmp_path / "unsafe.db"
    with Store(db) as store:
        run_id = store.start_run("pivot", "alice")
        store.save_profiles(run_id, [Profile("github", "alice", "javascript:alert(1)")])
        store.finish_run(run_id)
    result = runner.invoke(app, ["--db", str(db), "export", str(run_id), "--format", "sarif"])
    assert result.exit_code == 0, result.output
    document = json.loads(result.output)
    assert all("locations" not in item for item in document["runs"][0]["results"])


def test_web_export_sarif(seeded):
    db, run_id, _ = seeded
    client = TestClient(create_app(Settings(db_path=db)))
    response = client.get(f"/runs/{run_id}/export?format=sarif")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/sarif+json")
    assert response.json()["version"] == "2.1.0"


# -- HTML diff -------------------------------------------------------------


def test_diff_html_writes_private_file(seeded, tmp_path):
    db, baseline, comparison = seeded
    destination = tmp_path / "diff.html"
    result = runner.invoke(
        app,
        [
            "--db",
            str(db),
            "diff",
            str(baseline),
            str(comparison),
            "--format",
            "html",
            "-o",
            str(destination),
        ],
    )
    assert result.exit_code == 0, result.output
    body = destination.read_text(encoding="utf-8")
    assert "<!doctype html>" in body
    assert "Profiles added / removed" in body
    assert "gitlab:alice" in body
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_diff_html_escapes_harvested_text(tmp_path):
    db = tmp_path / "escape.db"
    with Store(db) as store:
        first = store.start_run("pivot", "alice")
        store.finish_run(first)
        second = store.start_run("pivot", "alice")
        store.save_profiles(second, [Profile("github", "<script>alert(1)</script>", "https://x/y")])
        store.finish_run(second)
    result = runner.invoke(
        app, ["--db", str(db), "diff", str(first), str(second), "--format", "html"]
    )
    assert result.exit_code == 0, result.output
    assert "&lt;script&gt;" in result.output
    assert "<script>alert(1)</script>" not in result.output


def test_diff_out_requires_html(seeded, tmp_path):
    db, baseline, comparison = seeded
    result = runner.invoke(
        app,
        [
            "--db",
            str(db),
            "diff",
            str(baseline),
            str(comparison),
            "-o",
            str(tmp_path / "diff.txt"),
        ],
    )
    assert result.exit_code == 2
    text = re.sub(r"\x1b\[[0-9;]*m", "", result.output)
    text = " ".join(text.split())
    assert "requires" in text and "html" in text


def test_web_diff_html_download(seeded):
    db, baseline, comparison = seeded
    client = TestClient(create_app(Settings(db_path=db)))
    response = client.get(f"/diff?a={baseline}&b={comparison}&format=html")
    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    assert "Profiles added / removed" in response.text
