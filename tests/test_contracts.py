"""Contract/drift tests: every curated source has a contract, and recorded
fixtures replay through the parsers offline."""

from __future__ import annotations

import base64
import json

import httpx
import pytest
import respx
from typer.testing import CliRunner

from larpharvester.cli import app
from larpharvester.config import Settings
from larpharvester.contracts import (
    CONTRACTS,
    record_contract,
    validate_result,
    verify_contract,
)
from larpharvester.models import CheckResult
from larpharvester.sources import CURATED

runner = CliRunner()


def _b64(payload: dict | list | str) -> str:
    raw = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
    return base64.b64encode(raw).decode()


def _github_fixture(target: str = "octocat") -> dict:
    return {
        "source": "github",
        "target": target,
        "observed_status": "found",
        "exchanges": [
            {
                "url": f"https://api.github.com/users/{target}",
                "status": 200,
                "body_b64": _b64(
                    {
                        "login": target,
                        "html_url": f"https://github.com/{target}",
                        "name": "Octo",
                        "bio": "hi",
                        "followers": 42,
                    }
                ),
            },
            {
                "url": f"https://api.github.com/users/{target}/keys",
                "status": 200,
                "body_b64": _b64([]),
            },
            {
                "url": f"https://api.github.com/users/{target}/gpg_keys",
                "status": 200,
                "body_b64": _b64([]),
            },
        ],
    }


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(db_path=tmp_path / "t.db", requests_per_second=0, jitter=0)


def test_every_curated_source_has_a_contract():
    missing = set(CURATED) - set(CONTRACTS)
    assert not missing, f"curated sources without contracts: {sorted(missing)}"
    for name, contract in CONTRACTS.items():
        assert contract.target, f"{name} has no contract target"
        assert contract.status in ("found", "not_found")


async def test_verify_contract_replays_fixture(settings, tmp_path):
    directory = tmp_path / "fixtures"
    directory.mkdir()
    (directory / "github.json").write_text(json.dumps(_github_fixture()))
    problems = await verify_contract("github", settings, directory)
    assert problems == []


async def test_verify_contract_detects_missing_required_field(settings, tmp_path):
    directory = tmp_path / "fixtures"
    directory.mkdir()
    fixture = _github_fixture()
    fixture["exchanges"][0]["body_b64"] = _b64(
        {"login": "octocat", "html_url": "https://github.com/octocat"}
    )
    (directory / "github.json").write_text(json.dumps(fixture))
    problems = await verify_contract("github", settings, directory)
    assert any("followers" in problem for problem in problems)


async def test_verify_contract_missing_fixture(settings, tmp_path):
    problems = await verify_contract("github", settings, tmp_path / "nope")
    assert problems and "no fixture" in problems[0]


async def test_record_contract_captures_replayable_exchanges(settings, tmp_path, monkeypatch):
    directory = tmp_path / "recorded"
    with respx.mock:
        respx.get("https://api.github.com/users/octocat").mock(
            return_value=httpx.Response(
                200,
                json={
                    "login": "octocat",
                    "html_url": "https://github.com/octocat",
                    "followers": 42,
                },
            )
        )
        respx.get("https://api.github.com/users/octocat/keys").mock(
            return_value=httpx.Response(200, json=[])
        )
        respx.get("https://api.github.com/users/octocat/gpg_keys").mock(
            return_value=httpx.Response(200, json=[])
        )
        payload = await record_contract("github", settings, directory)
    assert payload["observed_status"] == "found"
    assert payload["profile"]["username"] == "octocat"
    assert payload["exchanges"]
    fixture_file = directory / "github.json"
    assert fixture_file.is_file()
    # The recorded fixture must replay cleanly through the parser.
    problems = await verify_contract("github", settings, directory)
    assert problems == []


def test_validate_result_reports_status_mismatch():
    problems = validate_result("github", CheckResult("github", "octocat", "not_found", detail="x"))
    assert any("expected status 'found'" in problem for problem in problems)


def test_cli_source_verify_offline(tmp_path):
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    (fixtures / "github.json").write_text(json.dumps(_github_fixture()))
    result = runner.invoke(
        app,
        [
            "--db",
            str(tmp_path / "t.db"),
            "source",
            "verify",
            "-s",
            "github",
            "--dir",
            str(fixtures),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["failures"] == {}


def test_cli_source_verify_fails_without_fixture(tmp_path):
    result = runner.invoke(
        app,
        [
            "--db",
            str(tmp_path / "t.db"),
            "source",
            "verify",
            "-s",
            "github",
            "--dir",
            str(tmp_path / "missing"),
            "--json",
        ],
    )
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert "github" in payload["failures"]


def test_cli_source_verify_rejects_unknown_source(tmp_path):
    result = runner.invoke(
        app,
        ["--db", str(tmp_path / "t.db"), "source", "verify", "-s", "nope"],
    )
    assert result.exit_code == 2
    assert "unknown source" in result.output
