from __future__ import annotations

import json

import httpx
import respx
from typer.testing import CliRunner

from larpharvester.cli import app
from larpharvester.models import Post, Profile
from larpharvester.store import Store

runner = CliRunner()


def invoke(args):
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    return result


def seed_posts(tmp_path):
    db = tmp_path / "t.db"
    text = "I think this is really just the best and I always say so because it is"
    with Store(db) as store:
        run_id = store.start_run("harvest", "alice")
        store.save_profiles(
            run_id,
            [
                Profile(source="github", username="alice", url="https://github.com/alice"),
                Profile(source="gitlab", username="alice2", url="https://gitlab.com/alice2"),
            ],
        )
        for index, (source, username) in enumerate([("github", "alice"), ("gitlab", "alice2")]):
            store.save_posts(
                run_id,
                [
                    Post(
                        source=source,
                        username=username,
                        post_id=f"{index}-{i}",
                        url="u",
                        text=text,
                        created_at=f"2024-01-01T20:{i:02d}:00Z",
                    )
                    for i in range(6)
                ],
            )
        store.finish_run(run_id)
    return db


def test_analyze_timezone_and_style(tmp_path):
    db = seed_posts(tmp_path)
    result = invoke(["--db", str(db), "analyze", "--json"])
    payload = json.loads(result.output)
    assert payload["timezones"]
    assert payload["style_pairs"]
    assert payload["style_pairs"][0]["similarity"] > 0.9


def test_phone_cli(tmp_path):
    result = invoke(["--db", str(tmp_path / "t.db"), "phone", "+351912345678", "--json"])
    assert json.loads(result.output)["country_code"] == 351


def test_phone_cli_invalid(tmp_path):
    result = runner.invoke(app, ["--db", str(tmp_path / "t.db"), "phone", "123"])
    assert result.exit_code == 1


@respx.mock
def test_archive_cli(tmp_path):
    respx.get("https://web.archive.org/cdx/search/cdx").mock(
        return_value=httpx.Response(
            200,
            json=[
                ["timestamp", "original", "statuscode", "mimetype", "digest", "length"],
                ["20200101000000", "https://example.com/", "200", "text/html", "abc", "1"],
            ],
        )
    )
    result = invoke(["--db", str(tmp_path / "t.db"), "archive", "https://example.com/", "--json"])
    assert json.loads(result.output)["captures"][0]["timestamp"] == "20200101000000"


@respx.mock
def test_domain_cli(tmp_path):
    respx.get("https://rdap.org/domain/example.com").mock(
        return_value=httpx.Response(200, json={"ldhName": "EXAMPLE.COM"})
    )
    respx.get("https://dns.google/resolve").mock(
        return_value=httpx.Response(200, json={"Answer": [{"data": "1.2.3.4"}]})
    )
    respx.get("https://crt.sh/").mock(return_value=httpx.Response(200, json=[]))
    result = invoke(["--db", str(tmp_path / "t.db"), "domain", "example.com", "--json"])
    payload = json.loads(result.output)
    assert payload["dns"]["A"] == ["1.2.3.4"]


@respx.mock
def test_ip_cli(tmp_path):
    respx.get("https://dns.google/resolve").mock(
        return_value=httpx.Response(200, json={"Answer": [{"data": "dns.google."}]})
    )
    respx.get("https://api.hackertarget.com/reverseiplookup/").mock(
        return_value=httpx.Response(200, text="a.example.com\n")
    )
    result = invoke(["--db", str(tmp_path / "t.db"), "ip", "8.8.8.8", "--json"])
    payload = json.loads(result.output)
    assert payload["ptr"] == ["dns.google."]
    assert payload["hostnames"] == ["a.example.com"]
