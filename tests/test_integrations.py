"""External tool integrations and import adapter tests (no real binaries)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

import larpharvester.integrations as integrations_mod
from larpharvester.cli import app
from larpharvester.config import Settings
from larpharvester.integrations import (
    TOOLS,
    ToolError,
    ToolUnavailable,
    detect_format,
    ingest_file,
    list_tools,
    parse_generic_json,
    parse_maltego_csv,
    parse_spiderfoot_json,
    parse_theharvester_json,
    persist_ingest,
    persist_tool_result,
    run_tool,
)
from larpharvester.store import Store

runner = CliRunner()


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(db_path=tmp_path / "t.db", requests_per_second=0, jitter=0)


# -- parsers ----------------------------------------------------------------


def test_sherlock_parser():
    stdout = "[+] GitHub: https://github.com/simonw\n[+] Reddit: https://reddit.com/user/simonw\n"
    parsed = TOOLS["sherlock"].parse(stdout, "simonw", Path("."))
    assert len(parsed.profiles) == 2
    assert parsed.profiles[0].source == "sherlock:github"
    assert parsed.profiles[0].url == "https://github.com/simonw"
    assert "2 profile" in parsed.summary


def test_exiftool_parser(tmp_path):
    record = [
        {
            "File:FileName": "photo.jpg",
            "EXIF:Make": "Canon",
            "EXIF:Model": "EOS",
            "EXIF:GPSPosition": "38.7 -9.1",
            "XMP:Creator": "alice@example.com",
        }
    ]
    parsed = TOOLS["exiftool"].parse(json.dumps(record), "photo.jpg", tmp_path)
    assert parsed.profiles[0].username == "photo.jpg"
    assert parsed.profiles[0].extra["metadata"]["EXIF:Make"] == "Canon"
    kinds = {(e.kind, e.value) for e in parsed.entities}
    assert ("email", "alice@example.com") in kinds
    assert any(kind == "coords" for kind, _ in kinds)


def test_ytdlp_parser():
    data = {
        "id": "abc",
        "title": "A video",
        "description": "contact me at creator@example.com",
        "uploader": "Creator",
        "uploader_id": "@creator",
        "uploader_url": "https://youtube.com/@creator",
        "webpage_url": "https://youtube.com/watch?v=abc",
        "timestamp": 1700000000,
        "view_count": 10,
        "like_count": 2,
    }
    parsed = TOOLS["yt-dlp"].parse(json.dumps(data), "https://youtube.com/watch?v=abc", Path("."))
    assert parsed.profiles[0].display_name == "Creator"
    assert parsed.posts[0].post_id == "abc"
    assert parsed.posts[0].metrics["views"] == 10
    assert any(e.kind == "email" for e in parsed.entities)


def test_whois_parser():
    text = (
        "Registrar: Example Registrar\n"
        "Creation Date: 1995-08-14T04:00:00Z\n"
        "Registrant Organization: Example Org\n"
        "Name Server: A.IANA-SERVERS.NET\n"
        "abuse@example.com\n"
    )
    parsed = TOOLS["whois"].parse(text, "example.com", Path("."))
    assert parsed.profiles[0].extra["fields"]["Registrar"] == "Example Registrar"
    assert parsed.entities[0].value == "abuse@example.com"


def test_dig_parser():
    stdout = "93.184.216.34\n2606:2800:220:1:248:1893:25c8:1946\n"
    parsed = TOOLS["dig"].parse(stdout, "example.com", Path("."))
    kinds = [(e.kind, e.value) for e in parsed.entities]
    assert ("ipv4", "93.184.216.34") in kinds


def test_nmap_parser():
    xml = """<?xml version="1.0"?><nmaprun><host>
      <address addr="203.0.113.9" addrtype="ipv4"/>
      <hostnames><hostname name="host.example"/></hostnames>
      <ports><port protocol="tcp" portid="22"><state state="open"/>
      <service name="ssh" product="OpenSSH" version="9"/></port></ports>
    </host></nmaprun>"""
    parsed = TOOLS["nmap"].parse(xml, "203.0.113.9", Path("."))
    assert parsed.profiles[0].extra["ports"][0]["port"] == 22
    assert parsed.profiles[0].extra["ports"][0]["service"] == "ssh"


def test_holehe_parser():
    parsed = TOOLS["holehe"].parse("[+] github.com\n[+] twitter.com\n", "a@b.com", Path("."))
    assert len(parsed.profiles) == 2
    assert parsed.entities[0].kind == "email"


# -- importers --------------------------------------------------------------


def test_maltego_import():
    text = (
        "SourceType,SourceValue,Relation,TargetType,TargetValue,Weight\n"
        "maltego.Alias,github:alice,same bio,maltego.Alias,gitlab:alice,0.9\n"
        "maltego.Alias,github:alice,mentions:email,maltego.email,a@x.com,0.8\n"
    )
    parsed = parse_maltego_csv(text)
    assert {p.source for p in parsed.profiles} == {"github", "gitlab"}
    assert len(parsed.links) == 1
    assert parsed.entities[0].kind == "email"


def test_spiderfoot_import():
    text = json.dumps(
        [
            {"type": "EMAILADDR", "data": "a@x.com", "module": "sfp_whois"},
            {"type": "INTERNET_NAME", "data": "mail.x.com", "module": "sfp_dns"},
            {"type": "USERNAME", "data": "alice", "module": "sfp_accounts"},
        ]
    )
    parsed = parse_spiderfoot_json(text)
    assert len(parsed.profiles) == 1
    assert {e.kind for e in parsed.entities} == {"email", "domain"}


def test_theharvester_import():
    text = json.dumps({"emails": ["a@x.com"], "hosts": ["vpn.x.com"], "ips": ["203.0.113.7"]})
    parsed = parse_theharvester_json(text)
    assert {e.kind for e in parsed.entities} == {"email", "domain", "ipv4"}


def test_generic_json_import():
    text = json.dumps(
        [
            {"source": "github", "username": "alice", "url": "https://github.com/alice"},
            {"kind": "email", "value": "a@x.com", "source": "notes"},
        ]
    )
    parsed = parse_generic_json(text)
    assert parsed.profiles[0].username == "alice"
    assert parsed.entities[0].kind == "email"


def test_detect_format():
    maltego_header = "SourceType,SourceValue,Relation,TargetType,TargetValue,Weight\n"
    assert detect_format(maltego_header) == "maltego"
    assert detect_format(json.dumps([{"type": "EMAILADDR", "data": "a@x.com"}])) == "spiderfoot"
    assert detect_format(json.dumps({"emails": ["a@x.com"]})) == "theharvester"
    assert detect_format(json.dumps([{"source": "github", "username": "a"}])) == "json"


def test_ingest_file_roundtrip(tmp_path):
    path = tmp_path / "spider.json"
    path.write_text(json.dumps([{"type": "EMAILADDR", "data": "a@x.com", "module": "m"}]))
    fmt, parsed, raw = ingest_file(path)
    assert fmt == "spiderfoot"
    assert parsed.entities[0].kind == "email"
    assert raw


# -- runner -----------------------------------------------------------------


def test_run_tool_unavailable(monkeypatch):
    monkeypatch.setattr(integrations_mod.shutil, "which", lambda binary: None)
    with pytest.raises(ToolUnavailable) as exc:
        run_tool("sherlock", "alice")
    assert "pipx install" in str(exc.value)


def test_run_tool_builds_safe_argv_and_parses(monkeypatch):
    captured: dict = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(command, 0, "[+] GitHub: https://github.com/alice\n", "")

    monkeypatch.setattr(integrations_mod.shutil, "which", lambda binary: f"/bin/{binary}")
    monkeypatch.setattr(integrations_mod.subprocess, "run", fake_run)
    result = run_tool("sherlock", "alice", extra_args=["--site", "GitHub"])
    assert result.parsed.profiles[0].url == "https://github.com/alice"
    assert captured["command"][0] == "sherlock"
    assert "alice" in captured["command"]
    assert not captured["kwargs"].get("shell")
    assert captured["kwargs"]["capture_output"] is True


def test_run_tool_timeout(monkeypatch):
    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, 1)

    monkeypatch.setattr(integrations_mod.shutil, "which", lambda binary: f"/bin/{binary}")
    monkeypatch.setattr(integrations_mod.subprocess, "run", fake_run)
    with pytest.raises(ToolError, match="timed out"):
        run_tool("whois", "example.com", timeout=1)


def test_run_tool_file_validation(monkeypatch):
    monkeypatch.setattr(integrations_mod.shutil, "which", lambda binary: f"/bin/{binary}")
    with pytest.raises(ToolError, match="not a file"):
        run_tool("exiftool", "/no/such/file.jpg")


# -- persistence ------------------------------------------------------------


def test_persist_tool_result_saves_run_and_evidence(settings, monkeypatch):
    monkeypatch.setattr(integrations_mod.shutil, "which", lambda binary: f"/bin/{binary}")
    monkeypatch.setattr(
        integrations_mod.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 0, "[+] GitHub: https://github.com/alice\n", ""
        ),
    )
    result = run_tool("sherlock", "alice")
    with Store(settings.db_path) as store:
        run_id = persist_tool_result(store, result)
        profiles = store.profiles(run_id=run_id)
        attachments = store.attachments(run_id=run_id)
    assert profiles[0]["username"] == "alice"
    assert attachments and attachments[0]["filename"].startswith("sherlock-alice")


def test_persist_ingest(settings, tmp_path):
    path = tmp_path / "spider.json"
    path.write_text(json.dumps([{"type": "EMAILADDR", "data": "a@x.com", "module": "m"}]))
    fmt, parsed, raw = ingest_file(path)
    with Store(settings.db_path) as store:
        run_id = persist_ingest(store, str(path), fmt, parsed, raw)
        entities = store.entities(run_id=run_id)
        attachments = store.attachments(run_id=run_id)
    assert entities[0]["value"] == "a@x.com"
    assert attachments[0]["filename"] == "spider.json"


# -- CLI --------------------------------------------------------------------


def test_cli_integrations_lists_tools():
    result = runner.invoke(app, ["integrations", "--json"])
    assert result.exit_code == 0, result.output
    rows = json.loads(result.output)
    names = {row["name"] for row in rows}
    assert {"sherlock", "exiftool", "yt-dlp", "whois", "nmap", "holehe"} <= names


def test_cli_run_unavailable_exits_2(settings, monkeypatch):
    monkeypatch.setattr(integrations_mod.shutil, "which", lambda binary: None)
    result = runner.invoke(app, ["--db", str(settings.db_path), "run", "holehe", "a@x.com"])
    assert result.exit_code == 2
    assert "not installed" in result.output


def test_cli_run_saves_with_fake_binary(settings, monkeypatch):
    monkeypatch.setattr(integrations_mod.shutil, "which", lambda binary: f"/bin/{binary}")
    monkeypatch.setattr(
        integrations_mod.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 0, "[+] GitHub: https://github.com/alice\n", ""
        ),
    )
    result = runner.invoke(
        app, ["--db", str(settings.db_path), "run", "sherlock", "alice", "--json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["run_id"] == 1
    assert payload["parsed"]["profiles"][0]["url"] == "https://github.com/alice"


def test_cli_ingest_detects_and_saves(settings, tmp_path):
    path = tmp_path / "spider.json"
    path.write_text(json.dumps([{"type": "EMAILADDR", "data": "a@x.com", "module": "m"}]))
    result = runner.invoke(app, ["--db", str(settings.db_path), "ingest", str(path), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["format"] == "spiderfoot"
    assert payload["run_id"] == 1


def test_cli_ingest_unknown_format(settings, tmp_path):
    path = tmp_path / "data.txt"
    path.write_text("nonsense")
    result = runner.invoke(
        app, ["--db", str(settings.db_path), "ingest", str(path), "--format", "nope"]
    )
    assert result.exit_code == 1
    assert "unknown import format" in result.output


def test_list_tools_reports_installed_flag(monkeypatch):
    monkeypatch.setattr(
        integrations_mod.shutil, "which", lambda binary: "/bin/x" if binary == "nmap" else None
    )
    rows = {row["name"]: row for row in list_tools()}
    assert rows["nmap"]["installed"] is True
    assert rows["sherlock"]["installed"] is False


# -- hardening --------------------------------------------------------------


def test_validate_target_rejects_option_like_values():
    from larpharvester.integrations import validate_target

    for bad in ("--timeout=999", "-oN", "", "a\nb", "a\x00b"):
        with pytest.raises(ToolError):
            validate_target(bad)
    assert validate_target("  alice  ") == "alice"


def test_run_tool_never_executes_option_injection(monkeypatch):
    calls: list[object] = []
    monkeypatch.setattr(integrations_mod.shutil, "which", lambda binary: "/bin/true")
    monkeypatch.setattr(integrations_mod.subprocess, "run", lambda *a, **k: calls.append(a))
    with pytest.raises(ToolError):
        run_tool("sherlock", "--script=/tmp/evil.nse")
    assert calls == []


# -- new username/social wrappers ------------------------------------------


def test_maigret_parser_uses_matches_and_skips_available_sites():
    stdout = json.dumps(
        {
            "query_username": "alice",
            "matches": [
                {
                    "site": "GitHub",
                    "url_user": "https://github.com/alice",
                    "status": "FOUND",
                },
                {
                    "site": "Reddit",
                    "url_user": "https://reddit.com/user/alice",
                    "status": "NOT_FOUND",
                },
            ],
        }
    )
    parsed = TOOLS["maigret"].parse(stdout, "alice", Path("."))
    assert [profile.source for profile in parsed.profiles] == ["maigret:github"]
    assert parsed.profiles[0].url == "https://github.com/alice"


def test_maigret_parser_reads_json_report_file(tmp_path):
    (tmp_path / "alice.json").write_text(
        json.dumps(
            {
                "matches": [
                    {"site": "GitHub", "url_user": "https://github.com/alice", "status": "FOUND"}
                ]
            }
        )
    )
    parsed = TOOLS["maigret"].parse("", "alice", tmp_path)
    assert parsed.profiles[0].source == "maigret:github"


def test_naminter_parser_falls_back_to_print_found_lines():
    stdout = "[+] GitHub: https://github.com/alice\n[-] Reddit: not found\n"
    parsed = TOOLS["naminter"].parse(stdout, "alice", Path("."))
    assert len(parsed.profiles) == 1
    assert parsed.profiles[0].source == "naminter:github"


def test_naminter_parser_reads_json_export(tmp_path):
    (tmp_path / "naminter.json").write_text(
        json.dumps(
            [
                {"site": "GitHub", "url": "https://github.com/alice", "status": "exists"},
                {"site": "Reddit", "url": "https://reddit.com/user/alice", "status": "missing"},
            ]
        )
    )
    parsed = TOOLS["naminter"].parse("", "alice", tmp_path)
    assert [profile.source for profile in parsed.profiles] == ["naminter:github"]


def test_social_analyzer_parser_detected_entries():
    stdout = json.dumps(
        {
            "detected": [
                {"site": "GitHub", "url": "https://github.com/alice"},
                {"site": "Reddit", "url": "https://reddit.com/user/alice"},
            ],
            "uncertain": [{"site": "Nope", "url": "https://nope.example/alice"}],
        }
    )
    parsed = TOOLS["social-analyzer"].parse(stdout, "alice", Path("."))
    assert {profile.source for profile in parsed.profiles} == {
        "social-analyzer:github",
        "social-analyzer:reddit",
    }


def test_blackbird_parser_json_results():
    stdout = json.dumps(
        {"results": [{"site": "GitHub", "url": "https://github.com/alice", "found": True}]}
    )
    parsed = TOOLS["blackbird"].parse(stdout, "alice", Path("."))
    assert parsed.profiles[0].source == "blackbird:github"


def test_instaloader_parser_reads_profile_and_posts(tmp_path):
    folder = tmp_path / "instagram"
    folder.mkdir()
    (folder / "123.json").write_text(
        json.dumps(
            {
                "node": {
                    "id": "123",
                    "username": "alice",
                    "full_name": "Alice A",
                    "biography": "contact alice@example.com",
                    "external_url": "https://alice.example",
                    "profile_pic_url": "https://x/a.jpg",
                    "edge_followed_by": {"count": 42},
                    "is_verified": True,
                }
            }
        )
    )
    (folder / "post.json").write_text(
        json.dumps(
            {
                "shortcode": "abc123",
                "taken_at_timestamp": 1700000000,
                "node": {"username": "alice"},
                "edge_media_to_caption": {"edges": [{"node": {"text": "hello"}}]},
            }
        )
    )
    parsed = TOOLS["instaloader"].parse("", "alice", tmp_path)
    assert parsed.profiles[0].username == "alice"
    assert parsed.profiles[0].followers == 42
    assert any(
        entity.kind == "email" and entity.value == "alice@example.com" for entity in parsed.entities
    )
    assert parsed.posts[0].post_id == "abc123"


def test_twscrape_parser_profile_json():
    stdout = json.dumps(
        {
            "id": "42",
            "username": "alice",
            "displayname": "Alice",
            "description": "security@example.com",
            "followersCount": 7,
        }
    )
    parsed = TOOLS["twscrape"].parse(stdout, "alice", Path("."))
    assert parsed.profiles[0].source == "x"
    assert parsed.profiles[0].followers == 7
    assert any(entity.kind == "email" for entity in parsed.entities)
