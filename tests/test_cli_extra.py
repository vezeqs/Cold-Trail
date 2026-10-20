from __future__ import annotations

import json

from typer.testing import CliRunner

from larpharvester.cli import app
from larpharvester.models import Cluster, Entity, Link, Post, Profile
from larpharvester.report import encrypt_bytes
from larpharvester.store import Store

runner = CliRunner()


def seed(tmp_path):
    db = tmp_path / "t.db"
    alice = Profile(
        source="github",
        username="alice",
        url="https://github.com/alice",
        display_name="Alice",
        bio="hi",
    )
    alice2 = Profile(
        source="gitlab", username="alice2", url="https://gitlab.com/alice2", display_name="Alice"
    )
    with Store(db) as store:
        run_id = store.start_run("pivot", "alice")
        store.save_profiles(run_id, [alice, alice2])
        store.save_posts(
            run_id,
            [
                Post(
                    source="github",
                    username="alice",
                    post_id="1",
                    url="https://github.com/alice",
                    created_at="2024-01-01T00:00:00Z",
                    text="hello world",
                )
            ],
        )
        store.save_links(run_id, [Link(a=alice, b=alice2, score=0.9, reasons=["same avatar"])])
        store.save_clusters(
            run_id,
            [Cluster(key="k1", profiles=[alice, alice2], score=0.9, reasons=["same avatar"])],
        )
        store.save_entities(
            run_id,
            [Entity(source="github", username="alice", kind="email", value="a@b.com")],
        )
        store.finish_run(run_id)
    return db


def invoke(args):
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    return result


def test_search_entities_clusters_timeline(tmp_path):
    db = seed(tmp_path)
    assert len(json.loads(invoke(["--db", str(db), "search", "hello", "--json"]).output)) == 1
    assert (
        json.loads(invoke(["--db", str(db), "entities", "--json"]).output)[0]["value"] == "a@b.com"
    )
    assert json.loads(invoke(["--db", str(db), "clusters", "--json"]).output)[0]["size"] == 2
    assert len(json.loads(invoke(["--db", str(db), "timeline", "--json"]).output)) == 1
    assert len(json.loads(invoke(["--db", str(db), "history", "--json"]).output)) == 0


def test_export_formats(tmp_path):
    db = seed(tmp_path)
    for fmt, needle in (
        ("json", '"target": "alice"'),
        ("jsonl", '"type": "profile"'),
        ("csv", "source,username"),
        ("graphml", "<graphml"),
        ("gexf", "<gexf"),
        ("dot", "graph larpharvester"),
        ("html", "Dossier: alice"),
    ):
        out = tmp_path / f"export.{fmt}"
        invoke(["--db", str(db), "export", "1", "--format", fmt, "-o", str(out)])
        assert needle in out.read_text()


def test_export_redacted(tmp_path):
    db = seed(tmp_path)
    out = tmp_path / "redacted.json"
    invoke(["--db", str(db), "export", "1", "--redact", "-o", str(out)])
    payload = json.loads(out.read_text())
    assert payload["profiles"][0]["username"].startswith("redacted-")


def test_report_writes_html(tmp_path):
    db = seed(tmp_path)
    out = tmp_path / "dossier.html"
    invoke(["--db", str(db), "report", "1", "-o", str(out)])
    assert "Dossier: alice" in out.read_text()


def test_dorks(tmp_path):
    result = invoke(["--db", str(tmp_path / "t.db"), "dorks", "alice", "--json"])
    assert json.loads(result.output)[0]["engine"]


def test_cases(tmp_path):
    db = seed(tmp_path)
    invoke(["--db", str(db), "case", "new", "op-x"])
    invoke(["--db", str(db), "case", "add", "op-x", "1"])
    listed = json.loads(invoke(["--db", str(db), "case", "list", "--json"]).output)
    assert listed[0]["name"] == "op-x"
    shown = json.loads(invoke(["--db", str(db), "case", "show", "op-x", "--json"]).output)
    assert shown["runs"][0]["id"] == 1


def test_tags_and_notes(tmp_path):
    db = tmp_path / "t.db"
    invoke(["--db", str(db), "tag", "profile", "github:alice", "suspect"])
    assert json.loads(invoke(["--db", str(db), "tags", "--json"]).output)[0]["tag"] == "suspect"
    invoke(["--db", str(db), "note", "profile", "github:alice", "check this"])
    assert (
        json.loads(invoke(["--db", str(db), "notes", "--json"]).output)[0]["note"] == "check this"
    )


def test_db_audit_prune(tmp_path):
    db = seed(tmp_path)
    info = json.loads(invoke(["--db", str(db), "db", "--json"]).output)
    assert info["stats"]["profiles"] == 2
    audit = json.loads(invoke(["--db", str(db), "audit", "--json"]).output)
    assert audit
    assert "pruned" in invoke(["--db", str(db), "prune", "--days", "30"]).output


def test_decrypt(tmp_path, monkeypatch):
    source = tmp_path / "secret.bin"
    source.write_bytes(encrypt_bytes(b"hello", "pw"))
    target = tmp_path / "out.txt"
    monkeypatch.setenv("LARPHARVESTER_PASSPHRASE", "pw")
    invoke(["--db", str(tmp_path / "t.db"), "decrypt", str(source), str(target)])
    assert target.read_bytes() == b"hello"


def test_source_test_with_fake(tmp_path, monkeypatch):
    class FakeSource:
        name = "fake"
        label = "Fake"
        kind = "username"
        group = "misc"
        homepage = ""
        supports_posts = False

        async def check(self, fetcher, target):
            from larpharvester.models import CheckResult

            return CheckResult(
                self.name,
                target,
                "found",
                profile=Profile(
                    source=self.name, username=target, url=f"https://fake.example/{target}"
                ),
            )

    monkeypatch.setattr("larpharvester.cli.osint.SOURCES", {"fake": FakeSource()})
    result = invoke(["--db", str(tmp_path / "t.db"), "source", "test", "fake", "alice", "--json"])
    assert json.loads(result.output)["status"] == "found"


def test_sources_all(tmp_path):
    result = invoke(["--db", str(tmp_path / "t.db"), "sources", "--all", "--json"])
    assert len(json.loads(result.output)) > 450


def test_export_encrypted_roundtrip(tmp_path, monkeypatch):
    db = seed(tmp_path)
    out = tmp_path / "enc.bin"
    monkeypatch.setenv("LARPHARVESTER_PASSPHRASE", "pw")
    invoke(["--db", str(db), "export", "1", "--encrypt", "-o", str(out)])
    decrypted = tmp_path / "dec.json"
    invoke(["--db", str(db), "decrypt", str(out), str(decrypted)])
    assert json.loads(decrypted.read_text())["run"]["target"] == "alice"
