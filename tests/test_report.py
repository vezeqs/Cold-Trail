from __future__ import annotations

import json

import pytest

from coldtrail.report import (
    decrypt_bytes,
    encrypt_bytes,
    redact_payload,
    to_csv,
    to_dot,
    to_gexf,
    to_graphml,
    to_html,
    to_json,
    to_jsonl,
)


@pytest.fixture
def payload():
    return {
        "run": {
            "id": 1,
            "kind": "pivot",
            "target": "alice",
            "started_at": "2024-01-01T00:00:00+00:00",
        },
        "profiles": [
            {
                "source": "github",
                "username": "alice",
                "display_name": "Alice",
                "bio": "<script>alert(1)</script>",
                "url": "https://github.com/alice",
                "followers": 5,
                "extra": {},
            },
            {
                "source": "gitlab",
                "username": "alice2",
                "display_name": "Alice",
                "bio": "hi",
                "url": "https://gitlab.com/alice2",
                "extra": {},
            },
        ],
        "posts": [
            {
                "source": "github",
                "username": "alice",
                "post_id": "1",
                "url": "https://github.com/alice",
                "created_at": "2024-01-01T00:00:00Z",
                "text": "hello",
                "metrics": {},
            }
        ],
        "links": [
            {
                "source_a": "github",
                "username_a": "alice",
                "source_b": "gitlab",
                "username_b": "alice2",
                "score": 0.9,
                "reasons": ["same avatar"],
            }
        ],
        "clusters": [
            {
                "cluster_key": "k1",
                "size": 2,
                "score": 0.9,
                "members": [
                    {"source": "github", "username": "alice"},
                    {"source": "gitlab", "username": "alice2"},
                ],
                "reasons": ["same avatar"],
            }
        ],
        "entities": [
            {"kind": "email", "value": "a@b.com", "source": "github", "username": "alice"}
        ],
        "history": [
            {
                "source": "github",
                "username": "alice",
                "field": "bio",
                "old_value": "old",
                "new_value": "new",
                "observed_at": "2024-01-02T00:00:00+00:00",
            }
        ],
        "checks": [
            {"source": "github", "target": "alice", "status": "found", "detail": None},
            {"source": "reddit", "target": "alice", "status": "blocked", "detail": "403"},
        ],
    }


def test_json_roundtrip(payload):
    assert json.loads(to_json(payload))["run"]["target"] == "alice"


def test_jsonl(payload):
    lines = [json.loads(line) for line in to_jsonl(payload).splitlines()]
    assert {line["type"] for line in lines} == {
        "run",
        "check",
        "profile",
        "post",
        "entity",
        "link",
        "cluster",
        "history",
    }
    assert next(line for line in lines if line["type"] == "run")["target"] == "alice"


def test_csv(payload):
    text = to_csv(payload, "profiles")
    assert text.startswith("source,username")
    assert "alice2" in text


def test_graphml(payload):
    text = to_graphml(payload)
    assert 'node id="github:alice"' in text
    assert 'edge source="github:alice" target="gitlab:alice2"' in text


def test_gexf(payload):
    text = to_gexf(payload)
    assert '<node id="github:alice"' in text
    assert "<edge " in text


def test_dot(payload):
    text = to_dot(payload)
    assert '"github:alice" -- "gitlab:alice2"' in text


def test_html_escapes_and_contains_sections(payload):
    text = to_html(payload)
    assert "Dossier: alice" in text
    assert "&lt;script&gt;" in text
    assert "<script>alert(1)</script>" not in text
    assert "Inferred identities" not in text  # sections are titled Clusters
    assert "Clusters" in text
    assert "a@b.com" in text


def test_redaction(payload):
    redacted = redact_payload(payload)
    assert redacted["profiles"][0]["username"].startswith("redacted-")
    assert redacted["profiles"][0]["bio"] is None
    assert redacted["entities"][0]["value"].startswith("redacted-")
    assert redacted["links"][0]["username_a"].startswith("redacted-")


def test_encrypt_roundtrip():
    blob = encrypt_bytes(b"secret", "passphrase")
    assert blob.startswith(b"LPH1")
    assert decrypt_bytes(blob, "passphrase") == b"secret"


def test_decrypt_wrong_passphrase():
    blob = encrypt_bytes(b"secret", "passphrase")
    with pytest.raises(ValueError):
        decrypt_bytes(blob, "wrong")


def test_decrypt_rejects_plaintext():
    with pytest.raises(ValueError):
        decrypt_bytes(b"not encrypted", "passphrase")
