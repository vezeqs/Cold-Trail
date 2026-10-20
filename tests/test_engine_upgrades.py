"""Tests for the 0.4.0 engine upgrades: domain deep recon, entity extraction,
handle similarity, re-clustering, and the new export formats."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from larpharvester.analysis import extract_entities
from larpharvester.config import Settings
from larpharvester.correlate import jaro_winkler, recluster_rows, score_pair
from larpharvester.domain import (
    extract_spf,
    favicon_shodan_hash,
    guess_mx_provider,
    lookup_domain,
    mmh3_32,
)
from larpharvester.http import Fetcher
from larpharvester.models import Profile
from larpharvester.report import to_maltego_csv, to_markdown, to_stix


@pytest.fixture
def settings(tmp_path):
    return Settings(db_path=tmp_path / "t.db", requests_per_second=0, jitter=0)


# -- domain -----------------------------------------------------------------


def test_guess_mx_provider():
    assert guess_mx_provider(["10 aspmx.l.google.com."]) == "Google Workspace"
    assert guess_mx_provider(["10 mx1.mail.icloud.com."]) == "Apple iCloud"
    assert guess_mx_provider(["10 mail.example.org."]) is None


def test_extract_spf():
    records = ['"v=spf1 include:_spf.google.com ~all"', '"other"']
    assert extract_spf(records) == "v=spf1 include:_spf.google.com ~all"
    assert extract_spf([]) is None


def test_mmh3_known_vector():
    # MurmurHash3 x86_32 of b"hello" with seed 0
    assert mmh3_32(b"hello") == 613153351


def test_favicon_shodan_hash_returns_int():
    value = favicon_shodan_hash(b"\x00\x01\x02favicon")
    assert isinstance(value, int)
    assert -(2**31) <= value < 2**31


@respx.mock
async def test_lookup_domain_deep(settings):
    domain = "example.com"

    def dns_response(*answers):
        return httpx.Response(200, json={"Answer": list(answers)})

    respx.get("https://dns.google/resolve", params={"name": domain, "type": "A"}).mock(
        return_value=dns_response({"data": "93.184.216.34"})
    )
    respx.get("https://dns.google/resolve", params={"name": domain, "type": "MX"}).mock(
        return_value=dns_response({"data": "10 aspmx.l.google.com."})
    )
    respx.get("https://dns.google/resolve", params={"name": domain, "type": "TXT"}).mock(
        return_value=dns_response({"data": '"v=spf1 include:_spf.google.com ~all"'})
    )
    for record_type in ("AAAA", "NS", "CNAME"):
        respx.get("https://dns.google/resolve", params={"name": domain, "type": record_type}).mock(
            return_value=dns_response()
        )
    respx.get(
        "https://dns.google/resolve", params={"name": f"_dmarc.{domain}", "type": "TXT"}
    ).mock(return_value=dns_response({"data": '"v=DMARC1; p=reject"'}))
    respx.get("https://rdap.org/domain/example.com").mock(return_value=httpx.Response(404))
    respx.get("https://crt.sh/", params={"q": "%.example.com", "output": "json"}).mock(
        return_value=httpx.Response(200, json=[])
    )
    respx.get("https://example.com/.well-known/security.txt").mock(
        return_value=httpx.Response(200, text="Contact: mailto:sec@example.com")
    )
    respx.get("https://example.com/favicon.ico").mock(
        return_value=httpx.Response(200, content=b"icon-bytes")
    )
    async with Fetcher(settings) as fetcher:
        payload = await lookup_domain(fetcher, domain, deep=True)
    assert payload["mx_provider"] == "Google Workspace"
    assert payload["spf"].startswith("v=spf1")
    assert payload["dmarc"] == "v=DMARC1; p=reject"
    assert payload["favicon_mmh3"] is not None
    assert payload["security_txt"].startswith("Contact:")


# -- entity extraction ------------------------------------------------------


def test_extract_new_entity_kinds():
    xmr = "4" + "A" * 94
    onion = "a" * 56 + ".onion"
    pgp = "1234 5678 9ABC DEF0 1234 5678 9ABC DEF0 1234 5678"
    ssh = "SHA256:" + "a" * 43 + "="
    text = f"wallet {xmr} onion {onion} pgp {pgp} ssh {ssh} matrix @alice:matrix.org"
    kinds = {e.kind for e in extract_entities(text, "github", "alice")}
    assert {"xmr", "onion", "pgp_fingerprint", "ssh_key", "matrix"} <= kinds


def test_extract_onion_normalizes_case():
    text = "visit " + "A" * 56 + ".onion"
    onions = [e.value for e in extract_entities(text, "s", "u") if e.kind == "onion"]
    assert onions and onions[0].islower()


# -- correlation ------------------------------------------------------------


def test_jaro_winkler_identical_and_distant():
    assert jaro_winkler("alice", "alice") == 1.0
    assert jaro_winkler("alice", "bob") < 0.6
    assert jaro_winkler("alice_sec", "alicesec") > 0.95


def test_handle_similarity_signal_contributes():
    a = Profile(source="github", username="alice_sec", url="https://x/a")
    b = Profile(source="gitlab", username="alicesec", url="https://y/b")
    score, reasons = score_pair(a, b)
    assert score > 0
    assert any("handle" in reason for reason in reasons)


def test_recluster_rows_dedupes_and_links():
    rows = [
        {
            "source": "github",
            "username": "alice",
            "url": "https://github.com/alice",
            "display_name": "Alice",
            "bio": "same distinctive bio about rust security research",
            "avatar": None,
            "avatar_hash": None,
            "website": None,
            "created_at": None,
            "followers": 1,
            "lang": "en",
            "timezone": "+00:00",
            "extra": {},
        },
        {
            "source": "github",
            "username": "alice",
            "url": "https://github.com/alice",
            "display_name": "Alice",
            "bio": "same distinctive bio about rust security research",
            "avatar": None,
            "avatar_hash": None,
            "website": None,
            "created_at": None,
            "followers": 1,
            "lang": "en",
            "timezone": "+00:00",
            "extra": {},
        },
        {
            "source": "gitlab",
            "username": "alice",
            "url": "https://gitlab.com/alice",
            "display_name": "Alice",
            "bio": "same distinctive bio about rust security research",
            "avatar": None,
            "avatar_hash": None,
            "website": None,
            "created_at": None,
            "followers": 1,
            "lang": "en",
            "timezone": "+00:00",
            "extra": {},
        },
    ]
    links, clusters = recluster_rows(rows)
    assert len(links) == 1
    assert len(clusters) == 1
    assert len(clusters[0].profiles) == 2  # duplicate github row deduped


# -- exports ----------------------------------------------------------------

PAYLOAD = {
    "run": {"id": 1, "kind": "pivot", "target": "alice", "started_at": "2024-01-01T00:00:00Z"},
    "checks": [{"source": "github", "target": "alice", "status": "found", "detail": ""}],
    "profiles": [
        {
            "source": "github",
            "username": "alice",
            "url": "https://github.com/alice",
            "display_name": "Alice",
            "bio": "hi",
            "followers": 5,
            "avatar_hash": "abcd",
        },
        {
            "source": "gitlab",
            "username": "alice",
            "url": "https://gitlab.com/alice",
            "display_name": "Alice",
            "bio": "hi",
            "followers": 2,
            "avatar_hash": "abcd",
        },
    ],
    "posts": [
        {
            "source": "github",
            "username": "alice",
            "created_at": "2024-01-01T00:00:00Z",
            "text": "hello",
            "url": "https://x/1",
        }
    ],
    "links": [
        {
            "source_a": "github",
            "username_a": "alice",
            "source_b": "gitlab",
            "username_b": "alice",
            "score": 0.7,
            "reasons": ["same bio"],
        }
    ],
    "clusters": [
        {
            "cluster_key": "abc",
            "score": 0.7,
            "size": 2,
            "members": [
                {"source": "github", "username": "alice"},
                {"source": "gitlab", "username": "alice"},
            ],
            "reasons": ["same bio"],
        }
    ],
    "entities": [
        {
            "kind": "email",
            "value": "a@x.com",
            "source": "github",
            "username": "alice",
            "context": "",
        }
    ],
    "edges": [{"platform": "github", "actor": "alice", "target": "bob", "direction": "follows"}],
    "history": [],
}


def test_to_markdown_contains_sections():
    md = to_markdown(PAYLOAD)
    assert "# OSINT Dossier: `alice`" in md
    assert "## Inferred Identity Clusters" in md
    assert "## Profiles" in md
    assert "## Correlated Pairs" in md
    assert "## Extracted Entities" in md
    assert "a@x.com" in md


def test_to_stix_is_valid_bundle():
    bundle = json.loads(to_stix(PAYLOAD))
    assert bundle["type"] == "bundle"
    types = {obj["type"] for obj in bundle["objects"]}
    assert "user-account" in types
    assert "identity" in types
    assert "relationship" in types
    accounts = [o for o in bundle["objects"] if o["type"] == "user-account"]
    assert accounts[0]["account_login"] == "alice"
    assert accounts[0]["spec_version"] == "2.1"
    rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
    assert any(r["relationship_type"] == "attributed-to" for r in rels)
    assert any(r["relationship_type"] == "related-to" for r in rels)


def test_to_maltego_csv_rows():
    csv_text = to_maltego_csv(PAYLOAD)
    lines = csv_text.strip().splitlines()
    assert lines[0].startswith("SourceType,SourceValue,Relation")
    assert any("github:alice" in line for line in lines)
    assert any("mentions:email" in line for line in lines)
