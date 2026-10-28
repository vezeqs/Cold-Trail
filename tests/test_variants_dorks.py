from __future__ import annotations

from coldtrail.dorks import dork_queries, dorks, reverse_image_links
from coldtrail.variants import email_variants, variants


def test_handle_variants_include_common_patterns():
    values = variants("alice")
    assert "alice" in values
    assert "alice_official" in values
    assert "4l1c3" in values
    assert len(values) == len(set(values))


def test_handle_variants_strip_at_and_reject_short():
    assert "alice" in variants("@alice")
    assert variants("ab") == []


def test_email_variants_canonicalise_gmail():
    values = email_variants("Alice.Smith+osint@googlemail.com")
    assert "alicesmith@gmail.com" in values
    assert "alicesmith@googlemail.com" in values


def test_email_variants_proton():
    values = email_variants("alice+tag@protonmail.com")
    assert "alice@proton.me" in values


def test_dork_queries_include_site_operators():
    queries = dork_queries("@alice")
    assert any("site:github.com" in query for query in queries)
    assert any(query == '"alice"' for query in queries)


def test_dorks_build_urls_for_each_engine():
    rows = dorks("alice", ["google", "bing"])
    assert rows
    assert {row["engine"] for row in rows} == {"google", "bing"}
    assert all(row["url"].startswith("https://") for row in rows)


def test_reverse_image_links():
    rows = reverse_image_links("https://example.com/a.png")
    assert {row["engine"] for row in rows} >= {"google_lens", "tineye", "yandex_images"}
