from __future__ import annotations

from coldtrail.analysis import (
    detect_lang,
    entities_from_posts,
    extract_entities,
    infer_timezone,
    marker_overlap,
    style_similarity,
    stylometry,
)
from coldtrail.models import Post


def test_extracts_common_entity_kinds():
    text = (
        "mail me at Alice@Example.com or +351 912 345 678; "
        "btc bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq "
        "eth 0x52908400098527886E0F7030069857D2E4169EE7 "
        "tg @alice_wonder ip 8.8.8.8 coords 38.7223,-9.1393"
    )
    entities = extract_entities(text, "mastodon", "alice")
    kinds = {entity.kind for entity in entities}
    assert {"email", "btc", "eth", "telegram", "ipv4", "coords"} <= kinds
    email = next(entity for entity in entities if entity.kind == "email")
    assert email.value == "alice@example.com"
    assert email.source == "mastodon"
    assert email.username == "alice"


def test_entities_dedupe_within_text():
    entities = extract_entities("a@b.com and a@b.com", "x", "u")
    assert len([e for e in entities if e.kind == "email"]) == 1


def test_phone_requires_plausible_length():
    assert not [e for e in extract_entities("call 12 34", "x", "u") if e.kind == "phone"]
    assert [e for e in extract_entities("call +351 912 345 678", "x", "u") if e.kind == "phone"]


def test_generic_domains_are_skipped():
    entities = extract_entities("visit github.com and alice.dev", "x", "u")
    domains = {e.value for e in entities if e.kind == "domain"}
    assert "alice.dev" in domains
    assert "github.com" not in domains


def test_entities_from_posts():
    posts = [Post(source="reddit", username="alice", post_id="1", url="u", text="hi a@b.com")]
    assert [e.value for e in entities_from_posts(posts)] == ["a@b.com"]


def test_detect_lang():
    assert detect_lang("the quick brown fox and the lazy dog with you") == "en"
    assert detect_lang("el perro y la casa que con para una") == "es"
    assert detect_lang("hi") is None


def test_infer_timezone_from_posting_hours():
    posts = [
        Post(
            source="x",
            username="u",
            post_id=str(i),
            url="u",
            created_at=f"2024-01-01T20:{i:02d}:00Z",
        )
        for i in range(10)
    ]
    assert infer_timezone(posts) == "+00:00"


def test_timezone_needs_enough_posts():
    posts = [
        Post(source="x", username="u", post_id="1", url="u", created_at="2024-01-01T20:00:00Z")
    ]
    assert infer_timezone(posts) is None


def test_stylometry_similarity():
    a = "I think this is really just the best and I always say so because it is"
    b = "I think this is really just the best and I always say so because it is"
    c = "completely different words without any of the function words at all"
    assert style_similarity(a, b) > 0.99
    assert style_similarity(a, c) < 0.5
    assert stylometry([Post(source="x", username="u", post_id="1", url="u", text=a)])


def test_marker_overlap():
    a = "hello #osint #ctf 🔥"
    b = "more #osint 🔥"
    assert marker_overlap(a, b) > 0.5
    assert marker_overlap(a, "no markers here") == 0.0
