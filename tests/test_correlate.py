from __future__ import annotations

from larpharvester.correlate import correlate, score_pair
from larpharvester.models import Profile


def profile(source: str, username: str, **kwargs) -> Profile:
    return Profile(
        source=source, username=username, url=f"https://{source}.example/{username}", **kwargs
    )


def test_same_avatar_links_profiles():
    a = profile("github", "alice", avatar="https://cdn.example/a.png")
    b = profile("gitlab", "alice2", avatar="https://cdn.example/a.png?size=80")
    links = correlate([a, b])
    assert len(links) == 1
    assert links[0].score >= 0.9
    assert "same avatar" in links[0].reasons


def test_identical_bio_links_profiles():
    bio = "Security researcher and occasional CTF player."
    a = profile("reddit", "alice", bio=bio)
    b = profile("mastodon", "alice", bio=bio)
    links = correlate([a, b])
    assert links and "identical bio" in links[0].reasons


def test_short_identical_bio_is_not_enough():
    a = profile("reddit", "alice", bio="hi")
    b = profile("mastodon", "alice", bio="hi")
    assert correlate([a, b]) == []


def test_same_website_links_profiles():
    a = profile("github", "alice", website="https://alice.dev")
    b = profile("devto", "alice", website="http://www.alice.dev/")
    links = correlate([a, b])
    assert links and "same website" in links[0].reasons


def test_handle_mentioned_in_other_bio_links_profiles():
    a = profile("github", "alicewonder")
    b = profile("mastodon", "alice", bio="Find me on github: alicewonder")
    links = correlate([a, b])
    assert links and any("handle in" in reason for reason in links[0].reasons)


def test_unrelated_profiles_do_not_link():
    a = profile("github", "alice", bio="Rust and embedded systems.", display_name="Alice")
    b = profile("mastodon", "bob", bio="Baker in Lisbon.", display_name="Bob")
    assert correlate([a, b]) == []


def test_same_source_and_handle_is_skipped():
    a = profile("github", "alice")
    b = profile("github", "alice")
    assert correlate([a, b]) == []


def test_score_is_capped():
    bio = "Security researcher and occasional CTF player."
    a = profile(
        "github", "alice", bio=bio, avatar="https://x.example/a.png", website="https://alice.dev"
    )
    b = profile(
        "mastodon", "alice", bio=bio, avatar="https://x.example/a.png", website="https://alice.dev"
    )
    score, _ = score_pair(a, b)
    assert score > 1.0
    assert correlate([a, b])[0].score == 1.0


def test_email_handles_do_not_self_correlate_via_mentions():
    a = profile("pgp", "user@example.com", bio="Alice <user@example.com>")
    b = profile("github-commits", "user@example.com", bio="author of 2 commits")
    links = correlate([a, b])
    assert not any("handle in" in reason for link in links for reason in link.reasons)


def test_shared_extracted_entities_correlate():
    a = profile(
        "github",
        "alice",
        extra={
            "extracted_entities": [
                {"kind": "btc", "value": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"}
            ]
        },
    )
    b = profile(
        "reddit",
        "alice_alt",
        extra={
            "extracted_entities": [
                {"kind": "btc", "value": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"}
            ]
        },
    )
    links = correlate([a, b])
    assert len(links) == 1
    assert links[0].score >= 0.9
    assert any("cryptographic identifier" in r for r in links[0].reasons)


def test_shared_ssh_key_is_near_proof():
    a = profile("github", "alice", extra={"ssh_keys": [{"fingerprint": "SHA256:abc123"}]})
    b = profile("gitlab", "alice_alt", extra={"ssh_keys": [{"fingerprint": "SHA256:abc123"}]})
    score, reasons = score_pair(a, b)
    assert score >= 0.95
    assert any("ssh_key" in reason for reason in reasons)


def test_shared_did_and_gpg_key():
    a = profile("bluesky", "alice", extra={"did": "did:plc:abc"})
    b = profile("github", "alice_alt", extra={"did": "did:plc:abc"})
    assert score_pair(a, b)[0] >= 0.95

    c = profile("github", "bob", extra={"gpg_keys": [{"key_id": "DEADBEEF12345678"}]})
    d = profile("codeberg", "bob_alt", extra={"gpg_keys": [{"key_id": "DEADBEEF12345678"}]})
    assert score_pair(c, d)[0] >= 0.95


def test_avatar_exif_camera_serial_signal():
    a = profile("github", "alice", extra={"avatar_meta": {"camera_serial": "SN-9999"}})
    b = profile("reddit", "alice_alt", extra={"avatar_meta": {"camera_serial": "SN-9999"}})
    score, reasons = score_pair(a, b)
    assert score >= 0.4
    assert any("camera serial" in reason for reason in reasons)


def test_calibrate_probability_is_monotonic_and_bounded():
    from larpharvester.correlate import calibrate_probability

    assert calibrate_probability(0.5) == 0.5
    assert calibrate_probability(0.0) < 0.5
    assert calibrate_probability(1.0) > calibrate_probability(0.7)
    assert 0.0 <= calibrate_probability(5.0) <= 0.99
