from __future__ import annotations

from coldtrail.correlate import build_clusters, correlate, score_pair
from coldtrail.models import Link, Profile


def profile(source: str, username: str, **kwargs) -> Profile:
    return Profile(
        source=source, username=username, url=f"https://{source}.example/{username}", **kwargs
    )


def test_shared_default_avatar_is_not_evidence():
    default = "https://mastodon.social/avatars/original/missing.png"
    a = profile("mastodon", "alice", avatar=default)
    b = profile("mastodon", "bob", avatar=default)
    assert correlate([a, b]) == []


def test_default_avatar_hash_is_also_ignored():
    default = "https://mastodon.social/avatars/original/missing.png"
    a = profile("mastodon", "alice", avatar=default, avatar_hash="f0f0f0f0f0f0f0f0")
    b = profile("mastodon", "bob", avatar=default, avatar_hash="f0f0f0f0f0f0f0f0")
    assert correlate([a, b]) == []


def test_perceptual_avatar_hash_links_profiles():
    a = profile("github", "alice", avatar="https://a.example/1.png", avatar_hash="f0f0f0f0f0f0f0f0")
    b = profile(
        "gitlab", "alice2", avatar="https://b.example/2.jpg", avatar_hash="f0f0f0f0f0f0f0f1"
    )
    links = correlate([a, b])
    assert links and "perceptual avatar match" in links[0].reasons[0]


def test_generic_website_root_is_not_evidence():
    a = profile("github", "alice", website="https://twitter.com")
    b = profile("gitlab", "bob", website="https://twitter.com/")
    assert correlate([a, b]) == []


def test_personal_domain_root_is_evidence():
    a = profile("github", "alice", website="https://alice.dev")
    b = profile("devto", "alice", website="http://www.alice.dev/")
    assert correlate([a, b]) and "same website" in correlate([a, b])[0].reasons


def test_stopword_only_bio_is_not_evidence():
    bio = "the and of to in for with"
    a = profile("reddit", "alice", bio=bio)
    b = profile("mastodon", "bob", bio=bio)
    assert correlate([a, b]) == []


def test_creation_proximity_is_a_weak_signal():
    a = profile("github", "alice", created_at="2020-01-01T00:00:00Z")
    b = profile("gitlab", "alice", created_at="2020-01-03T00:00:00Z")
    score, reasons = score_pair(a, b)
    assert score == 0.1
    assert any("created within" in reason for reason in reasons)


def test_timezone_mismatch_penalises():
    a = profile("github", "alice", timezone="+09:00")
    b = profile("gitlab", "alice", timezone="-05:00")
    score, _ = score_pair(a, b)
    assert score == 0.0


def test_clusters_are_transitive():
    a = profile("github", "alice", avatar="https://x.example/a.png")
    b = profile("gitlab", "alice", avatar="https://x.example/a.png")
    c = profile("mastodon", "alice", bio="Security researcher and CTF player in Lisbon.")
    d = profile("bluesky", "alice", bio="Security researcher and CTF player in Lisbon.")
    links = correlate([a, b, c, d])
    clusters = build_clusters([a, b, c, d], links)
    sizes = sorted(len(cluster.profiles) for cluster in clusters)
    assert sizes == [2, 2]
    assert all(cluster.score >= 0.5 for cluster in clusters)


def test_cluster_score_is_weakest_link():
    a = profile("github", "alice", avatar="https://x.example/a.png")
    b = profile("gitlab", "alice", avatar="https://x.example/a.png")
    c = profile("reddit", "alice2", bio="Security researcher and occasional CTF player.")
    d = profile("mastodon", "alice2", bio="Security researcher and occasional CTF player.")
    profiles = [a, b, c, d]
    links = correlate(profiles)
    clusters = build_clusters(profiles, links)
    assert clusters
    for cluster in clusters:
        member_links = [
            link for link in links if link.a in cluster.profiles and link.b in cluster.profiles
        ]
        assert cluster.score == round(min(link.score for link in member_links), 2)


def test_singletons_are_not_clusters():
    a = profile("github", "alice")
    b = profile("gitlab", "bob")
    assert build_clusters([a, b], []) == []


def test_link_objects_still_carry_profiles():
    a = profile("github", "alice", avatar="https://x.example/a.png")
    b = profile("gitlab", "alice", avatar="https://x.example/a.png")
    links = correlate([a, b])
    assert isinstance(links[0], Link)
    assert links[0].a.username == "alice"
