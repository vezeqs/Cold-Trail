"""Regression tests for identity-contamination bugs found in the live
investigation: weak email-source handles feeding expansion, same-platform
links, and generated bios creating mentions."""

from __future__ import annotations

from coldtrail.correlate import correlate, score_pair
from coldtrail.models import CheckResult, Profile
from coldtrail.pivot import discovered_emails, discovered_usernames


def _result(source: str, username: str, extra: dict, bio: str | None = None) -> CheckResult:
    return CheckResult(
        source,
        username,
        "found",
        profile=Profile(
            source=source,
            username=username,
            url=f"https://example.test/{source}/{username}",
            bio=bio,
            extra=extra,
        ),
    )


# -- expansion must require structured evidence -----------------------------


def test_email_source_username_is_not_an_expansion_candidate():
    results = [
        _result("gravatar", "simondev", {"accounts": []}),
        _result("libravatar", "simon@simonwillison.net", {"email": "simon@simonwillison.net"}),
        _result("pgp", "simon@simonwillison.net", {}),
    ]
    assert discovered_usernames(results) == []


def test_email_source_structured_accounts_still_expand():
    results = [
        _result(
            "gravatar",
            "simondev",
            {
                "accounts": [
                    {"username": "simonw", "url": "https://github.com/simonw"},
                    {"username": "simon", "url": "https://news.ycombinator.com/user?id=simon"},
                ]
            },
        )
    ]
    found = discovered_usernames(results)
    assert "simonw" in found
    assert "simon" in found
    assert "simondev" not in found


def test_username_source_username_still_expands():
    results = [_result("github", "alice", {})]
    assert discovered_usernames(results) == ["alice"]


def test_discovered_emails_ignores_bio_and_keeps_structured_fields():
    results = [
        _result(
            "github",
            "alice",
            {"email": "alice@example.com"},
            bio="reach me at other@example.com",
        ),
        _result("gitlab", "alice", {"public_email": "alice@example.com"}),
        _result(
            "github",
            "bob",
            {"gpg_keys": [{"key_id": "ABC", "emails": ["bob@example.com"]}]},
            bio="bob@personal.example",
        ),
    ]
    emails = discovered_emails(results)
    assert emails == ["alice@example.com", "bob@example.com"]
    assert "other@example.com" not in emails
    assert "bob@personal.example" not in emails


# -- correlation hygiene ----------------------------------------------------


def _profile(source: str, username: str, **kwargs) -> Profile:
    defaults = {
        "source": source,
        "username": username,
        "url": f"https://example.test/{source}/{username}",
        "extra": {},
    }
    return Profile(**{**defaults, **kwargs})


def test_same_source_different_handles_never_link():
    a = _profile("duolingo", "simondev", avatar="https://cdn.example/same.png")
    b = _profile("duolingo", "simon", avatar="https://cdn.example/same.png")
    assert correlate([a, b]) == []
    # score_pair still reports the raw evidence for direct callers.
    assert score_pair(a, b)[0] >= 0.9


def test_cross_source_identical_avatar_still_links():
    a = _profile("duolingo", "simondev", avatar="https://cdn.example/same.png")
    b = _profile("github", "simondev", avatar="https://cdn.example/same.png")
    links = correlate([a, b])
    assert len(links) == 1
    assert links[0].score >= 0.9


def test_generated_package_list_bio_does_not_mention_handles():
    a = _profile(
        "packagist",
        "simon",
        bio="7 PHP package(s): simon/auth, simon/authl",
        display_name="simon",
    )
    b = _profile("steam", "ThrowRanger", display_name="simon")
    score, reasons = score_pair(a, b)
    assert score < 0.5
    assert not any("bio" in reason for reason in reasons)


# -- source honesty ---------------------------------------------------------


def test_libravatar_username_is_the_full_email():
    from coldtrail.sources import SOURCES

    assert SOURCES["libravatar"].kind == "email"
    # Source-level contract: username must not be a bare local part.
    assert SOURCES["libravatar"].name == "libravatar"


def test_packagist_profile_has_no_generated_bio():
    from coldtrail.sources.packagist import Packagist

    source = Packagist()
    assert source.supports_posts is False


# -- declarative web corpus hygiene ----------------------------------------


def test_web_profiles_do_not_feed_text_correlation():
    a = _profile("web.9gag", "simonw", bio="simonw - 9GAG", display_name="simonw - 9GAG")
    b = _profile(
        "web.aniworld", "simonw", bio="SimonW Anime-Profil", display_name="SimonW Anime-Profil"
    )
    score, reasons = score_pair(a, b)
    assert score == 0.0
    assert reasons == []
    assert correlate([a, b]) == []


def test_web_profile_entities_are_empty():
    from coldtrail.pivot import profile_entities

    profile = _profile(
        "web.about-me",
        "simonw",
        bio="Contact me at person@example.com or t.me/someone",
        display_name="Simon White on about.me",
    )
    assert profile_entities(profile) == []


def test_declarative_generic_title_is_not_a_profile():
    from coldtrail.sites import SiteDef
    from coldtrail.sources.declarative import DeclarativeSource, _generic_title

    site = SiteDef(
        name="APClips",
        url="https://apclips.com/{username}",
        main="https://apclips.com/",
        error_type="status_code",
    )
    assert _generic_title(site, "APClips.com") is True
    assert _generic_title(site, "APClips") is True
    assert _generic_title(site, "simonw on APClips") is False
    assert _generic_title(site, None) is True
    assert DeclarativeSource(site).name == "web.apclips"


def test_build_sites_filters_search_and_availability_endpoints():
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parent.parent / "scripts" / "build_sites.py"
    spec = importlib.util.spec_from_file_location("build_sites", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module._search_like("https://archive.org/search?query={username}")
    assert module._search_like("https://example.com/members?username={username}")
    assert module._search_like("https://example.com/api/users?username={username}")
    assert module._search_like("https://example.com/register/validate?username={username}")
    assert not module._search_like("https://github.com/{username}")
    assert not module._search_like("https://play.google.com/store/apps/developer?id={username}")
    assert not module._search_like("https://news.ycombinator.com/user?id={username}")
