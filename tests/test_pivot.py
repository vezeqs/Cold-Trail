from __future__ import annotations

import pytest

from coldtrail.config import Settings
from coldtrail.models import Profile
from coldtrail.pivot import discovered_usernames, pivot
from coldtrail.sources.base import Source


class EmailSource(Source):
    name = "email-src"
    label = "Email"
    kind = "email"

    async def check(self, fetcher, target):
        return self.ok(
            target,
            Profile(
                source=self.name,
                username="alice",
                url="https://email.example/alice",
                extra={
                    "accounts": [
                        {"username": "alicegh"},
                        {"username": "@alicebsky"},
                        {"username": "alicegh"},
                        {"username": None},
                    ]
                },
            ),
        )


class UserSource(Source):
    name = "user-src"
    label = "User"
    kind = "username"

    async def check(self, fetcher, target):
        return self.ok(
            target,
            Profile(source=self.name, username=target, url=f"https://user.example/{target}"),
        )


@pytest.fixture
def sources(monkeypatch):
    registry = {"email-src": EmailSource(), "user-src": UserSource()}
    monkeypatch.setattr("coldtrail.pivot.SOURCES", registry)
    return registry


async def test_discovered_usernames_dedupes_and_strips_at():
    result = await EmailSource().check(None, "alice@example.com")
    # Only structured accounts expand; the email-source username is not trusted.
    assert discovered_usernames([result]) == ["alicegh", "alicebsky"]
    assert discovered_usernames([result], limit=1) == ["alicegh"]


async def test_email_pivot_expands_into_username_sources(sources, tmp_path):
    report = await pivot(
        "alice@example.com",
        settings=Settings(db_path=tmp_path / "t.db"),
        expand=True,
    )
    assert report.kind == "email"
    assert report.expanded == ["alicegh", "alicebsky"]
    assert {r.source for r in report.results} == {"email-src", "user-src"}
    user_targets = {r.target for r in report.results if r.source == "user-src"}
    assert user_targets == {"alicegh", "alicebsky"}


async def test_expansion_falls_back_to_full_cross_kind_pool(sources, tmp_path):
    # An explicitly listed source of the primary kind can't serve the expansion,
    # so the whole cross-kind pool is used instead.
    report = await pivot(
        "alice@example.com",
        settings=Settings(db_path=tmp_path / "t.db"),
        sources=["email-src"],
        expand=True,
    )
    assert [r.source for r in report.results if r.target in {"alicegh", "alicebsky"}] == [
        "user-src",
        "user-src",
    ]


async def test_mixed_kind_source_list_raises(sources, tmp_path):
    with pytest.raises(ValueError):
        await pivot(
            "alice@example.com",
            settings=Settings(db_path=tmp_path / "t.db"),
            sources=["email-src", "user-src"],
        )


async def test_username_pivot_expands_into_email_sources(sources, tmp_path):
    class StructuredEmail(UserSource):
        async def check(self, fetcher, target):
            result = await super().check(fetcher, target)
            result.profile.extra["email"] = "alice@example.com"
            return result

    import coldtrail.pivot as pivot_mod

    pivot_mod.SOURCES["user-src"] = StructuredEmail()
    try:
        report = await pivot(
            "alice",
            settings=Settings(db_path=tmp_path / "t.db"),
            expand=True,
        )
    finally:
        pivot_mod.SOURCES["user-src"] = UserSource()
    assert report.expanded == ["alice@example.com"]
    assert any(r.source == "email-src" and r.target == "alice@example.com" for r in report.results)


async def test_bio_emails_do_not_drive_expansion(sources, tmp_path):
    class EmailBio(UserSource):
        async def check(self, fetcher, target):
            result = await super().check(fetcher, target)
            result.profile.bio = "reach me at alice@example.com"
            return result

    import coldtrail.pivot as pivot_mod

    pivot_mod.SOURCES["user-src"] = EmailBio()
    try:
        report = await pivot(
            "alice",
            settings=Settings(db_path=tmp_path / "t.db"),
            expand=True,
        )
    finally:
        pivot_mod.SOURCES["user-src"] = UserSource()
    assert report.expanded == []


async def test_expand_does_nothing_for_usernames(sources, tmp_path):
    report = await pivot("alice", settings=Settings(db_path=tmp_path / "t.db"), expand=True)
    assert report.expanded == []
    assert [r.source for r in report.results] == ["user-src"]
