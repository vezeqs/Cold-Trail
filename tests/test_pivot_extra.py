from __future__ import annotations

import pytest

from larpharvester.config import Settings
from larpharvester.models import Profile
from larpharvester.pivot import entities_for_profiles, pivot, select_sources
from larpharvester.sources.base import Source
from larpharvester.store import Store
from larpharvester.variants import variants


class CountingSource(Source):
    name = "counting"
    label = "Counting"
    group = "social"

    def __init__(self) -> None:
        self.calls = 0

    async def check(self, fetcher, target):
        self.calls += 1
        return self.ok(
            target,
            Profile(
                source=self.name,
                username=target,
                url=f"https://counting.example/{target}",
                bio="contact me at alice@example.com",
            ),
        )


class MissingSource(Source):
    name = "missing"
    label = "Missing"
    group = "social"

    def __init__(self) -> None:
        self.calls = 0

    async def check(self, fetcher, target):
        self.calls += 1
        return self.missing(target)


class AvatarSource(Source):
    name = "avatar"
    label = "Avatar"
    group = "social"

    async def check(self, fetcher, target):
        return self.ok(
            target,
            Profile(
                source=self.name,
                username=target,
                url=f"https://avatar.example/{target}",
                avatar="https://cdn.example/a.png",
            ),
        )


@pytest.fixture
def settings(tmp_path):
    return Settings(db_path=tmp_path / "t.db", requests_per_second=0, jitter=0)


async def test_variants_probe_every_generated_handle(settings, monkeypatch):
    source = CountingSource()
    monkeypatch.setattr("larpharvester.pivot.SOURCES", {source.name: source})
    report = await pivot("alice", settings=settings, use_variants=True, avatar_hash=False)
    expected = variants("alice")
    assert source.calls == len(expected)
    assert {result.target for result in report.results} == set(expected)
    assert report.coverage["found"] == len(expected)


async def test_negative_probe_cache_prevents_repeat(settings, monkeypatch, tmp_path):
    source = MissingSource()
    monkeypatch.setattr("larpharvester.pivot.SOURCES", {source.name: source})
    with Store(settings.db_path) as store:
        first = await pivot("alice", settings=settings, avatar_hash=False, store=store)
        second = await pivot("alice", settings=settings, avatar_hash=False, store=store)
    assert source.calls == 1
    assert first.coverage["not_found"] == 1
    assert second.coverage["not_found"] == 1


async def test_coverage_counts_every_status(settings, monkeypatch):
    sources = {
        "counting": CountingSource(),
        "missing": MissingSource(),
    }
    monkeypatch.setattr("larpharvester.pivot.SOURCES", sources)
    report = await pivot("alice", settings=settings, avatar_hash=False)
    assert report.coverage == {"found": 1, "not_found": 1}


async def test_clusters_are_attached_to_report(settings, monkeypatch):
    sources = {"avatar": AvatarSource()}
    monkeypatch.setattr("larpharvester.pivot.SOURCES", sources)
    report = await pivot("alice", settings=settings, avatar_hash=False)
    assert report.clusters == []


async def test_two_sources_with_same_avatar_form_cluster(settings, monkeypatch):
    class AvatarTwo(AvatarSource):
        name = "avatar2"

    monkeypatch.setattr(
        "larpharvester.pivot.SOURCES", {"avatar": AvatarSource(), "avatar2": AvatarTwo()}
    )
    report = await pivot("alice", settings=settings, avatar_hash=False)
    assert len(report.clusters) == 1
    assert len(report.clusters[0].profiles) == 2


def test_select_sources_excludes_web_by_default(monkeypatch):
    class WebSource(Source):
        name = "web.test"
        label = "Web"
        group = "web"

        async def check(self, fetcher, target):
            return self.missing(target)

    curated = CountingSource()
    monkeypatch.setattr(
        "larpharvester.pivot.SOURCES", {"counting": curated, "web.test": WebSource()}
    )
    assert [source.name for source in select_sources(None, "username")] == ["counting"]
    assert {source.name for source in select_sources(None, "username", include_web=True)} == {
        "counting",
        "web.test",
    }


def test_select_sources_expands_groups(monkeypatch):
    monkeypatch.setattr(
        "larpharvester.pivot.SOURCES", {"counting": CountingSource(), "missing": MissingSource()}
    )
    assert {source.name for source in select_sources(["social"], "username")} == {
        "counting",
        "missing",
    }


def test_select_sources_rejects_unknown(monkeypatch):
    monkeypatch.setattr("larpharvester.pivot.SOURCES", {"counting": CountingSource()})
    with pytest.raises(ValueError):
        select_sources(["nope"], "username")


def test_select_sources_all_filters_by_kind(monkeypatch):
    class EmailFake(Source):
        name = "emailfake"
        label = "Email"
        kind = "email"
        group = "email"

        async def check(self, fetcher, target):
            return self.missing(target)

    monkeypatch.setattr(
        "larpharvester.pivot.SOURCES",
        {"counting": CountingSource(), "emailfake": EmailFake()},
    )
    assert [source.name for source in select_sources(["all"], "username")] == ["counting"]
    assert [source.name for source in select_sources(["all"], "email")] == ["emailfake"]


def test_entities_for_profiles():
    profile = Profile(
        source="github",
        username="alice",
        url="https://github.com/alice",
        bio="mail alice@example.com",
    )
    entities = entities_for_profiles([profile])
    assert any(
        entity.kind == "email" and entity.value == "alice@example.com" for entity in entities
    )
