from __future__ import annotations

import pytest

from coldtrail.alerts import Alerter
from coldtrail.config import Settings
from coldtrail.models import Post, Profile
from coldtrail.sources.base import Source
from coldtrail.store import Store
from coldtrail.watch import watch


class FakeSource(Source):
    name = "fake"
    label = "Fake"
    group = "social"
    supports_posts = True

    async def check(self, fetcher, target):
        return self.ok(
            target,
            Profile(
                source=self.name,
                username=target,
                url=f"https://fake.example/{target}",
                bio="bio",
            ),
        )

    async def posts(self, fetcher, target, limit, *, since=None):
        return [
            Post(
                source=self.name,
                username=target,
                post_id="1",
                url="https://fake.example/1",
                created_at="2024-01-01T00:00:00Z",
                text="new post",
            )
        ]


class RecordingAlerter(Alerter):
    name = "recording"

    def __init__(self) -> None:
        self.messages: list[tuple[str, str]] = []

    async def send(self, title: str, body: str) -> bool:
        self.messages.append((title, body))
        return True


@pytest.fixture
def fake_sources(monkeypatch):
    registry = {"fake": FakeSource()}
    monkeypatch.setattr("coldtrail.pivot.SOURCES", registry)
    monkeypatch.setattr("coldtrail.watch.SOURCES", registry)
    monkeypatch.setattr("coldtrail.harvest.SOURCES", registry)
    return registry


async def test_watch_alerts_on_new_posts(tmp_path, fake_sources):
    settings = Settings(db_path=tmp_path / "t.db")
    alerter = RecordingAlerter()
    with Store(settings.db_path) as store:
        cycles = await watch(
            "alice",
            settings=settings,
            store=store,
            interval=1,
            iterations=1,
            limit=5,
            alerters=[alerter],
        )
        assert cycles == 1
        assert store.posts(username="alice")
        assert store.runs()[0]["kind"] == "watch"
        assert store.profiles(username="alice")
    assert alerter.messages
    assert "1 new posts" in alerter.messages[0][0]
    assert "new post" in alerter.messages[0][1]


async def test_watch_does_not_alert_twice(tmp_path, fake_sources):
    settings = Settings(db_path=tmp_path / "t.db")
    alerter = RecordingAlerter()
    with Store(settings.db_path) as store:
        await watch(
            "alice",
            settings=settings,
            store=store,
            interval=1,
            iterations=2,
            limit=5,
            alerters=[alerter],
        )
        assert len(store.runs()) == 2
    assert len(alerter.messages) == 1
