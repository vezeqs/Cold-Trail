from __future__ import annotations

import io

from PIL import Image

from coldtrail.avatars import dhash
from coldtrail.utils import hamming_hex


def gradient(size: int = 64) -> bytes:
    image = Image.new("L", (size, size))
    image.putdata([int((x / max(1, size - 1)) * 255) for y in range(size) for x in range(size)])
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def test_dhash_is_stable_for_same_bytes():
    data = gradient()
    assert dhash(data) == dhash(data)
    assert len(dhash(data) or "") == 16


def test_dhash_survives_resize():
    original = dhash(gradient(64))
    resized = dhash(gradient(32))
    assert original and resized
    assert hamming_hex(original, resized) <= 4


def test_dhash_rejects_garbage():
    assert dhash(b"not an image") is None


def test_hamming_hex():
    assert hamming_hex("0000000000000000", "0000000000000000") == 0
    assert hamming_hex("0000000000000001", "0000000000000000") == 1
    assert hamming_hex("nothex", "0000000000000000") == 64


async def test_web_profiles_skip_avatar_downloads(monkeypatch):
    from coldtrail.avatars import hash_avatars
    from coldtrail.models import Profile

    calls = []

    class FakeFetcher:
        async def get(self, url):
            calls.append(url)
            raise AssertionError("web.* avatars must not be downloaded")

    profiles = [
        Profile(
            source="web.9gag",
            username="simonw",
            url="https://9gag.com/u/simonw",
            avatar="https://9gag.com/logo.png",
            extra={},
        )
    ]
    assert await hash_avatars(FakeFetcher(), profiles) == 0
    assert calls == []
