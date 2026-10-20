from __future__ import annotations

import io

from PIL import Image

from larpharvester.avatars import dhash
from larpharvester.utils import hamming_hex


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
