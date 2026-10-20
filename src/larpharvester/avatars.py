from __future__ import annotations

import asyncio
import io

from PIL import Image

from .models import Profile

MAX_AVATAR_BYTES = 2_000_000
HASH_SIZE = 8


def dhash(image_bytes: bytes, size: int = HASH_SIZE) -> str | None:
    """Difference hash: robust to resizing/re-encoding, 64 bits as hex."""
    try:
        image = Image.open(io.BytesIO(image_bytes)).convert("L")
    except Exception:
        return None
    image = image.resize((size + 1, size), Image.Resampling.LANCZOS)
    pixels = image.tobytes()
    bits = 0
    for row in range(size):
        base = row * (size + 1)
        for column in range(size):
            bits = (bits << 1) | (1 if pixels[base + column] > pixels[base + column + 1] else 0)
    return f"{bits:016x}"


async def hash_avatars(fetcher, profiles: list[Profile]) -> int:
    """Download avatars and attach perceptual hashes. Returns how many were hashed."""
    targets = [profile for profile in profiles if profile.avatar and not profile.avatar_hash]
    if not targets:
        return 0
    urls = list(dict.fromkeys(profile.avatar for profile in targets))

    async def worker(url: str) -> tuple[str, str | None]:
        try:
            response = await fetcher.get(url)
        except Exception:
            return url, None
        content = response.content
        if response.status != 200 or not content or len(content) > MAX_AVATAR_BYTES:
            return url, None
        return url, await asyncio.to_thread(dhash, content)

    results = await asyncio.gather(*(worker(url) for url in urls if url))
    mapping = {url: digest for url, digest in results if digest}
    for profile in targets:
        profile.avatar_hash = mapping.get(profile.avatar or "")
    return sum(1 for profile in targets if profile.avatar_hash)
