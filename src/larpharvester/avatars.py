from __future__ import annotations

import asyncio
import io
from typing import Any

from PIL import Image

from .models import Profile

MAX_AVATAR_BYTES = 2_000_000
HASH_SIZE = 8

EXIF_FIELDS = {
    "Make": "camera_make",
    "Model": "camera_model",
    "Software": "exif_software",
    "Artist": "exif_artist",
    "Copyright": "exif_copyright",
    "DateTimeOriginal": "taken_at",
    "DateTime": "modified_at",
    "BodySerialNumber": "camera_serial",
    "LensModel": "lens",
}

INFO_FIELDS = {
    "Software": "software",
    "Comment": "comment",
    "Author": "author",
    "Artist": "artist",
    "Description": "description",
    "Copyright": "copyright",
}

GPS_IFD = 34853


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


def _rational(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(value[0]) / float(value[1])
    except (TypeError, ValueError, ZeroDivisionError, IndexError):
        return None


def _gps_decimal(values: Any, ref: str) -> float | None:
    if not values:
        return None
    parts = [_rational(part) for part in values]
    if len(parts) < 3 or any(part is None for part in parts):
        return None
    degrees = parts[0] + parts[1] / 60 + parts[2] / 3600
    if ref.upper() in ("S", "W"):
        degrees = -degrees
    return round(degrees, 6)


def extract_image_metadata(image_bytes: bytes) -> dict[str, Any]:
    """Extract dimensions, EXIF camera fields, PNG text chunks, and GPS coords."""
    try:
        image = Image.open(io.BytesIO(image_bytes))
    except Exception:
        return {}
    meta: dict[str, Any] = {
        "format": image.format,
        "width": image.width,
        "height": image.height,
        "mode": image.mode,
    }
    info = getattr(image, "info", {}) or {}
    for key, out in INFO_FIELDS.items():
        value = info.get(key) or info.get(key.lower())
        if isinstance(value, bytes):
            value = value.decode("utf-8", "replace")
        if value:
            meta[out] = str(value)[:300]
    try:
        exif = image.getexif() or {}
    except Exception:
        exif = {}
    tags = {k: v for k, v in exif.items()}
    from PIL.ExifTags import TAGS

    named = {TAGS.get(key, key): value for key, value in tags.items()}
    for name, out in EXIF_FIELDS.items():
        value = named.get(name)
        if value:
            meta[out] = str(value)[:200]
    try:
        gps = exif.get_ifd(GPS_IFD) or {}
    except Exception:
        gps = {}
    if gps:
        latitude = _gps_decimal(gps.get(2), str(gps.get(1) or "N"))
        longitude = _gps_decimal(gps.get(4), str(gps.get(3) or "E"))
        if latitude is not None and longitude is not None:
            meta["gps"] = f"{latitude},{longitude}"
            meta["coords"] = f"{latitude},{longitude}"
    return {key: value for key, value in meta.items() if value not in (None, "", 0)}


async def hash_avatars(fetcher, profiles: list[Profile]) -> int:
    """Download avatars, attach perceptual hashes and metadata. Returns hashes set.

    Declarative web.* avatars are og:image site logos/templates, not user
    avatars, and are excluded from correlation — skip them entirely.
    """
    targets = [
        profile
        for profile in profiles
        if profile.avatar and not profile.avatar_hash and not profile.source.startswith("web.")
    ]
    if not targets:
        return 0
    urls = list(dict.fromkeys(profile.avatar for profile in targets))

    async def worker(url: str) -> tuple[str, str | None, dict[str, Any]]:
        try:
            response = await fetcher.get(url)
        except Exception:
            return url, None, {}
        content = response.content
        if response.status != 200 or not content or len(content) > MAX_AVATAR_BYTES:
            return url, None, {}
        digest, meta = await asyncio.to_thread(_analyse, content)
        return url, digest, meta

    results = await asyncio.gather(*(worker(url) for url in urls if url))
    mapping = {url: (digest, meta) for url, digest, meta in results if digest}
    hashed = 0
    for profile in targets:
        digest, meta = mapping.get(profile.avatar or "", (None, {}))
        if digest:
            profile.avatar_hash = digest
            hashed += 1
        if meta:
            profile.extra["avatar_meta"] = meta
    return hashed


def _analyse(content: bytes) -> tuple[str | None, dict[str, Any]]:
    return dhash(content), extract_image_metadata(content)
