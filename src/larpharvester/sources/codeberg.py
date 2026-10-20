from __future__ import annotations

import asyncio
from urllib.parse import quote

from ..http import Fetcher, FetchError
from ..models import CheckResult, Profile
from ..utils import ssh_fingerprint
from .base import Source, register


async def _keys(fetcher: Fetcher, target: str) -> dict[str, list]:
    """Fetch SSH and GPG keys for a Codeberg user (best-effort)."""

    async def ssh() -> list[dict]:
        try:
            status, data = await fetcher.get_json(
                f"https://codeberg.org/api/v1/users/{quote(target)}/keys"
            )
        except FetchError:
            return []
        if status != 200 or not isinstance(data, list):
            return []
        out = []
        for item in data:
            fingerprint = ssh_fingerprint(item.get("key"))
            if fingerprint:
                out.append({"id": item.get("id"), "fingerprint": fingerprint})
        return out

    async def gpg() -> list[dict]:
        try:
            status, data = await fetcher.get_json(
                f"https://codeberg.org/api/v1/users/{quote(target)}/gpg_keys"
            )
        except FetchError:
            return []
        if status != 200 or not isinstance(data, list):
            return []
        return [
            {"id": item.get("id"), "key_id": item.get("key_id"), "emails": item.get("emails") or []}
            for item in data
            if item.get("key_id") or item.get("emails")
        ]

    ssh_keys, gpg_keys = await asyncio.gather(ssh(), gpg())
    return {"ssh_keys": ssh_keys, "gpg_keys": gpg_keys}


@register
class Codeberg(Source):
    name = "codeberg"
    label = "Codeberg"
    group = "dev"
    homepage = "https://codeberg.org"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        status, data = await fetcher.get_json(f"https://codeberg.org/api/v1/users/{quote(target)}")
        if status == 200 and isinstance(data, dict) and data.get("login"):
            key_material = await _keys(fetcher, data["login"])
            return self.ok(
                target,
                Profile(
                    source=self.name,
                    username=data["login"],
                    url=data.get("html_url") or f"https://codeberg.org/{data['login']}",
                    display_name=data.get("full_name"),
                    bio=data.get("description"),
                    avatar=data.get("avatar_url"),
                    website=data.get("website"),
                    created_at=data.get("created"),
                    followers=data.get("followers_count"),
                    extra={
                        "id": data.get("id"),
                        "location": data.get("location"),
                        "language": data.get("language"),
                        "following": data.get("following_count"),
                        "starred_repos": data.get("starred_repos_count"),
                        "visibility": data.get("visibility"),
                        **key_material,
                    },
                ),
            )
        if status == 404:
            return self.missing(target)
        if status in (403, 429):
            return self.blocked(target, f"HTTP {status}: rate limited")
        return self.failed(target, f"HTTP {status}")
