from __future__ import annotations

from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register


@register
class DockerHub(Source):
    name = "dockerhub"
    label = "Docker Hub"
    group = "dev"
    homepage = "https://hub.docker.com"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        handle = target.strip().casefold()
        status, data = await fetcher.get_json(f"https://hub.docker.com/v2/users/{quote(handle)}/")
        if status == 200 and isinstance(data, dict):
            uname = data.get("username") or data.get("orgname") or data.get("id")
            if uname:
                uname = str(uname)
                return self.ok(
                    target,
                    Profile(
                        source=self.name,
                        username=uname,
                        url=f"https://hub.docker.com/u/{uname}",
                        display_name=data.get("full_name") or data.get("company") or uname,
                        bio=data.get("company") or data.get("location"),
                        avatar=data.get("gravatar_url"),
                        website=data.get("profile_url") or None,
                        created_at=data.get("date_joined"),
                        extra={
                            "id": data.get("id"),
                            "location": data.get("location"),
                            "company": data.get("company"),
                            "type": data.get("type") or ("org" if data.get("orgname") else "user"),
                        },
                    ),
                )
            return self.missing(target)
        if status == 404:
            return self.missing(target)
        if status in (403, 429):
            return self.blocked(target, f"HTTP {status}: rate limited")
        return self.failed(target, f"HTTP {status}")
