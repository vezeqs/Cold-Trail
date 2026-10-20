from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import quote

from bs4 import BeautifulSoup

from ..http import Fetched, Fetcher
from ..models import CheckResult, Profile
from ..sites import SiteDef
from .base import Source


@dataclass(slots=True)
class Meta:
    title: str | None = None
    description: str | None = None
    image: str | None = None


def parse_meta(text: str) -> Meta:
    # Most metadata sits within the document head; limit parse payload to first 32KB
    head = text[:32768] if text else ""
    soup = BeautifulSoup(head, "html.parser")

    def content(*keys: str) -> str | None:
        for key in keys:
            tag = soup.find("meta", attrs={"property": key}) or soup.find(
                "meta", attrs={"name": key}
            )
            if tag and tag.get("content"):
                return str(tag["content"]).strip()
        return None

    title = content("og:title", "twitter:title")
    if not title and soup.title and soup.title.string:
        title = soup.title.string.strip()
    return Meta(
        title=title,
        description=content("og:description", "twitter:description", "description"),
        image=content("og:image", "twitter:image"),
    )


class DeclarativeSource(Source):
    """A source defined entirely by data in sites.toml (Sherlock-style checks)."""

    group = "web"

    def __init__(self, site: SiteDef) -> None:
        from ..sites import slugify

        self.site = site
        self.name = f"web.{slugify(site.name)}"
        self.label = site.name
        self.homepage = site.main

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        site = self.site
        if site.regex:
            try:
                if not re.fullmatch(site.regex, target):
                    return self.missing(target, "handle fails the site's regex")
            except re.error:
                pass
        template = site.url_probe or site.url
        probe = template.replace("{username}", quote(target, safe=""))
        headers = {
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
            **site.headers,
        }
        response = await fetcher.get(probe, headers=headers)
        if response.status == 410 and "://www." in probe:
            response = await fetcher.get(probe.replace("://www.", "://"), headers=headers)
        if not _found(site, response):
            return self.missing(target, f"HTTP {response.status}")
        meta = parse_meta(response.text)
        human = site.url.replace("{username}", quote(target, safe=""))
        return self.ok(
            target,
            Profile(
                source=self.name,
                username=target,
                url=human,
                display_name=meta.title,
                bio=meta.description,
                avatar=meta.image,
                website=None,
                extra={"site": site.name, "nsfw": site.nsfw, "group": "web"},
            ),
        )


def _found(site: SiteDef, response: Fetched) -> bool:
    if site.error_type == "status_code":
        if site.error_code and response.status == site.error_code:
            return False
        return response.status == 200
    if site.error_type == "message":
        if response.status != 200:
            return False
        low = response.text.casefold()
        return not any(message.casefold() in low for message in site.error_msg)
    if site.error_type == "response_url":
        return response.status == 200 and site.error_url.casefold() not in response.url.casefold()
    return response.status == 200
