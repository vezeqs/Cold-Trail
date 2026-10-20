from __future__ import annotations

from urllib.parse import quote

from ..http import Fetcher
from ..models import CheckResult, Profile
from .base import Source, register
from .declarative import parse_meta


@register
class PyPI(Source):
    name = "pypi"
    label = "PyPI"
    group = "dev"
    homepage = "https://pypi.org"

    async def check(self, fetcher: Fetcher, target: str) -> CheckResult:
        status, text = await fetcher.get_text(f"https://pypi.org/user/{quote(target)}/")
        if status != 200:
            return self.missing(target) if status == 404 else self.failed(target, f"HTTP {status}")
        meta = parse_meta(text)
        if not meta.title or meta.title.strip().casefold() == "pypi":
            return self.missing(target)
        return self.ok(
            target,
            Profile(
                source=self.name,
                username=target,
                url=f"https://pypi.org/user/{target}/",
                display_name=meta.title,
                bio=meta.description,
                avatar=meta.image,
            ),
        )
