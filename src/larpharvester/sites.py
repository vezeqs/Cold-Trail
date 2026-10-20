from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class SiteDef(BaseModel):
    name: str
    url: str
    main: str = ""
    error_type: Literal["status_code", "message", "response_url"] = "status_code"
    error_msg: list[str] = Field(default_factory=list)
    error_url: str = ""
    error_code: int | None = None
    regex: str | None = None
    url_probe: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    nsfw: bool = False

    @field_validator("error_msg", mode="before")
    @classmethod
    def _as_list(cls, value: object) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return list(value)  # type: ignore[arg-type]


def load_sites(path: Path) -> list[SiteDef]:
    if not path.is_file():
        return []
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    sites: list[SiteDef] = []
    for name, payload in (data.get("sites") or {}).items():
        if isinstance(payload, dict):
            sites.append(SiteDef(name=name, **payload))
    return sites


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.casefold()).strip("-")
    return slug or "site"
