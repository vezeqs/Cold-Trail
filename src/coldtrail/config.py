from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

from .utils import redact_url_credentials

DEFAULT_INSTANCES = ("mastodon.social", "fosstodon.org", "infosec.exchange")
DEFAULT_UA = "coldtrail/0.10 (OSINT research; public data only)"

ENV_VARS = {
    "db_path": "COLDTRAIL_DB",
    "timeout": "COLDTRAIL_TIMEOUT",
    "concurrency": "COLDTRAIL_CONCURRENCY",
    "requests_per_second": "COLDTRAIL_RPS",
    "user_agent": "COLDTRAIL_USER_AGENT",
    "mastodon_instances": "COLDTRAIL_MASTODON_INSTANCES",
    "proxy": "COLDTRAIL_PROXY",
    "max_requests": "COLDTRAIL_MAX_REQUESTS",
    "cache_ttl": "COLDTRAIL_CACHE_TTL",
    "retention_days": "COLDTRAIL_RETENTION_DAYS",
    "tor": "COLDTRAIL_TOR",
    "keep_raw": "COLDTRAIL_KEEP_RAW",
    "avatar_hash": "COLDTRAIL_AVATAR_HASH",
    "web_token": "COLDTRAIL_WEB_TOKEN",
    "trust_proxy": "COLDTRAIL_TRUST_PROXY",
    "allow_private_targets": "COLDTRAIL_ALLOW_PRIVATE_TARGETS",
    "github_token": "GITHUB_TOKEN",
    "hibp_api_key": "HIBP_API_KEY",
    "emailrep_api_key": "EMAILREP_API_KEY",
    "shodan_api_key": "SHODAN_API_KEY",
    "hunter_api_key": "HUNTER_API_KEY",
    "x_bearer_token": "X_BEARER_TOKEN",
    "serper_api_key": "SERPER_API_KEY",
    "brave_api_key": "BRAVE_API_KEY",
    "searxng_url": "SEARXNG_URL",
    "opencorporates_api_key": "OPENCORPORATES_API_KEY",
    "companies_house_api_key": "COMPANIES_HOUSE_API_KEY",
    "opensanctions_api_key": "OPENSANCTIONS_API_KEY",
}

SECRET_FIELDS = {
    "github_token",
    "hibp_api_key",
    "emailrep_api_key",
    "shodan_api_key",
    "hunter_api_key",
    "x_bearer_token",
    "serper_api_key",
    "brave_api_key",
    "opencorporates_api_key",
    "companies_house_api_key",
    "opensanctions_api_key",
    "web_token",
}


def _default_db() -> Path:
    base = os.environ.get("XDG_DATA_HOME")
    root = Path(base) if base else Path.home() / ".local" / "share"
    return root / "coldtrail" / "coldtrail.db"


def default_config_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return root / "coldtrail" / "config.toml"


def _instances(value: str | tuple[str, ...] | list[str] | None) -> tuple[str, ...]:
    if not value:
        return DEFAULT_INSTANCES
    parts = value.split(",") if isinstance(value, str) else list(value)
    return tuple(
        part.strip().removeprefix("https://").removeprefix("http://").rstrip("/")
        for part in parts
        if part and part.strip()
    )


def _display_value(name: str, value: Any) -> Any:
    if name in SECRET_FIELDS:
        return "set" if value else "unset"
    if name in {"proxy", "searxng_url"}:
        return redact_url_credentials(value if isinstance(value, str) else None)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, tuple):
        return list(value)
    return value


@dataclass(slots=True)
class Settings:
    db_path: Path = field(default_factory=_default_db)
    timeout: float = 10.0
    concurrency: int = 24
    requests_per_second: float = 5.0
    jitter: float = 0.1
    user_agent: str = DEFAULT_UA
    github_token: str | None = None
    hibp_api_key: str | None = None
    emailrep_api_key: str | None = None
    shodan_api_key: str | None = None
    hunter_api_key: str | None = None
    x_bearer_token: str | None = None
    serper_api_key: str | None = None
    brave_api_key: str | None = None
    searxng_url: str | None = None
    opencorporates_api_key: str | None = None
    companies_house_api_key: str | None = None
    opensanctions_api_key: str | None = None
    mastodon_instances: tuple[str, ...] = DEFAULT_INSTANCES
    proxy: str | None = None
    tor: bool = False
    respect_robots: bool = False
    keep_raw: bool = False
    avatar_hash: bool = False
    cache_ttl: int = 86_400
    negative_cache_ttl: int = 86_400
    max_requests: int = 0
    retention_days: int = 0
    replay: bool = False
    web_token: str | None = None
    trust_proxy: bool = False
    allow_private_targets: bool = False
    sites_path: Path = field(
        default_factory=lambda: Path(__file__).resolve().parent / "data" / "sites.toml"
    )
    config_path: Path | None = None

    @classmethod
    def load(cls, config_path: Path | None = None) -> Settings:
        path = config_path.expanduser() if config_path else default_config_path()
        data: dict[str, Any] = {}
        if path.is_file():
            with path.open("rb") as handle:
                data = tomllib.load(handle)
        known = {f.name for f in fields(cls)} - {"config_path"}
        values = {key: value for key, value in data.items() if key in known}
        if "mastodon_instances" in values:
            values["mastodon_instances"] = _instances(values["mastodon_instances"])
        for key in ("db_path", "sites_path"):
            if key in values:
                values[key] = Path(values[key]).expanduser()
        settings = cls(**values)
        settings.config_path = path if path.is_file() else None
        settings._apply_env()
        return settings

    def _apply_env(self) -> None:
        env = os.environ
        if value := env.get("COLDTRAIL_DB"):
            self.db_path = Path(value).expanduser()
        if value := env.get("COLDTRAIL_TIMEOUT"):
            self.timeout = float(value)
        if value := env.get("COLDTRAIL_CONCURRENCY"):
            self.concurrency = int(value)
        if value := env.get("COLDTRAIL_RPS"):
            self.requests_per_second = float(value)
        if value := env.get("COLDTRAIL_USER_AGENT"):
            self.user_agent = value
        if value := env.get("COLDTRAIL_MASTODON_INSTANCES"):
            self.mastodon_instances = _instances(value)
        if value := env.get("COLDTRAIL_PROXY"):
            self.proxy = value
        if value := env.get("COLDTRAIL_MAX_REQUESTS"):
            self.max_requests = int(value)
        if value := env.get("COLDTRAIL_CACHE_TTL"):
            self.cache_ttl = int(value)
        if value := env.get("COLDTRAIL_RETENTION_DAYS"):
            self.retention_days = int(value)
        if value := env.get("COLDTRAIL_TOR"):
            self.tor = value.lower() in ("1", "true", "yes")
        if value := env.get("COLDTRAIL_KEEP_RAW"):
            self.keep_raw = value.lower() in ("1", "true", "yes")
        if value := env.get("COLDTRAIL_AVATAR_HASH"):
            self.avatar_hash = value.lower() in ("1", "true", "yes")
        if value := env.get("COLDTRAIL_WEB_TOKEN"):
            self.web_token = value
        if value := env.get("COLDTRAIL_TRUST_PROXY"):
            self.trust_proxy = value.lower() in ("1", "true", "yes")
        if value := env.get("COLDTRAIL_ALLOW_PRIVATE_TARGETS"):
            self.allow_private_targets = value.lower() in ("1", "true", "yes")
        self.github_token = env.get("GITHUB_TOKEN") or self.github_token
        self.hibp_api_key = env.get("HIBP_API_KEY") or self.hibp_api_key
        self.emailrep_api_key = env.get("EMAILREP_API_KEY") or self.emailrep_api_key
        self.shodan_api_key = env.get("SHODAN_API_KEY") or self.shodan_api_key
        self.hunter_api_key = env.get("HUNTER_API_KEY") or self.hunter_api_key
        self.x_bearer_token = env.get("X_BEARER_TOKEN") or self.x_bearer_token
        self.serper_api_key = env.get("SERPER_API_KEY") or self.serper_api_key
        self.brave_api_key = env.get("BRAVE_API_KEY") or self.brave_api_key
        self.searxng_url = env.get("SEARXNG_URL") or self.searxng_url
        self.opencorporates_api_key = (
            env.get("OPENCORPORATES_API_KEY") or self.opencorporates_api_key
        )
        self.companies_house_api_key = (
            env.get("COMPANIES_HOUSE_API_KEY") or self.companies_house_api_key
        )
        self.opensanctions_api_key = env.get("OPENSANCTIONS_API_KEY") or self.opensanctions_api_key

    def describe(self, overrides: dict[str, str] | None = None) -> list[dict[str, Any]]:
        """Effective values with provenance (default/config/env/flag), secrets redacted."""
        overrides = overrides or {}
        config_keys: set[str] = set()
        if self.config_path and self.config_path.is_file():
            with self.config_path.open("rb") as handle:
                config_keys = set(tomllib.load(handle))
        rows: list[dict[str, Any]] = []
        for item in fields(self):
            name = item.name
            if name == "config_path":
                continue
            value = getattr(self, name)
            source = "default"
            if name in config_keys:
                source = "config"
            env_name = ENV_VARS.get(name)
            if env_name and os.environ.get(env_name):
                source = "env"
            if name in overrides:
                source = overrides[name]
            rows.append(
                {
                    "key": name,
                    "value": _display_value(name, value),
                    "source": source,
                    "secret": name in SECRET_FIELDS,
                }
            )
        return rows
