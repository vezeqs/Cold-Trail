from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

DEFAULT_INSTANCES = ("mastodon.social", "fosstodon.org", "infosec.exchange")
DEFAULT_UA = "larpharvester/0.1 (OSINT research; public data only)"


def _default_db() -> Path:
    base = os.environ.get("XDG_DATA_HOME")
    root = Path(base) if base else Path.home() / ".local" / "share"
    return root / "larpharvester" / "larpharvester.db"


def default_config_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return root / "larpharvester" / "config.toml"


def _instances(value: str | tuple[str, ...] | list[str] | None) -> tuple[str, ...]:
    if not value:
        return DEFAULT_INSTANCES
    parts = value.split(",") if isinstance(value, str) else list(value)
    return tuple(
        part.strip().removeprefix("https://").removeprefix("http://").rstrip("/")
        for part in parts
        if part and part.strip()
    )


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
    mastodon_instances: tuple[str, ...] = DEFAULT_INSTANCES
    proxy: str | None = None
    tor: bool = False
    respect_robots: bool = False
    keep_raw: bool = True
    cache_ttl: int = 86_400
    negative_cache_ttl: int = 86_400
    max_requests: int = 0
    retention_days: int = 0
    replay: bool = False
    web_token: str | None = None
    trust_proxy: bool = False
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
        if value := env.get("LARPHARVESTER_DB"):
            self.db_path = Path(value).expanduser()
        if value := env.get("LARPHARVESTER_TIMEOUT"):
            self.timeout = float(value)
        if value := env.get("LARPHARVESTER_CONCURRENCY"):
            self.concurrency = int(value)
        if value := env.get("LARPHARVESTER_RPS"):
            self.requests_per_second = float(value)
        if value := env.get("LARPHARVESTER_USER_AGENT"):
            self.user_agent = value
        if value := env.get("LARPHARVESTER_MASTODON_INSTANCES"):
            self.mastodon_instances = _instances(value)
        if value := env.get("LARPHARVESTER_PROXY"):
            self.proxy = value
        if value := env.get("LARPHARVESTER_MAX_REQUESTS"):
            self.max_requests = int(value)
        if value := env.get("LARPHARVESTER_CACHE_TTL"):
            self.cache_ttl = int(value)
        if value := env.get("LARPHARVESTER_RETENTION_DAYS"):
            self.retention_days = int(value)
        if value := env.get("LARPHARVESTER_TOR"):
            self.tor = value.lower() in ("1", "true", "yes")
        if value := env.get("LARPHARVESTER_KEEP_RAW"):
            self.keep_raw = value.lower() in ("1", "true", "yes")
        if value := env.get("LARPHARVESTER_WEB_TOKEN"):
            self.web_token = value
        if value := env.get("LARPHARVESTER_TRUST_PROXY"):
            self.trust_proxy = value.lower() in ("1", "true", "yes")
        self.github_token = env.get("GITHUB_TOKEN") or self.github_token
        self.hibp_api_key = env.get("HIBP_API_KEY") or self.hibp_api_key
        self.emailrep_api_key = env.get("EMAILREP_API_KEY") or self.emailrep_api_key
        self.shodan_api_key = env.get("SHODAN_API_KEY") or self.shodan_api_key
        self.hunter_api_key = env.get("HUNTER_API_KEY") or self.hunter_api_key
        self.x_bearer_token = env.get("X_BEARER_TOKEN") or self.x_bearer_token
