"""External OSINT tool integrations and import adapters.

Two capabilities:

1. ``run_tool`` executes a locally installed OSINT binary (sherlock, exiftool,
   yt-dlp, whois, dig, nmap, …) with a fixed argument vector (never a shell),
   parses its output into ColdTrail models, and can persist it as a run
   with the raw output stored as evidence.
2. ``ingest_file`` imports Maltego CSV, SpiderFoot JSON, theHarvester JSON, or
   generic JSON into the same model so third-party findings land in the local
   database instead of staying stranded in another tool.

Tools that are not installed remain in the registry with an install hint, so
``coldtrail integrations`` tells the operator exactly what to add.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .analysis import extract_entities
from .evidence import add_evidence
from .models import CheckResult, Entity, Link, Post, Profile
from .security import ensure_public_target
from .sites import slugify
from .store import Store

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SHERLOCK_LINE = re.compile(r"^\[\+\]\s*(.+?):\s*(https?://\S+)")
HOLEHE_LINE = re.compile(r"^\[\+\]\s*(\S+)")
SUBDOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$", re.IGNORECASE)


class ToolError(Exception):
    """A tool failed to run or produced unusable output."""


class ToolUnavailable(ToolError):
    """The tool is registered but its binary is not installed."""


MAX_TARGET_LENGTH = 2048


def validate_target(target: str) -> str:
    """Reject targets that a CLI tool could mistake for an option.

    Targets are appended to a fixed argv, so a value such as ``--timeout=999``
    or ``--script=/tmp/x.nse`` would be parsed as a flag by argparse/getopt
    tools. This is reachable from the CLI and the web workbench.
    """
    value = target.strip()
    if not value:
        raise ToolError("target is required")
    if len(value) > MAX_TARGET_LENGTH:
        raise ToolError(f"target is longer than {MAX_TARGET_LENGTH} characters")
    if value.startswith("-"):
        raise ToolError("target must not start with '-' (option injection is not allowed)")
    if any(char in value for char in ("\x00", "\n", "\r")):
        raise ToolError("target must not contain NUL or newline characters")
    return value


@dataclass(slots=True)
class Parsed:
    profiles: list[Profile] = field(default_factory=list)
    posts: list[Post] = field(default_factory=list)
    entities: list[Entity] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
    summary: str = ""
    artifacts: dict[str, bytes] = field(default_factory=dict)


@dataclass(slots=True)
class ToolResult:
    tool: str
    target: str
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    parsed: Parsed

    @property
    def profiles(self) -> list[Profile]:
        return self.parsed.profiles

    @property
    def posts(self) -> list[Post]:
        return self.parsed.posts

    @property
    def entities(self) -> list[Entity]:
        return self.parsed.entities

    @property
    def links(self) -> list[Link]:
        return self.parsed.links

    @property
    def summary(self) -> str:
        return self.parsed.summary

    def raw_bytes(self) -> bytes:
        parts = [f"# tool: {self.tool}", f"# target: {self.target}", f"# command: {self.command}"]
        if self.stderr.strip():
            parts.extend(["", "# stderr", self.stderr])
        parts.extend(["", self.stdout])
        return "\n".join(parts).encode()


@dataclass(slots=True)
class ToolSpec:
    name: str
    binary: str
    category: str
    input_kind: str
    description: str
    install: str
    build: Callable[[str, list[str], Path], list[str]]
    parse: Callable[[str, str, Path], Parsed]
    runner_only: bool = False


def _now(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, UTC).isoformat()
    return str(value)


def _entities(text: str | None, source: str, username: str) -> list[Entity]:
    return extract_entities(text, source, username)


# -- sherlock ---------------------------------------------------------------


def _sherlock_build(target: str, extra: list[str], workdir: Path) -> list[str]:
    return ["sherlock", "--print-found", "--no-color", "--timeout", "10", *extra, target]


def _sherlock_parse(stdout: str, target: str, workdir: Path) -> Parsed:
    profiles: list[Profile] = []
    entities: list[Entity] = []
    for line in stdout.splitlines():
        match = SHERLOCK_LINE.match(line.strip())
        if not match:
            continue
        site, url = match.group(1).strip(), match.group(2).strip()
        source = f"sherlock:{slugify(site)}"
        profiles.append(
            Profile(
                source=source,
                username=target,
                url=url,
                display_name=site,
                extra={"tool": "sherlock", "site": site},
            )
        )
        entities.extend(_entities(url, source, target))
    return Parsed(
        profiles=profiles,
        entities=entities,
        summary=f"{len(profiles)} profile(s) found by sherlock",
    )


# -- holehe -----------------------------------------------------------------


def _holehe_build(target: str, extra: list[str], workdir: Path) -> list[str]:
    return ["holehe", "--only-used", "--no-color", *extra, target]


def _holehe_parse(stdout: str, target: str, workdir: Path) -> Parsed:
    profiles: list[Profile] = []
    for line in stdout.splitlines():
        match = HOLEHE_LINE.match(line.strip())
        if not match:
            continue
        site = match.group(1)
        profiles.append(
            Profile(
                source=f"holehe:{slugify(site)}",
                username=target,
                url="",
                display_name=site,
                extra={"tool": "holehe", "site": site},
            )
        )
    entities = [Entity(source="holehe", username=target, kind="email", value=target)]
    return Parsed(
        profiles=profiles,
        entities=entities,
        summary=f"{len(profiles)} service registration(s) found by holehe",
    )


# -- theHarvester -----------------------------------------------------------


def _theharvester_build(target: str, extra: list[str], workdir: Path) -> list[str]:
    return [
        "theHarvester",
        "-d",
        target,
        "-b",
        "all",
        "-f",
        str(workdir / "harvester"),
        *extra,
    ]


def _theharvester_parse(stdout: str, target: str, workdir: Path) -> Parsed:
    data: dict[str, Any] = {}
    for suffix in (".json", ".xml"):
        artifact = workdir / f"harvester{suffix}"
        if artifact.is_file():
            break
    else:
        artifact = None
    if artifact and artifact.suffix == ".json":
        try:
            loaded = json.loads(artifact.read_text(errors="replace"))
            if isinstance(loaded, dict):
                data = loaded
        except ValueError:
            data = {}
    artifacts = {artifact.name: artifact.read_bytes()} if artifact else {}
    entities: list[Entity] = []
    for key, kind in (
        ("emails", "email"),
        ("hosts", "domain"),
        ("ips", "ipv4"),
        ("urls", "domain"),
        ("linkedin_people", "person"),
    ):
        for value in data.get(key) or []:
            if isinstance(value, str) and value.strip():
                entities.append(
                    Entity(
                        source="theharvester",
                        username=target,
                        kind=kind,
                        value=value.strip(),
                        context="theHarvester import",
                    )
                )
    return Parsed(
        entities=entities,
        summary=f"{len(entities)} finding(s) imported from theHarvester",
        artifacts=artifacts,
    )


# -- subfinder --------------------------------------------------------------


def _subfinder_build(target: str, extra: list[str], workdir: Path) -> list[str]:
    return ["subfinder", "-d", target, "-silent", *extra]


def _subfinder_parse(stdout: str, target: str, workdir: Path) -> Parsed:
    entities = [
        Entity(source="subfinder", username=target, kind="domain", value=line.strip())
        for line in stdout.splitlines()
        if SUBDOMAIN_RE.match(line.strip())
    ]
    return Parsed(entities=entities, summary=f"{len(entities)} subdomain(s) found by subfinder")


# -- h8mail / ghunt ---------------------------------------------------------


def _h8mail_build(target: str, extra: list[str], workdir: Path) -> list[str]:
    return ["h8mail", "-t", target, *extra]


def _h8mail_parse(stdout: str, target: str, workdir: Path) -> Parsed:
    entities = [
        Entity(source="h8mail", username=target, kind="email", value=match)
        for match in dict.fromkeys(EMAIL_RE.findall(stdout))
    ]
    return Parsed(entities=entities, summary=f"{len(entities)} email indicator(s) from h8mail")


def _ghunt_build(target: str, extra: list[str], workdir: Path) -> list[str]:
    return ["ghunt", "email", target, "--json", str(workdir / "ghunt.json"), *extra]


def _ghunt_parse(stdout: str, target: str, workdir: Path) -> Parsed:
    artifact = workdir / "ghunt.json"
    data: dict[str, Any] = {}
    if artifact.is_file():
        try:
            loaded = json.loads(artifact.read_text(errors="replace"))
            if isinstance(loaded, dict):
                data = loaded
        except ValueError:
            data = {}
    entities: list[Entity] = []
    for key, kind in (("email", "email"), ("name", "person"), ("user_id", "google_id")):
        if data.get(key):
            entities.append(
                Entity(source="ghunt", username=target, kind=kind, value=str(data[key]))
            )
    profile = None
    if data.get("name"):
        profile = Profile(
            source="ghunt",
            username=target,
            url="",
            display_name=str(data.get("name")),
            extra={"tool": "ghunt", "google_id": data.get("user_id")},
        )
    return Parsed(
        profiles=[profile] if profile else [],
        entities=entities,
        summary=f"{len(entities)} Google account indicator(s) from ghunt",
        artifacts={"ghunt.json": artifact.read_bytes()} if artifact.is_file() else {},
    )


# -- exiftool ---------------------------------------------------------------


def _exiftool_build(target: str, extra: list[str], workdir: Path) -> list[str]:
    return ["exiftool", "-j", "-G1", "-n", *extra, target]


def _exiftool_parse(stdout: str, target: str, workdir: Path) -> Parsed:
    try:
        records = json.loads(stdout)
    except ValueError as exc:
        raise ToolError(f"exiftool produced invalid JSON: {exc}") from exc
    record = records[0] if isinstance(records, list) and records else {}
    filename = str(record.get("File:FileName") or Path(target).name)
    summary_fields = {}
    entities: list[Entity] = []
    for key, value in record.items():
        if not isinstance(value, (str, int, float)) or str(value) in ("", "0"):
            continue
        summary_fields[key] = value
        if key.endswith((":GPSPosition", ":GPSLatitude", ":GPSLongitude")):
            entities.append(
                Entity(source="exiftool", username=filename, kind="coords", value=str(value))
            )
        elif "email" in key.casefold() or EMAIL_RE.search(str(value)):
            for match in EMAIL_RE.findall(str(value)):
                entities.append(
                    Entity(source="exiftool", username=filename, kind="email", value=match)
                )
    meta = {
        key: str(value)[:300]
        for key, value in summary_fields.items()
        if any(
            marker in key
            for marker in (
                "Make",
                "Model",
                "Software",
                "Artist",
                "Author",
                "Creator",
                "GPS",
                "Date",
            )
        )
    }
    profile = Profile(
        source="exiftool",
        username=filename,
        url=Path(target).resolve().as_uri() if Path(target).exists() else "",
        display_name=filename,
        bio=json.dumps(meta, ensure_ascii=False)[:500] if meta else None,
        extra={"tool": "exiftool", "metadata": meta},
    )
    return Parsed(
        profiles=[profile],
        entities=entities,
        summary=f"{len(record)} metadata tag(s) extracted from {filename}",
    )


# -- yt-dlp -----------------------------------------------------------------


def _ytdlp_build(target: str, extra: list[str], workdir: Path) -> list[str]:
    return ["yt-dlp", "-J", "--no-warnings", "--no-playlist", *extra, target]


def _ytdlp_parse(stdout: str, target: str, workdir: Path) -> Parsed:
    try:
        data = json.loads(stdout)
    except ValueError as exc:
        raise ToolError(f"yt-dlp produced invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ToolError("yt-dlp returned no metadata")
    uploader = data.get("uploader") or data.get("channel") or data.get("uploader_id") or target
    uploader_id = data.get("uploader_id") or data.get("channel_id") or uploader
    uploader_url = (
        data.get("uploader_url") or data.get("channel_url") or data.get("webpage_url") or ""
    )
    profile = Profile(
        source="yt-dlp",
        username=str(uploader_id),
        url=str(uploader_url),
        display_name=str(uploader),
        bio=data.get("description"),
        avatar=data.get("thumbnail"),
        followers=data.get("channel_follower_count"),
        extra={
            "tool": "yt-dlp",
            "channel_id": data.get("channel_id"),
            "extractor": data.get("extractor"),
            "view_count": data.get("view_count"),
        },
    )
    post = Post(
        source="yt-dlp",
        username=str(uploader_id),
        post_id=str(data.get("id") or slugify(target)),
        url=str(data.get("webpage_url") or target),
        created_at=_now(data.get("timestamp") or data.get("release_timestamp")),
        text=" — ".join(filter(None, [data.get("title"), data.get("description")]))[:2000],
        metrics={
            "views": data.get("view_count"),
            "likes": data.get("like_count"),
            "duration": data.get("duration"),
        },
    )
    entities = _entities(data.get("description"), "yt-dlp", str(uploader_id))
    return Parsed(
        profiles=[profile],
        posts=[post],
        entities=entities,
        summary=f"video metadata for {data.get('title') or target}",
    )


# -- whois ------------------------------------------------------------------


def _whois_build(target: str, extra: list[str], workdir: Path) -> list[str]:
    return ["whois", *extra, target]


def _whois_parse(stdout: str, target: str, workdir: Path) -> Parsed:
    fields: dict[str, str] = {}
    for line in stdout.splitlines():
        key, sep, value = line.partition(":")
        if not sep or not value.strip():
            continue
        key = key.strip()
        if key.casefold() in {
            "registrar",
            "creation date",
            "registry expiry date",
            "updated date",
            "registrant organization",
            "registrant country",
            "name server",
            "org",
            "netname",
        }:
            fields.setdefault(key, value.strip())
    emails = dict.fromkeys(EMAIL_RE.findall(stdout))
    entities = [
        Entity(source="whois", username=target, kind="email", value=email) for email in emails
    ]
    profile = Profile(
        source="whois",
        username=target,
        url=f"https://{target}" if "." in target else "",
        display_name=fields.get("Registrant Organization") or fields.get("org") or target,
        bio="; ".join(f"{key}: {value}" for key, value in list(fields.items())[:8]) or None,
        extra={"tool": "whois", "fields": fields},
    )
    return Parsed(
        profiles=[profile],
        entities=entities,
        summary=f"whois record for {target} ({len(fields)} fields)",
    )


# -- dig --------------------------------------------------------------------


def _dig_build(target: str, extra: list[str], workdir: Path) -> list[str]:
    return ["dig", "+short", *extra, target, "A"]


def _dig_parse(stdout: str, target: str, workdir: Path) -> Parsed:
    values = [line.strip() for line in stdout.splitlines() if line.strip()]
    entities = [
        Entity(
            source="dig",
            username=target,
            kind="ipv4" if IPV4_RE.fullmatch(value) else "domain",
            value=value,
        )
        for value in values
    ]
    profile = Profile(
        source="dig",
        username=target,
        url=f"https://{target}" if "." in target else "",
        bio=f"A: {', '.join(values)}" if values else None,
        extra={"tool": "dig", "answers": values},
    )
    return Parsed(
        profiles=[profile] if values else [],
        entities=entities,
        summary=f"{len(values)} DNS answer(s) for {target}",
    )


# -- nmap -------------------------------------------------------------------


def _nmap_build(target: str, extra: list[str], workdir: Path) -> list[str]:
    return ["nmap", "-Pn", "-T4", "-F", "--open", "-oX", "-", *extra, target]


def _nmap_parse(stdout: str, target: str, workdir: Path) -> Parsed:
    from defusedxml import ElementTree as ET
    from defusedxml.common import DefusedXmlException

    try:
        root = ET.fromstring(stdout)
    except (ET.ParseError, DefusedXmlException) as exc:
        raise ToolError(f"nmap produced invalid XML: {exc}") from exc
    ports: list[dict[str, Any]] = []
    addresses: list[str] = []
    hostnames: list[str] = []
    for host in root.findall("host"):
        for address in host.findall("address"):
            if address.get("addr"):
                addresses.append(str(address.get("addr")))
        for hostname in host.findall("./hostnames/hostname"):
            if hostname.get("name"):
                hostnames.append(str(hostname.get("name")))
        for port in host.findall("./ports/port"):
            service = port.find("service")
            ports.append(
                {
                    "port": int(port.get("portid") or 0),
                    "protocol": port.get("protocol"),
                    "service": service.get("name") if service is not None else None,
                    "product": service.get("product") if service is not None else None,
                    "version": service.get("version") if service is not None else None,
                }
            )
    entities: list[Entity] = []
    for address in dict.fromkeys(addresses):
        entities.append(
            Entity(
                source="nmap",
                username=target,
                kind="ipv4" if IPV4_RE.fullmatch(address) else "domain",
                value=address,
            )
        )
    for hostname in dict.fromkeys(hostnames):
        entities.append(Entity(source="nmap", username=target, kind="domain", value=hostname))
    profile = Profile(
        source="nmap",
        username=target,
        url=f"nmap://{target}",
        display_name=target,
        bio=f"{len(ports)} open port(s): {', '.join(str(p['port']) for p in ports[:20])}",
        extra={"tool": "nmap", "ports": ports, "hostnames": hostnames},
    )
    return Parsed(
        profiles=[profile],
        entities=entities,
        summary=f"{len(ports)} open port(s) on {target}",
    )


# -- username / social coverage tools ---------------------------------------


def _first_json(stdout: str) -> Any:
    """Parse a JSON document even when the tool prints progress lines first."""
    text = stdout.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        pass
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        end = text.rfind(closer)
        if start != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except ValueError:
                continue
    return None


def _site_profile(site: str, url: str, target: str, tool: str) -> Profile:
    return Profile(
        source=f"{tool}:{slugify(site)}",
        username=target,
        url=url,
        display_name=site,
        extra={"tool": tool, "site": site},
    )


def _line_profiles(stdout: str, target: str, tool: str) -> list[Profile]:
    profiles: list[Profile] = []
    for line in stdout.splitlines():
        match = SHERLOCK_LINE.match(line.strip())
        if match:
            profiles.append(
                _site_profile(match.group(1).strip(), match.group(2).strip(), target, tool)
            )
    return profiles


def _json_site_entries(data: Any) -> list[tuple[str, str, bool]]:
    """Normalize the common ``{site: {url, status}}`` / ``[{site, url}]`` shapes."""
    entries: list[tuple[str, str, bool]] = []
    if isinstance(data, dict):
        containers = [data]
        for key in ("detected", "results", "sites", "data", "found", "matches"):
            value = data.get(key)
            if isinstance(value, (list, dict)):
                containers.append(value)
        for container in containers:
            if isinstance(container, list):
                for item in container:
                    if not isinstance(item, dict):
                        continue
                    site = item.get("site") or item.get("name") or item.get("site_name")
                    url = item.get("url") or item.get("url_user") or item.get("profile_url")
                    status = item.get("status")
                    if status is not None and str(status).casefold() not in {
                        "found",
                        "claimed",
                        "exists",
                        "true",
                        "detected",
                        "registered",
                    }:
                        continue
                    if site and url:
                        entries.append((str(site), str(url), True))
            else:
                for site, payload in container.items():
                    if not isinstance(payload, dict):
                        continue
                    url = (
                        payload.get("url_user")
                        or payload.get("url")
                        or payload.get("profile_url")
                        or payload.get("url_main")
                    )
                    status = payload.get("status")
                    if isinstance(status, dict):
                        status = status.get("status")
                    flag = payload.get("is_found", payload.get("found"))
                    found = (
                        bool(flag)
                        if flag is not None
                        else str(status).casefold()
                        in {"claimed", "found", "exists", "true", "detected", "registered"}
                    )
                    if url and found:
                        entries.append((str(site), str(url), True))
    elif isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            site = item.get("site") or item.get("name") or item.get("site_name")
            url = item.get("url") or item.get("url_user") or item.get("profile_url")
            status = item.get("status")
            if status is not None and str(status).casefold() not in {
                "found",
                "claimed",
                "exists",
                "true",
                "detected",
                "registered",
            }:
                continue
            if site and url:
                entries.append((str(site), str(url), True))
    return entries


def _maigret_build(target: str, extra: list[str], workdir: Path) -> list[str]:
    return [
        "maigret",
        target,
        "--json",
        "simple",
        "--folderoutput",
        str(workdir),
        "--no-color",
        "--timeout",
        "10",
        *extra,
    ]


def _maigret_parse(stdout: str, target: str, workdir: Path) -> Parsed:
    entries = _json_site_entries(_first_json(stdout))
    if not entries:
        for path in sorted(workdir.rglob("*.json"))[:20]:
            try:
                entries = _json_site_entries(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                continue
            if entries:
                break
    profiles = [_site_profile(site, url, target, "maigret") for site, url, _ in entries]
    if not profiles:
        profiles = _line_profiles(stdout, target, "maigret")
    entities = [
        entity for profile in profiles for entity in _entities(profile.url, profile.source, target)
    ]
    return Parsed(
        profiles=profiles,
        entities=entities,
        summary=f"{len(profiles)} profile(s) found by maigret",
    )


def _naminter_build(target: str, extra: list[str], workdir: Path) -> list[str]:
    return [
        "naminter",
        "-u",
        target,
        "--json",
        "--json-path",
        str(workdir / "naminter.json"),
        *extra,
    ]


def _naminter_parse(stdout: str, target: str, workdir: Path) -> Parsed:
    data = _first_json(stdout)
    if data is None:
        path = workdir / "naminter.json"
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                data = None
    entries = _json_site_entries(data)
    profiles = [_site_profile(site, url, target, "naminter") for site, url, _ in entries]
    if not profiles:
        profiles = _line_profiles(stdout, target, "naminter")
    entities = [
        entity for profile in profiles for entity in _entities(profile.url, profile.source, target)
    ]
    return Parsed(
        profiles=profiles,
        entities=entities,
        summary=f"{len(profiles)} profile(s) found by naminter (WhatsMyName dataset)",
    )


def _social_analyzer_build(target: str, extra: list[str], workdir: Path) -> list[str]:
    return ["social-analyzer", "--username", target, "--output", "json", "--silent", *extra]


def _social_analyzer_parse(stdout: str, target: str, workdir: Path) -> Parsed:
    entries = _json_site_entries(_first_json(stdout))
    profiles = [_site_profile(site, url, target, "social-analyzer") for site, url, _ in entries]
    if not profiles:
        profiles = _line_profiles(stdout, target, "social-analyzer")
    entities = [
        entity for profile in profiles for entity in _entities(profile.url, profile.source, target)
    ]
    return Parsed(
        profiles=profiles,
        entities=entities,
        summary=f"{len(profiles)} profile(s) found by social-analyzer",
    )


def _blackbird_build(target: str, extra: list[str], workdir: Path) -> list[str]:
    return ["otinstaller", "run", "blackbird", "--", "--username", target, *extra]


def _blackbird_parse(stdout: str, target: str, workdir: Path) -> Parsed:
    entries = _json_site_entries(_first_json(stdout))
    profiles = [_site_profile(site, url, target, "blackbird") for site, url, _ in entries]
    if not profiles:
        profiles = _line_profiles(stdout, target, "blackbird")
    entities = [
        entity for profile in profiles for entity in _entities(profile.url, profile.source, target)
    ]
    return Parsed(
        profiles=profiles,
        entities=entities,
        summary=f"{len(profiles)} profile(s) found by blackbird",
    )


def _instaloader_build(target: str, extra: list[str], workdir: Path) -> list[str]:
    return [
        "instaloader",
        "--no-pictures",
        "--no-videos",
        "--no-captions",
        "--no-compress-json",
        "--max-count",
        "12",
        "--dirname-pattern",
        str(workdir / "instagram"),
        *extra,
        target,
    ]


def _instaloader_parse(stdout: str, target: str, workdir: Path) -> Parsed:
    profiles: list[Profile] = []
    posts: list[Post] = []
    entities: list[Entity] = []
    seen_profiles: set[str] = set()
    for path in sorted(workdir.rglob("*.json"))[:200]:
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        node = data.get("node") if isinstance(data.get("node"), dict) else data
        username = node.get("username")
        if not username:
            continue
        username = str(username)
        if username.casefold() not in seen_profiles:
            seen_profiles.add(username.casefold())
            profile = Profile(
                source="instagram",
                username=username,
                url=f"https://www.instagram.com/{username}/",
                display_name=node.get("full_name"),
                bio=node.get("biography"),
                avatar=node.get("profile_pic_url_hd") or node.get("profile_pic_url"),
                website=node.get("external_url"),
                followers=(node.get("edge_followed_by") or {}).get("count")
                if isinstance(node.get("edge_followed_by"), dict)
                else None,
                extra={
                    "tool": "instaloader",
                    "instagram_id": node.get("id"),
                    "verified": node.get("is_verified"),
                    "business_email": node.get("business_email"),
                    "public_email": node.get("public_email"),
                    "phone": node.get("contact_phone_number"),
                },
            )
            profiles.append(profile)
            for key in ("biography", "external_url", "business_email", "public_email"):
                value = node.get(key)
                if isinstance(value, str):
                    entities.extend(_entities(value, "instagram", profile.username))
            caption_edges = (node.get("edge_media_to_caption") or {}).get("edges") or []
            for edge in caption_edges:
                caption = ((edge or {}).get("node") or {}).get("text")
                if caption:
                    entities.extend(_entities(caption, "instagram", profile.username))
        shortcode = data.get("shortcode")
        if shortcode:
            caption_edges = (data.get("edge_media_to_caption") or {}).get("edges") or []
            caption = ((caption_edges[0] if caption_edges else {}).get("node") or {}).get("text")
            posts.append(
                Post(
                    source="instagram",
                    username=username,
                    post_id=str(shortcode),
                    url=f"https://www.instagram.com/p/{shortcode}/",
                    created_at=_now(data.get("taken_at_timestamp")),
                    text=caption,
                )
            )
    if not profiles:
        match = re.search(r"Profile:\s*(\S+)", stdout)
        if match:
            profiles.append(
                Profile(
                    source="instagram",
                    username=match.group(1),
                    url=f"https://www.instagram.com/{match.group(1)}/",
                    extra={"tool": "instaloader"},
                )
            )
    return Parsed(
        profiles=profiles,
        posts=posts,
        entities=entities,
        summary=f"{len(profiles)} Instagram profile(s), {len(posts)} post(s)",
    )


def _twscrape_build(target: str, extra: list[str], workdir: Path) -> list[str]:
    return ["twscrape", "user_by_login", target, *extra]


def _twscrape_parse(stdout: str, target: str, workdir: Path) -> Parsed:
    data = _first_json(stdout)
    if isinstance(data, list):
        data = data[0] if data else None
    profiles: list[Profile] = []
    entities: list[Entity] = []
    if isinstance(data, dict):
        username = str(data.get("username") or target)
        metrics = data.get("public_metrics")
        if not isinstance(metrics, dict):
            metrics = {}
        profiles.append(
            Profile(
                source="x",
                username=username,
                url=f"https://x.com/{username}",
                display_name=data.get("displayname") or data.get("name"),
                bio=data.get("description") or data.get("rawDescription"),
                avatar=data.get("profileImageUrl") or data.get("profile_image_url"),
                website=data.get("url"),
                created_at=_now(data.get("createdAt") or data.get("created_at")),
                followers=data.get("followersCount") or metrics.get("followers_count"),
                extra={"tool": "twscrape", "x_id": data.get("id")},
            )
        )
        for key in ("description", "location", "url"):
            value = data.get(key)
            if isinstance(value, str):
                entities.extend(_entities(value, "x", username))
    return Parsed(
        profiles=profiles,
        entities=entities,
        summary=f"{len(profiles)} X/Twitter profile(s) via twscrape",
    )


# -- registry ---------------------------------------------------------------

TOOLS: dict[str, ToolSpec] = {
    "sherlock": ToolSpec(
        name="sherlock",
        binary="sherlock",
        category="username",
        input_kind="username",
        description="Hundreds of sites for a username (imports as profiles).",
        install="pipx install sherlock-project",
        build=_sherlock_build,
        parse=_sherlock_parse,
    ),
    "holehe": ToolSpec(
        name="holehe",
        binary="holehe",
        category="email",
        input_kind="email",
        description="Checks which services an email is registered on.",
        install="pipx install holehe",
        build=_holehe_build,
        parse=_holehe_parse,
    ),
    "theharvester": ToolSpec(
        name="theharvester",
        binary="theHarvester",
        category="domain",
        input_kind="domain",
        description="Emails, hosts, and IPs for a domain.",
        install="pipx install theHarvester",
        build=_theharvester_build,
        parse=_theharvester_parse,
    ),
    "subfinder": ToolSpec(
        name="subfinder",
        binary="subfinder",
        category="domain",
        input_kind="domain",
        description="Passive subdomain enumeration.",
        install="go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        build=_subfinder_build,
        parse=_subfinder_parse,
    ),
    "h8mail": ToolSpec(
        name="h8mail",
        binary="h8mail",
        category="email",
        input_kind="email",
        description="Breach and credential-leak indicator search.",
        install="pipx install h8mail",
        build=_h8mail_build,
        parse=_h8mail_parse,
    ),
    "ghunt": ToolSpec(
        name="ghunt",
        binary="ghunt",
        category="email",
        input_kind="email",
        description="Google account intelligence for an email.",
        install="pipx install ghunt",
        build=_ghunt_build,
        parse=_ghunt_parse,
    ),
    "exiftool": ToolSpec(
        name="exiftool",
        binary="exiftool",
        category="file",
        input_kind="file",
        description="EXIF/XMP metadata, GPS, and author tags from a file.",
        install="apt install libimage-exiftool-perl",
        build=_exiftool_build,
        parse=_exiftool_parse,
    ),
    "yt-dlp": ToolSpec(
        name="yt-dlp",
        binary="yt-dlp",
        category="url",
        input_kind="url",
        description="Video/channel metadata and uploader identity.",
        install="pipx install yt-dlp",
        build=_ytdlp_build,
        parse=_ytdlp_parse,
    ),
    "whois": ToolSpec(
        name="whois",
        binary="whois",
        category="domain",
        input_kind="domain",
        description="Registration record, registrar, dates, and emails.",
        install="apt install whois",
        build=_whois_build,
        parse=_whois_parse,
    ),
    "dig": ToolSpec(
        name="dig",
        binary="dig",
        category="domain",
        input_kind="domain",
        description="DNS answers for a domain.",
        install="apt install dnsutils",
        build=_dig_build,
        parse=_dig_parse,
    ),
    "nmap": ToolSpec(
        name="nmap",
        binary="nmap",
        category="network",
        input_kind="ip/domain",
        description="Fast open-port and service scan.",
        install="apt install nmap",
        build=_nmap_build,
        parse=_nmap_parse,
    ),
    "maigret": ToolSpec(
        name="maigret",
        binary="maigret",
        category="username",
        input_kind="username",
        description="Deep username search across 3,000+ sites (successor to Sherlock).",
        install="pipx install maigret",
        build=_maigret_build,
        parse=_maigret_parse,
    ),
    "naminter": ToolSpec(
        name="naminter",
        binary="naminter",
        category="username",
        input_kind="username",
        description="Async client for the WebBreacher WhatsMyName dataset (JSON export).",
        install="pipx install naminter",
        build=_naminter_build,
        parse=_naminter_parse,
    ),
    "social-analyzer": ToolSpec(
        name="social-analyzer",
        binary="social-analyzer",
        category="username",
        input_kind="username",
        description="Profile detection with confidence metadata across social sites.",
        install="pipx install social-analyzer",
        build=_social_analyzer_build,
        parse=_social_analyzer_parse,
    ),
    "blackbird": ToolSpec(
        name="blackbird",
        binary="otinstaller",
        category="username",
        input_kind="username",
        description="Username/email OSINT with per-site JSON and CSV exports (via otinstaller).",
        install="pipx install otinstaller && otinstaller init && otinstaller install blackbird",
        build=_blackbird_build,
        parse=_blackbird_parse,
    ),
    "instaloader": ToolSpec(
        name="instaloader",
        binary="instaloader",
        category="social",
        input_kind="username",
        description="Public Instagram profile metadata and recent post JSON.",
        install="pipx install instaloader",
        build=_instaloader_build,
        parse=_instaloader_parse,
    ),
    "twscrape": ToolSpec(
        name="twscrape",
        binary="twscrape",
        category="social",
        input_kind="username",
        description="X/Twitter profile lookup through a logged-in account pool.",
        install="pipx install twscrape && twscrape add_accounts accounts.txt",
        build=_twscrape_build,
        parse=_twscrape_parse,
    ),
    "spiderfoot": ToolSpec(
        name="spiderfoot",
        binary="sf.py",
        category="import",
        input_kind="import",
        description="Import SpiderFoot JSON exports (no runner).",
        install="pipx install spiderfoot",
        build=lambda target, extra, workdir: [],
        parse=lambda stdout, target, workdir: Parsed(),
        runner_only=True,
    ),
    "maltego": ToolSpec(
        name="maltego",
        binary="maltego",
        category="import",
        input_kind="import",
        description="Import Maltego CSV edge exports (no runner).",
        install="Maltego desktop",
        build=lambda target, extra, workdir: [],
        parse=lambda stdout, target, workdir: Parsed(),
        runner_only=True,
    ),
}


def installed(tool: str) -> bool:
    spec = TOOLS.get(tool)
    return bool(spec and shutil.which(spec.binary))


def list_tools() -> list[dict[str, Any]]:
    return [
        {
            "name": spec.name,
            "binary": spec.binary,
            "category": spec.category,
            "input": spec.input_kind,
            "installed": installed(spec.name),
            "runner": not spec.runner_only,
            "description": spec.description,
            "install": spec.install,
        }
        for spec in sorted(TOOLS.values(), key=lambda item: item.name)
    ]


def run_tool(
    name: str,
    target: str,
    *,
    timeout: float = 180.0,
    extra_args: list[str] | None = None,
    allow_private: bool = True,
    allow_file_paths: bool = True,
) -> ToolResult:
    """Execute a registered tool safely (argument vector, no shell) and parse output."""
    spec = TOOLS.get(name)
    if spec is None:
        raise ToolError(f"unknown tool {name!r}; see `coldtrail integrations`")
    if spec.runner_only:
        raise ToolError(f"{name} is import-only; use `coldtrail ingest --format {name}`")
    target = validate_target(target)
    if spec.input_kind == "file":
        if not allow_file_paths:
            raise ToolError(
                "file targets are CLI-only; the web workbench does not read local paths"
            )
        if not Path(target).is_file():
            raise ToolError(f"not a file: {target}")
    elif spec.input_kind in {"domain", "ip/domain", "url"} and not allow_private:
        try:
            ensure_public_target(target)
        except ValueError as exc:
            raise ToolError(str(exc)) from exc
    if not shutil.which(spec.binary):
        raise ToolUnavailable(f"{spec.binary} is not installed. Install with: {spec.install}")
    extra = [str(item) for item in (extra_args or [])]
    with tempfile.TemporaryDirectory(prefix="coldtrail-tool-") as temp:
        workdir = Path(temp)
        command = spec.build(target, extra, workdir)
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                cwd=workdir,
                env={**os.environ, "NO_COLOR": "1", "TERM": "dumb"},
            )
        except subprocess.TimeoutExpired as exc:
            raise ToolError(f"{name} timed out after {timeout:.0f}s") from exc
        except OSError as exc:
            raise ToolError(f"could not execute {spec.binary}: {exc}") from exc
        parsed = spec.parse(completed.stdout, target, workdir)
        return ToolResult(
            tool=name,
            target=target,
            command=command,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            parsed=parsed,
        )


def persist_tool_result(store: Store, result: ToolResult) -> int:
    """Persist an external tool result as a run, with raw output as evidence."""
    run_id = store.start_run(f"tool:{result.tool}", result.target)
    status = "found" if (result.profiles or result.entities) else "not_found"
    try:
        store.save_checks(
            run_id,
            [CheckResult(result.tool, result.target, status, detail=result.summary)],
        )
        if result.profiles:
            store.save_profiles(run_id, result.profiles)
            store.record_profile_history(run_id, result.profiles)
        if result.posts:
            store.save_posts(run_id, result.posts)
        if result.entities:
            store.save_entities(run_id, result.entities)
        if result.links:
            store.save_links(run_id, result.links)
        add_evidence(
            store,
            data=result.raw_bytes(),
            filename=f"{result.tool}-{slugify(result.target)}.txt",
            media_type="text/plain",
            run_id=run_id,
            target_type="run",
            target=str(run_id),
            note=f"raw output from {result.tool}",
        )
        for filename, data in result.parsed.artifacts.items():
            add_evidence(
                store,
                data=data,
                filename=filename,
                run_id=run_id,
                target_type="run",
                target=str(run_id),
                note=f"{result.tool} artifact",
            )
        store.finish_run(run_id)
    except Exception:
        store.finish_run(run_id, "error")
        raise
    return run_id


# -- importers --------------------------------------------------------------


def _host_of(value: str) -> str:
    if value.startswith(("http://", "https://")):
        return urlsplit(value).netloc or value
    return value


def _entity(kind: str, value: str, source: str, username: str, context: str) -> Entity:
    return Entity(
        source=source,
        username=username,
        kind=kind,
        value=value,
        context=context,
    )


def parse_maltego_csv(text: str) -> Parsed:
    reader = csv.DictReader(io.StringIO(text))
    profiles: dict[tuple[str, str], Profile] = {}
    entities: list[Entity] = []
    links: list[Link] = []
    alias_profiles: dict[str, Profile] = {}

    def alias_profile(value: str) -> Profile:
        if value in alias_profiles:
            return alias_profiles[value]
        source, _, username = value.partition(":")
        profile = Profile(
            source=source or "maltego",
            username=username or value,
            url="",
            extra={"tool": "maltego"},
        )
        alias_profiles[value] = profile
        profiles[(profile.source, profile.username)] = profile
        return profile

    for row in reader:
        source_value = (row.get("SourceValue") or "").strip()
        target_value = (row.get("TargetValue") or "").strip()
        relation = (row.get("Relation") or "related-to").strip()
        if not source_value or not target_value:
            continue
        source_type = (row.get("SourceType") or "").casefold()
        target_type = (row.get("TargetType") or "").casefold()
        source_is_alias = "alias" in source_type
        target_is_alias = "alias" in target_type
        if source_is_alias and target_is_alias:
            a, b = alias_profile(source_value), alias_profile(target_value)
            try:
                weight = float(row.get("Weight") or 0.5)
            except ValueError:
                weight = 0.5
            links.append(Link(a=a, b=b, score=weight, reasons=[relation]))
        elif source_is_alias:
            kind = target_type.split(".")[-1] or "entity"
            entities.append(
                _entity(kind, target_value, "maltego", source_value, f"Maltego import ({relation})")
            )
        elif target_is_alias:
            kind = source_type.split(".")[-1] or "entity"
            entities.append(
                _entity(kind, source_value, "maltego", target_value, f"Maltego import ({relation})")
            )
    return Parsed(
        profiles=list(profiles.values()),
        entities=entities,
        links=links,
        summary=f"Maltego import: {len(profiles)} profile(s), {len(entities)} entity(ies), "
        f"{len(links)} link(s)",
    )


SPIDERFOOT_KINDS = {
    "EMAILADDR": "email",
    "INTERNET_NAME": "domain",
    "DOMAIN_NAME": "domain",
    "IP_ADDRESS": "ipv4",
    "PHONE_NUMBER": "phone",
    "BTC_ADDRESS": "btc",
    "ETH_ADDRESS": "eth",
    "USERNAME": "username",
    "HUMAN_NAME": "person",
    "URL": "domain",
}


def parse_spiderfoot_json(text: str) -> Parsed:
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ToolError(f"invalid SpiderFoot JSON: {exc}") from exc
    records = data if isinstance(data, list) else data.get("data") or []
    profiles: list[Profile] = []
    entities: list[Entity] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        kind = SPIDERFOOT_KINDS.get(str(record.get("type") or "").upper())
        value = record.get("data")
        if not kind or not isinstance(value, str) or not value.strip():
            continue
        module = str(record.get("module") or "spiderfoot")
        if kind == "username":
            profiles.append(
                Profile(
                    source=f"spiderfoot:{slugify(module)}",
                    username=value.strip(),
                    url="",
                    extra={"tool": "spiderfoot", "module": module},
                )
            )
        else:
            cleaned = _host_of(value.strip()) if kind == "domain" else value.strip()
            entities.append(_entity(kind, cleaned, "spiderfoot", module, "SpiderFoot import"))
    return Parsed(
        profiles=profiles,
        entities=entities,
        summary=f"SpiderFoot import: {len(profiles)} profile(s), {len(entities)} entity(ies)",
    )


def parse_theharvester_json(text: str) -> Parsed:
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ToolError(f"invalid theHarvester JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ToolError("theHarvester JSON must be an object")
    entities: list[Entity] = []
    for key, kind in (
        ("emails", "email"),
        ("hosts", "domain"),
        ("ips", "ipv4"),
        ("urls", "domain"),
        ("linkedin_people", "person"),
    ):
        for value in data.get(key) or []:
            if isinstance(value, str) and value.strip():
                cleaned = _host_of(value.strip()) if key == "urls" else value.strip()
                entities.append(_entity(kind, cleaned, "theharvester", key, "theHarvester import"))
    return Parsed(
        entities=entities,
        summary=f"theHarvester import: {len(entities)} entity(ies)",
    )


def parse_generic_json(text: str) -> Parsed:
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ToolError(f"invalid JSON: {exc}") from exc
    records = data if isinstance(data, list) else data.get("records") or []
    profiles: list[Profile] = []
    entities: list[Entity] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        if record.get("username") and record.get("source"):
            profiles.append(
                Profile(
                    source=str(record["source"]),
                    username=str(record["username"]),
                    url=str(record.get("url") or ""),
                    display_name=record.get("display_name"),
                    bio=record.get("bio"),
                    extra={"tool": "generic-import"},
                )
            )
            continue
        kind = str(record.get("kind") or "entity")
        value = record.get("value")
        if isinstance(value, str) and value.strip():
            entities.append(
                _entity(
                    kind,
                    value.strip(),
                    "generic",
                    record.get("source") or "import",
                    "JSON import",
                )
            )
    return Parsed(
        profiles=profiles,
        entities=entities,
        summary=f"JSON import: {len(profiles)} profile(s), {len(entities)} entity(ies)",
    )


INGEST_FORMATS: dict[str, Callable[[str], Parsed]] = {
    "maltego": parse_maltego_csv,
    "spiderfoot": parse_spiderfoot_json,
    "theharvester": parse_theharvester_json,
    "json": parse_generic_json,
}


def detect_format(text: str, filename: str = "") -> str:
    text = text.lstrip("\ufeff")
    suffix = Path(filename).suffix.casefold()
    if suffix in (".csv", ".tsv") or text.lstrip().startswith("SourceType,SourceValue"):
        return "maltego"
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(text)
        except ValueError:
            return "json"
        if isinstance(data, dict) and any(
            key in data for key in ("emails", "hosts", "ips", "urls")
        ):
            return "theharvester"
        if isinstance(data, list) and data and isinstance(data[0], dict):
            if {"type", "data"} <= set(data[0]):
                return "spiderfoot"
            if {"source", "username"} <= set(data[0]):
                return "json"
        if isinstance(data, dict) and isinstance(data.get("data"), list):
            return "spiderfoot"
    return "json"


def ingest_file(path: Path, fmt: str = "auto") -> tuple[str, Parsed, bytes]:
    text = Path(path).read_text(errors="replace")
    chosen = detect_format(text, str(path)) if fmt == "auto" else fmt
    parser = INGEST_FORMATS.get(chosen)
    if parser is None:
        raise ToolError(f"unknown import format {fmt!r}; choose {', '.join(INGEST_FORMATS)}")
    return chosen, parser(text), text.encode()


def persist_ingest(store: Store, filename: str, fmt: str, parsed: Parsed, raw: bytes) -> int:
    run_id = store.start_run(f"ingest:{fmt}", filename)
    try:
        store.save_checks(
            run_id,
            [CheckResult(f"ingest:{fmt}", filename, "found", detail=parsed.summary)],
        )
        if parsed.profiles:
            store.save_profiles(run_id, parsed.profiles)
            store.record_profile_history(run_id, parsed.profiles)
        if parsed.posts:
            store.save_posts(run_id, parsed.posts)
        if parsed.entities:
            store.save_entities(run_id, parsed.entities)
        if parsed.links:
            store.save_links(run_id, parsed.links)
        add_evidence(
            store,
            data=raw,
            filename=Path(filename).name,
            media_type="text/csv" if fmt == "maltego" else "application/json",
            run_id=run_id,
            target_type="run",
            target=str(run_id),
            note=f"{fmt} import source",
        )
        store.finish_run(run_id)
    except Exception:
        store.finish_run(run_id, "error")
        raise
    return run_id
