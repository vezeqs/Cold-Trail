from __future__ import annotations

import math
import re
from collections import Counter

from .models import Entity, Post, Profile
from .utils import parse_dt

PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "btc": re.compile(r"\b(?:bc1[a-zA-HJ-NP-Z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    "eth": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "xmr": re.compile(r"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),
    "onion": re.compile(r"\b[a-z2-7]{56}\.onion\b", re.IGNORECASE),
    "pgp_fingerprint": re.compile(
        r"\b(?:0x)?(?:[0-9A-Fa-f]{4}\s+){9}[0-9A-Fa-f]{4}\b|\b0x[0-9A-Fa-f]{16,40}\b"
    ),
    "ssh_key": re.compile(r"\bSHA256:[A-Za-z0-9+/]{43}=?\b"),
    "matrix": re.compile(r"(?<![\w.])@[A-Za-z0-9._=-]{2,64}:[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "coords": re.compile(r"\b-?\d{1,3}\.\d{4,}\s*,\s*-?\d{1,3}\.\d{4,}\b"),
    "discord": re.compile(r"\b[A-Za-z0-9_.]{2,32}#\d{4}\b"),
    "telegram": re.compile(r"(?<![\w.])(?:t\.me/|@)([A-Za-z][A-Za-z0-9_]{4,31})\b"),
    "phone": re.compile(r"(?<![\w.])\+?\d[\d\s().-]{7,14}\d(?![\w.])"),
    "domain": re.compile(
        r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"(?:com|net|org|io|dev|me|co|ai|xyz|info|ru|de|fr|es|nl|se|no|fi|dk|pl|br|jp|cn|uk|us)\b",
        re.IGNORECASE,
    ),
}

STOP_DOMAINS = {
    "example.com",
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "protonmail.com",
    "proton.me",
    "icloud.com",
    "aol.com",
    "gmx.com",
    "mail.com",
    "yandex.ru",
    "twitter.com",
    "x.com",
    "github.com",
    "gitlab.com",
    "reddit.com",
    "youtube.com",
    "instagram.com",
    "facebook.com",
    "linkedin.com",
    "t.me",
    "discord.gg",
    "tiktok.com",
    "twitch.tv",
    "medium.com",
    "substack.com",
    "bsky.app",
    "mastodon.social",
}

LANG_STOPWORDS = {
    "en": {"the", "and", "you", "that", "with", "have", "this", "from", "not", "are"},
    "es": {"el", "la", "los", "las", "que", "con", "para", "una", "por", "como"},
    "fr": {"le", "la", "les", "des", "que", "pour", "avec", "une", "pas", "dans"},
    "de": {"der", "die", "das", "und", "mit", "für", "nicht", "ist", "ein", "auf"},
    "pt": {"que", "não", "uma", "para", "com", "dos", "das", "por", "como", "mais"},
    "it": {"che", "non", "una", "per", "con", "del", "della", "sono", "come", "più"},
    "nl": {"het", "een", "van", "niet", "met", "voor", "dat", "zijn", "op", "maar"},
}

STYLE_WORDS = [
    "the",
    "and",
    "but",
    "so",
    "because",
    "however",
    "therefore",
    "actually",
    "really",
    "just",
    "maybe",
    "probably",
    "always",
    "never",
    "i",
    "we",
    "you",
    "they",
    "is",
    "was",
    "not",
]

HASHTAG_RE = re.compile(r"#\w{2,}")
EMOJI_RE = re.compile("[\U0001f300-\U0001faff\u2600-\u27bf]")


def extract_entities(text: str | None, source: str, username: str) -> list[Entity]:
    if not text:
        return []
    found: list[Entity] = []
    seen: set[tuple[str, str]] = set()
    email_domains: set[str] = set()
    for kind, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(1) if kind == "telegram" else match.group(0)
            value = value.strip().rstrip(".,;:)")
            if kind == "email":
                value = value.casefold()
                if "@" in value:
                    email_domains.add(value.rsplit("@", 1)[1])
            if kind == "domain":
                value = value.casefold()
                if value in STOP_DOMAINS or value.startswith("www.") or value in email_domains:
                    continue
            if kind == "phone":
                stripped = value.strip()
                if re.match(r"^\d{4}-\d{2}-\d{2}", stripped):
                    continue
                digits = re.sub(r"\D", "", value)
                minimum = 8 if stripped.startswith("+") else 9
                if not minimum <= len(digits) <= 15:
                    continue
                if not (stripped.startswith("+") or " " in stripped or "(" in stripped):
                    continue
                value = f"+{digits}" if stripped.startswith("+") else digits
            if kind == "telegram" and value.casefold() in {"gmail", "yahoo", "hotmail"}:
                continue
            if kind == "pgp_fingerprint":
                value = re.sub(r"\s+", "", value).upper()
            if kind == "onion":
                value = value.casefold()
            key = (kind, value.casefold())
            if key in seen:
                continue
            seen.add(key)
            start = max(0, match.start() - 40)
            end = min(len(text), match.end() + 40)
            found.append(
                Entity(
                    source=source,
                    username=username,
                    kind=kind,
                    value=value,
                    context=text[start:end].replace("\n", " ").strip(),
                )
            )
    return found


def entities_from_posts(posts: list[Post]) -> list[Entity]:
    out: list[Entity] = []
    for post in posts:
        out.extend(extract_entities(post.text, post.source, post.username))
    return out


def detect_lang(text: str | None) -> str | None:
    if not text:
        return None
    tokens = re.findall(r"[a-zà-ÿ']+", text.casefold())
    if len(tokens) < 3:
        return None
    counts = {
        lang: sum(1 for token in tokens if token in words) for lang, words in LANG_STOPWORDS.items()
    }
    best = max(counts, key=lambda lang: counts[lang])
    return best if counts[best] >= 2 else None


def infer_timezone(posts: list[Post]) -> str | None:
    hours = [dt.hour for dt in (parse_dt(post.created_at) for post in posts) if dt is not None]
    if len(hours) < 5:
        return None
    counts = Counter(hours)
    # Find inactive window (sleeping hours) - lowest consecutive 6-hour window
    min_sum = 999999
    sleep_start = 0
    for h in range(24):
        window_sum = sum(counts.get((h + i) % 24, 0) for i in range(6))
        if window_sum < min_sum:
            min_sum = window_sum
            sleep_start = h
    # Center of typical sleep is roughly 03:00 local time
    # sleep_start + 3 (UTC) corresponds to 03:00 local
    sleep_mid_utc = (sleep_start + 3) % 24
    offset = ((3 - sleep_mid_utc + 12) % 24) - 12
    sign = "+" if offset >= 0 else "-"
    return f"{sign}{abs(offset):02d}:00"


def enrich_profile(profile: Profile) -> Profile:
    if not profile.lang:
        profile.lang = detect_lang(" ".join(filter(None, [profile.bio, profile.display_name])))
    return profile


def style_vector(text: str | None) -> dict[str, float]:
    if not text:
        return {}
    tokens = re.findall(r"[a-z']+", text.casefold())
    if not tokens:
        return {}
    counts = Counter(tokens)
    return {word: counts.get(word, 0) / len(tokens) for word in STYLE_WORDS}


def style_similarity(left: str | None, right: str | None) -> float:
    a, b = style_vector(left), style_vector(right)
    if not a or not b:
        return 0.0
    dot = sum(a[word] * b[word] for word in STYLE_WORDS)
    norm_a = math.sqrt(sum(value * value for value in a.values()))
    norm_b = math.sqrt(sum(value * value for value in b.values()))
    if not norm_a or not norm_b:
        return 0.0
    return dot / (norm_a * norm_b)


def stylometry(posts: list[Post]) -> dict[str, float]:
    return style_vector(" ".join(post.text or "" for post in posts))


def markers(text: str | None) -> set[str]:
    if not text:
        return set()
    return {tag.casefold() for tag in HASHTAG_RE.findall(text)} | set(EMOJI_RE.findall(text))


def marker_overlap(left: str | None, right: str | None) -> float:
    a, b = markers(left), markers(right)
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)
