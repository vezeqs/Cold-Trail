from __future__ import annotations

import re
from itertools import combinations

from .models import Cluster, Link, Profile
from .utils import days_between, hamming_hex, norm, norm_url, parse_dt, short_key

THRESHOLD = 0.5
BIO_MIN = 25
AVATAR_MAX_DISTANCE = 8

GENERIC_HOSTS = {
    "twitter.com",
    "x.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "github.com",
    "gitlab.com",
    "youtube.com",
    "tiktok.com",
    "twitch.tv",
    "t.me",
    "discord.gg",
    "bit.ly",
    "goo.gl",
    "tinyurl.com",
    "google.com",
    "medium.com",
    "substack.com",
    "linktr.ee",
    "beacons.ai",
    "about.me",
    "wordpress.com",
    "blogspot.com",
    "tumblr.com",
}

AVATAR_DENY = (
    "missing.png",
    "missing.jpg",
    "default_profile",
    "default-avatar",
    "default_avatar",
    "avatar_default",
    "no-avatar",
    "noavatar",
    "blank.png",
    "blank.gif",
    "default.png",
    "default.jpg",
    "identicon_default",
    "d=identicon",
    "d=mm",
    "d=mp",
    "d=retro",
    "d=robohash",
    "d=monsterid",
    "d=wavatar",
    "d=404",
)

STOPWORDS = set(
    [
        "the",
        "a",
        "an",
        "and",
        "or",
        "of",
        "to",
        "in",
        "for",
        "with",
        "my",
        "me",
        "i",
        "am",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "being",
        "on",
        "at",
        "by",
        "from",
        "this",
        "that",
        "these",
        "those",
        "it",
        "its",
        "as",
        "not",
        "no",
        "yes",
        "you",
        "your",
        "yours",
        "we",
        "our",
        "ours",
        "they",
        "their",
        "theirs",
        "he",
        "she",
        "his",
        "her",
        "him",
        "about",
        "more",
        "most",
        "all",
        "any",
        "can",
        "will",
        "would",
        "just",
        "also",
        "very",
        "so",
        "if",
        "but",
        "out",
        "up",
        "down",
        "one",
        "two",
        "new",
        "now",
        "get",
        "got",
        "make",
        "made",
        "like",
        "life",
        "love",
        "world",
        "user",
        "official",
        "account",
        "profile",
        "page",
        "follow",
        "following",
        "me",
        "please",
        "thanks",
        "thank",
        "hello",
        "hi",
        "hey",
        "here",
        "there",
        "what",
        "who",
        "how",
        "why",
        "when",
        "where",
        "who's",
        "i'm",
        "i've",
        "i'll",
        "don't",
        "can't",
        "won't",
        "im",
        "ur",
        "r",
        "u",
        "ive",
        "id",
    ]
)

PLATFORM_WORDS = {
    "github",
    "gitlab",
    "reddit",
    "twitter",
    "x",
    "mastodon",
    "bluesky",
    "instagram",
    "facebook",
    "linkedin",
    "youtube",
    "twitch",
    "tiktok",
    "telegram",
    "discord",
    "devto",
    "hackernews",
    "keybase",
    "gravatar",
    "linktree",
}


def correlate(profiles: list[Profile], threshold: float = THRESHOLD) -> list[Link]:
    """Find pairs of profiles that plausibly belong to the same person."""
    links: list[Link] = []
    for a, b in combinations(profiles, 2):
        if a.source == b.source and a.username.casefold() == b.username.casefold():
            continue
        score, reasons = score_pair(a, b)
        if score >= threshold:
            links.append(Link(a=a, b=b, score=round(min(score, 1.0), 2), reasons=reasons))
    return sorted(links, key=lambda link: link.score, reverse=True)


def build_clusters(
    profiles: list[Profile], links: list[Link], threshold: float = THRESHOLD
) -> list[Cluster]:
    """Union-find over correlation edges; a cluster is an inferred identity."""
    parent: dict[tuple[str, str], tuple[str, str]] = {
        (p.source, p.username): (p.source, p.username) for p in profiles
    }

    def find(node: tuple[str, str]) -> tuple[str, str]:
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    def union(left: tuple[str, str], right: tuple[str, str]) -> None:
        root_left, root_right = find(left), find(right)
        if root_left != root_right:
            parent[root_right] = root_left

    for link in links:
        if link.score >= threshold:
            union((link.a.source, link.a.username), (link.b.source, link.b.username))

    groups: dict[tuple[str, str], list[Profile]] = {}
    for profile in profiles:
        groups.setdefault(find((profile.source, profile.username)), []).append(profile)

    clusters: list[Cluster] = []
    for members in groups.values():
        if len(members) < 2:
            continue
        member_keys = {(p.source, p.username) for p in members}
        internal = [
            link
            for link in links
            if (link.a.source, link.a.username) in member_keys
            and (link.b.source, link.b.username) in member_keys
        ]
        if not internal:
            continue
        reasons: list[str] = []
        for link in internal:
            reasons.extend(link.reasons)
        clusters.append(
            Cluster(
                key=short_key("|".join(sorted(f"{s}:{u}" for s, u in member_keys))),
                profiles=members,
                score=round(min(link.score for link in internal), 2),
                reasons=list(dict.fromkeys(reasons)),
            )
        )
    return sorted(
        clusters, key=lambda cluster: (len(cluster.profiles), cluster.score), reverse=True
    )


def score_pair(a: Profile, b: Profile) -> tuple[float, list[str]]:
    score = 0.0
    reasons: list[str] = []

    avatar_score, avatar_reason = _avatar_signal(a, b)
    score += avatar_score
    if avatar_reason:
        reasons.append(avatar_reason)

    bio_score, bio_reason = _bio_signal(a, b)
    score += bio_score
    if bio_reason:
        reasons.append(bio_reason)

    if _website_key(a.website) and _website_key(a.website) == _website_key(b.website):
        score += 0.6
        reasons.append("same website")

    name_a, name_b = norm(a.display_name), norm(b.display_name)
    if name_a and name_a == name_b and len(name_a) >= 3 and name_a not in {"admin", "user"}:
        score += 0.3
        reasons.append("same display name")

    if "@" not in a.username and _mentions(a.username, b.bio):
        score += 0.5
        reasons.append(f"{a.source} handle in {b.source} bio")
    if "@" not in b.username and _mentions(b.username, a.bio):
        score += 0.5
        reasons.append(f"{b.source} handle in {a.source} bio")

    gap = days_between(a.created_at, b.created_at)
    if gap is not None and gap <= 7:
        score += 0.1
        reasons.append(f"accounts created within {gap:.0f} days")

    score += _timezone_signal(a, b, reasons)
    score += _language_signal(a, b, reasons)
    score += _extracted_entity_signal(a, b, reasons)
    score += _handle_similarity_signal(a, b, reasons)

    return max(0.0, score), reasons


# Kinds that are strong identity evidence when two profiles share them.
STRONG_ENTITY_KINDS = {
    "email",
    "btc",
    "eth",
    "xmr",
    "onion",
    "pgp_fingerprint",
    "ssh_key",
    "matrix",
    "discord",
    "telegram",
    "phone",
}


def jaro_winkler(left: str, right: str) -> float:
    """Jaro-Winkler similarity in [0.0, 1.0]."""
    s1, s2 = left.casefold(), right.casefold()
    if s1 == s2:
        return 1.0 if s1 else 0.0
    len1, len2 = len(s1), len(s2)
    if not len1 or not len2:
        return 0.0
    match_distance = max(len1, len2) // 2 - 1
    if match_distance < 0:
        match_distance = 0
    s1_matches = [False] * len1
    s2_matches = [False] * len2
    matches = 0
    transpositions = 0
    for i in range(len1):
        start = max(0, i - match_distance)
        end = min(i + match_distance + 1, len2)
        for j in range(start, end):
            if s2_matches[j] or s1[i] != s2[j]:
                continue
            s1_matches[i] = True
            s2_matches[j] = True
            matches += 1
            break
    if not matches:
        return 0.0
    k = 0
    for i in range(len1):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1
    jaro = (matches / len1 + matches / len2 + (matches - transpositions / 2) / matches) / 3.0
    prefix = 0
    for c1, c2 in zip(s1[:4], s2[:4], strict=False):
        if c1 == c2:
            prefix += 1
        else:
            break
    return jaro + prefix * 0.1 * (1.0 - jaro)


def _handle_similarity_signal(a: Profile, b: Profile, reasons: list[str]) -> float:
    if "@" in a.username or "@" in b.username:
        return 0.0
    ua = a.username.strip().lstrip("@").casefold()
    ub = b.username.strip().lstrip("@").casefold()
    if not ua or not ub or ua == ub or min(len(ua), len(ub)) < 5:
        return 0.0
    stripped_a = re.sub(r"[._-]+", "", ua)
    stripped_b = re.sub(r"[._-]+", "", ub)
    if stripped_a == stripped_b and len(stripped_a) >= 5:
        reasons.append(f"normalized handle match ({a.username} ~ {b.username})")
        return 0.2
    sim = jaro_winkler(ua, ub)
    if sim >= 0.92:
        reasons.append(f"similar handles ({sim:.2f})")
        return 0.15
    return 0.0


def _extracted_entity_signal(a: Profile, b: Profile, reasons: list[str]) -> float:
    # Entities extracted from profile bios / fields (e.g. emails, crypto addresses, discord handles)
    ents_a = a.extra.get("extracted_entities") or []
    ents_b = b.extra.get("extracted_entities") or []
    if not ents_a or not ents_b:
        return 0.0
    keys_a = {
        (e.get("kind"), e.get("value", "").casefold())
        for e in ents_a
        if isinstance(e, dict) and e.get("kind") in STRONG_ENTITY_KINDS
    }
    keys_b = {
        (e.get("kind"), e.get("value", "").casefold())
        for e in ents_b
        if isinstance(e, dict) and e.get("kind") in STRONG_ENTITY_KINDS
    }
    shared = keys_a & keys_b
    if not shared:
        return 0.0
    for kind, val in shared:
        reasons.append(f"shared extracted {kind} ({val})")
    return 0.8


def _avatar_signal(a: Profile, b: Profile) -> tuple[float, str | None]:
    key_a, key_b = _avatar_key(a.avatar), _avatar_key(b.avatar)
    if not key_a or not key_b:
        return 0.0, None
    if key_a == key_b:
        return 0.9, "same avatar"
    if a.avatar_hash and b.avatar_hash:
        distance = hamming_hex(a.avatar_hash, b.avatar_hash)
        if distance <= AVATAR_MAX_DISTANCE:
            return 0.85, f"perceptual avatar match (distance {distance})"
    return 0.0, None


def _avatar_key(url: str | None) -> str:
    if not url:
        return ""
    low = url.casefold()
    if any(marker in low for marker in AVATAR_DENY):
        return ""
    return norm_url(url, preserve_query=True)


def _website_key(url: str | None) -> str:
    normalized = norm_url(url, preserve_query=True)
    if not normalized:
        return ""
    host, _, path = normalized.partition("/")
    if host in GENERIC_HOSTS and not path:
        return ""
    return normalized


def _bio_signal(a: Profile, b: Profile) -> tuple[float, str | None]:
    bio_a, bio_b = norm(a.bio), norm(b.bio)
    tokens_a, tokens_b = _distinctive(bio_a), _distinctive(bio_b)
    if bio_a and bio_a == bio_b and len(bio_a) >= BIO_MIN and len(tokens_a) >= 3:
        return 0.7, "identical bio"
    if len(tokens_a) >= 3 and len(tokens_b) >= 3:
        overlap = _jaccard(tokens_a, tokens_b)
        if overlap >= 0.7:
            return 0.5, f"{overlap:.0%} bio overlap"
    return 0.0, None


def _distinctive(text: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9_]{3,}", text)
        if token not in STOPWORDS and token not in PLATFORM_WORDS and not token.isdigit()
    }


def _mentions(username: str, text: str | None) -> bool:
    handle = (username or "").strip().lstrip("@")
    if len(handle) < 4 or not text:
        return False
    return bool(re.search(rf"(?<!\w){re.escape(handle)}(?!\w)", text, re.IGNORECASE))


def _jaccard(left: set[str], right: set[str]) -> float:
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def _timezone_signal(a: Profile, b: Profile, reasons: list[str]) -> float:
    if not a.timezone or not b.timezone:
        return 0.0
    offset_a, offset_b = _offset_hours(a.timezone), _offset_hours(b.timezone)
    if offset_a is None or offset_b is None:
        return 0.0
    delta = abs(offset_a - offset_b)
    if delta <= 1:
        reasons.append("same inferred timezone")
        return 0.1
    if delta >= 4:
        return -0.1
    return 0.0


def _language_signal(a: Profile, b: Profile, reasons: list[str]) -> float:
    if a.lang and b.lang and a.lang != b.lang:
        return -0.05
    if a.lang and a.lang == b.lang:
        reasons.append(f"same language ({a.lang})")
        return 0.05
    return 0.0


def _offset_hours(value: str) -> float | None:
    match = re.match(r"^([+-])(\d{2}):?(\d{2})?$", value.strip())
    if not match:
        return None
    sign = 1 if match.group(1) == "+" else -1
    return sign * (int(match.group(2)) + int(match.group(3) or 0) / 60)


def creation_spread(profiles: list[Profile]) -> float | None:
    dates = [parse_dt(p.created_at) for p in profiles]
    valid = [date for date in dates if date is not None]
    if len(valid) < 2:
        return None
    return (max(valid) - min(valid)).total_seconds() / 86_400


def recluster_rows(
    rows: list[dict], threshold: float = THRESHOLD
) -> tuple[list[Link], list[Cluster]]:
    """Convert stored profile dicts into Profile models (deduped by source:username)
    and run correlation + clustering across them."""
    seen: dict[tuple[str, str], Profile] = {}
    for row in rows:
        key = (str(row["source"]), str(row["username"]).casefold())
        if key in seen:
            continue
        seen[key] = Profile(
            source=row["source"],
            username=row["username"],
            url=row["url"],
            display_name=row.get("display_name"),
            bio=row.get("bio"),
            avatar=row.get("avatar"),
            avatar_hash=row.get("avatar_hash"),
            website=row.get("website"),
            created_at=row.get("created_at"),
            followers=row.get("followers"),
            lang=row.get("lang"),
            timezone=row.get("timezone"),
            extra=row.get("extra") or {},
        )
    profiles = list(seen.values())
    links = correlate(profiles, threshold=threshold)
    clusters = build_clusters(profiles, links, threshold=threshold)
    return links, clusters
