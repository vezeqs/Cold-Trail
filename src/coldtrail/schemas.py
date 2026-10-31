"""JSON Schema contracts for the payloads emitted by ``--json`` and the web API.

Downstream tooling can validate a payload with any draft-2020-12 validator:

    coldtrail pivot alice --json > pivot.json
    coldtrail schema pivot > pivot.schema.json
"""

from __future__ import annotations

from typing import Any

DIALECT = "https://json-schema.org/draft/2020-12/schema"

_PROFILE: dict[str, Any] = {
    "type": "object",
    "required": ["source", "username", "url"],
    "properties": {
        "source": {"type": "string"},
        "username": {"type": "string"},
        "url": {"type": "string"},
        "display_name": {"type": ["string", "null"]},
        "bio": {"type": ["string", "null"]},
        "avatar": {"type": ["string", "null"]},
        "avatar_hash": {"type": ["string", "null"]},
        "website": {"type": ["string", "null"]},
        "created_at": {"type": ["string", "null"]},
        "followers": {"type": ["integer", "null"]},
        "lang": {"type": ["string", "null"]},
        "timezone": {"type": ["string", "null"]},
        "extra": {"type": "object"},
    },
    "additionalProperties": True,
}

_CHECK: dict[str, Any] = {
    "type": "object",
    "required": ["source", "target", "status"],
    "properties": {
        "source": {"type": "string"},
        "target": {"type": "string"},
        "status": {"enum": ["found", "not_found", "blocked", "error"]},
        "profile": {"anyOf": [{"$ref": "#/$defs/profile"}, {"type": "null"}]},
        "detail": {"type": ["string", "null"]},
    },
    "additionalProperties": True,
}

_LINK: dict[str, Any] = {
    "type": "object",
    "required": ["a", "b", "score", "reasons"],
    "properties": {
        "a": {"$ref": "#/$defs/profile"},
        "b": {"$ref": "#/$defs/profile"},
        "score": {"type": "number"},
        "reasons": {"type": "array", "items": {"type": "string"}},
    },
    "additionalProperties": True,
}

_CLUSTER: dict[str, Any] = {
    "type": "object",
    "required": ["key", "profiles", "score", "reasons"],
    "properties": {
        "key": {"type": "string"},
        "profiles": {"type": "array", "items": {"$ref": "#/$defs/profile"}},
        "score": {"type": "number"},
        "reasons": {"type": "array", "items": {"type": "string"}},
    },
    "additionalProperties": True,
}

_POST: dict[str, Any] = {
    "type": "object",
    "required": ["source", "username", "post_id", "url"],
    "properties": {
        "source": {"type": "string"},
        "username": {"type": "string"},
        "post_id": {"type": "string"},
        "url": {"type": "string"},
        "created_at": {"type": ["string", "null"]},
        "created_ts": {"type": ["integer", "null"]},
        "text": {"type": ["string", "null"]},
        "metrics": {"type": "object"},
        "fetched_at": {"type": ["string", "null"]},
        "deleted_at": {"type": ["string", "null"]},
    },
    "additionalProperties": True,
}

_ENTITY: dict[str, Any] = {
    "type": "object",
    "required": ["source", "username", "kind", "value"],
    "properties": {
        "source": {"type": "string"},
        "username": {"type": "string"},
        "kind": {"type": "string"},
        "value": {"type": "string"},
        "context": {"type": ["string", "null"]},
    },
    "additionalProperties": True,
}

_STORED_LINK: dict[str, Any] = {
    "type": "object",
    "required": ["source_a", "username_a", "source_b", "username_b", "score"],
    "properties": {
        "source_a": {"type": "string"},
        "username_a": {"type": "string"},
        "source_b": {"type": "string"},
        "username_b": {"type": "string"},
        "score": {"type": "number"},
        "reasons": {"type": "array", "items": {"type": "string"}},
    },
    "additionalProperties": True,
}

_STORED_CLUSTER: dict[str, Any] = {
    "type": "object",
    "required": ["cluster_key", "score", "size"],
    "properties": {
        "cluster_key": {"type": "string"},
        "score": {"type": "number"},
        "size": {"type": "integer"},
        "reasons": {"type": "array", "items": {"type": "string"}},
        "members": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["source", "username"],
                "properties": {
                    "source": {"type": "string"},
                    "username": {"type": "string"},
                },
            },
        },
    },
    "additionalProperties": True,
}

_EDGE: dict[str, Any] = {
    "type": "object",
    "required": ["platform", "actor", "target", "direction"],
    "properties": {
        "platform": {"type": "string"},
        "actor": {"type": "string"},
        "target": {"type": "string"},
        "direction": {"type": "string"},
    },
    "additionalProperties": True,
}

_HISTORY: dict[str, Any] = {
    "type": "object",
    "required": ["source", "username", "field", "observed_at"],
    "properties": {
        "source": {"type": "string"},
        "username": {"type": "string"},
        "field": {"type": "string"},
        "old_value": {"type": ["string", "null"]},
        "new_value": {"type": ["string", "null"]},
        "observed_at": {"type": "string"},
    },
    "additionalProperties": True,
}

_ATTACHMENT: dict[str, Any] = {
    "type": "object",
    "required": ["id", "sha256", "filename", "size"],
    "properties": {
        "id": {"type": "integer"},
        "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "filename": {"type": "string"},
        "media_type": {"type": ["string", "null"]},
        "size": {"type": "integer"},
        "note": {"type": ["string", "null"]},
        "created_at": {"type": "string"},
    },
    "additionalProperties": True,
}

_RUN_ROW: dict[str, Any] = {
    "type": "object",
    "required": ["id", "kind", "target", "started_at", "status"],
    "properties": {
        "id": {"type": "integer"},
        "kind": {"type": "string"},
        "target": {"type": "string"},
        "started_at": {"type": "string"},
        "finished_at": {"type": ["string", "null"]},
        "status": {"type": "string"},
    },
    "additionalProperties": True,
}

SCHEMAS: dict[str, dict[str, Any]] = {
    "pivot": {
        "$schema": DIALECT,
        "$id": "https://coldtrail.dev/schemas/pivot.json",
        "title": "ColdTrail pivot report",
        "type": "object",
        "required": ["target", "kind", "results", "links", "expanded", "clusters", "coverage"],
        "properties": {
            "target": {"type": "string"},
            "kind": {"enum": ["username", "email"]},
            "results": {"type": "array", "items": {"$ref": "#/$defs/check"}},
            "links": {"type": "array", "items": {"$ref": "#/$defs/link"}},
            "expanded": {"type": "array", "items": {"type": "string"}},
            "clusters": {"type": "array", "items": {"$ref": "#/$defs/cluster"}},
            "coverage": {"type": "object", "additionalProperties": {"type": "integer"}},
            "run_id": {"type": ["integer", "null"]},
        },
        "$defs": {
            "profile": _PROFILE,
            "check": _CHECK,
            "link": _LINK,
            "cluster": _CLUSTER,
        },
    },
    "run": {
        "$schema": DIALECT,
        "$id": "https://coldtrail.dev/schemas/run.json",
        "title": "ColdTrail stored run export",
        "type": "object",
        "required": [
            "run",
            "checks",
            "profiles",
            "posts",
            "links",
            "clusters",
            "entities",
            "edges",
            "history",
            "attachments",
        ],
        "properties": {
            "run": {"$ref": "#/$defs/run"},
            "checks": {"type": "array", "items": {"$ref": "#/$defs/check"}},
            "profiles": {"type": "array", "items": {"$ref": "#/$defs/profile"}},
            "posts": {"type": "array", "items": {"$ref": "#/$defs/post"}},
            "links": {"type": "array", "items": {"$ref": "#/$defs/link"}},
            "clusters": {"type": "array", "items": {"$ref": "#/$defs/cluster"}},
            "entities": {"type": "array", "items": {"$ref": "#/$defs/entity"}},
            "edges": {"type": "array", "items": {"$ref": "#/$defs/edge"}},
            "history": {"type": "array", "items": {"$ref": "#/$defs/history"}},
            "attachments": {"type": "array", "items": {"$ref": "#/$defs/attachment"}},
        },
        "$defs": {
            "run": _RUN_ROW,
            "profile": _PROFILE,
            "check": _CHECK,
            "post": _POST,
            "link": _STORED_LINK,
            "cluster": _STORED_CLUSTER,
            "entity": _ENTITY,
            "edge": _EDGE,
            "history": _HISTORY,
            "attachment": _ATTACHMENT,
        },
    },
    "diff": {
        "$schema": DIALECT,
        "$id": "https://coldtrail.dev/schemas/diff.json",
        "title": "ColdTrail run diff",
        "type": "object",
        "required": ["run_a", "run_b", "profiles", "entities", "links", "clusters", "posts"],
        "properties": {
            "run_a": {"type": "integer"},
            "run_b": {"type": "integer"},
            "profiles": {
                "type": "object",
                "required": ["added", "removed", "changed"],
                "properties": {
                    "added": {"type": "array", "items": {"type": "object"}},
                    "removed": {"type": "array", "items": {"type": "object"}},
                    "changed": {"type": "array", "items": {"type": "object"}},
                },
            },
            "entities": {
                "type": "object",
                "required": ["added", "removed"],
                "properties": {
                    "added": {"type": "array", "items": {"type": "object"}},
                    "removed": {"type": "array", "items": {"type": "object"}},
                },
            },
            "links": {
                "type": "object",
                "required": ["added", "removed"],
                "properties": {
                    "added": {"type": "array", "items": {"type": "object"}},
                    "removed": {"type": "array", "items": {"type": "object"}},
                },
            },
            "clusters": {
                "type": "object",
                "required": ["added", "removed"],
                "properties": {
                    "added": {"type": "array", "items": {"type": "string"}},
                    "removed": {"type": "array", "items": {"type": "string"}},
                },
            },
            "posts": {
                "type": "object",
                "required": ["added", "removed", "tombstoned"],
                "properties": {
                    "added": {"type": "array", "items": {"type": "object"}},
                    "removed": {"type": "array", "items": {"type": "object"}},
                    "tombstoned": {"type": "array", "items": {"type": "object"}},
                },
            },
        },
    },
    "sources": {
        "$schema": DIALECT,
        "$id": "https://coldtrail.dev/schemas/sources.json",
        "title": "ColdTrail source catalogue",
        "type": "array",
        "items": {
            "type": "object",
            "required": ["name", "label", "kind", "group", "posts", "auth", "homepage"],
            "properties": {
                "name": {"type": "string"},
                "label": {"type": "string"},
                "kind": {"enum": ["username", "email"]},
                "group": {"type": "string"},
                "posts": {"type": "boolean"},
                "auth": {"type": "boolean"},
                "homepage": {"type": "string"},
            },
            "additionalProperties": True,
        },
    },
    "doctor": {
        "$schema": DIALECT,
        "$id": "https://coldtrail.dev/schemas/doctor.json",
        "title": "ColdTrail doctor report",
        "type": "object",
        "required": ["db", "stats", "online", "privacy", "health"],
        "properties": {
            "db": {"type": "object"},
            "stats": {"type": "object"},
            "online": {"type": ["boolean", "null"]},
            "privacy": {"type": "object"},
            "health": {"type": "array", "items": {"type": "object"}},
        },
        "additionalProperties": True,
    },
    "config": {
        "$schema": DIALECT,
        "$id": "https://coldtrail.dev/schemas/config.json",
        "title": "ColdTrail effective configuration",
        "type": "object",
        "required": ["config_path", "config_mode", "settings"],
        "properties": {
            "config_path": {"type": ["string", "null"]},
            "config_mode": {"type": ["string", "null"]},
            "settings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["key", "value", "source", "secret"],
                    "properties": {
                        "key": {"type": "string"},
                        "value": {},
                        "source": {"enum": ["default", "config", "env", "flag"]},
                        "secret": {"type": "boolean"},
                    },
                },
            },
        },
    },
    "stats": {
        "$schema": DIALECT,
        "$id": "https://coldtrail.dev/schemas/stats.json",
        "title": "ColdTrail database statistics",
        "type": "object",
        "required": ["stats", "db"],
        "properties": {
            "stats": {"type": "object", "additionalProperties": {"type": "integer"}},
            "db": {"type": "object"},
            "health": {"type": "array", "items": {"type": "object"}},
            "version": {"type": "string"},
        },
    },
}

SCHEMA_NAMES = tuple(sorted(SCHEMAS))
