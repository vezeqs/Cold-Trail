from __future__ import annotations

SCHEMA_VERSION = 4

POSTS_AU_TRIGGER = """CREATE TRIGGER posts_au AFTER UPDATE OF text, username, source ON posts BEGIN
    INSERT INTO posts_fts(posts_fts, rowid, text, username, source)
    VALUES ('delete', old.id, old.text, old.username, old.source);
    INSERT INTO posts_fts(rowid, text, username, source)
    VALUES (new.id, new.text, new.username, new.source);
END"""

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    detail TEXT
);

CREATE TABLE IF NOT EXISTS profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    username TEXT NOT NULL,
    url TEXT NOT NULL,
    display_name TEXT,
    bio TEXT,
    avatar TEXT,
    avatar_hash TEXT,
    website TEXT,
    created_at TEXT,
    followers INTEGER,
    lang TEXT,
    timezone TEXT,
    extra_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(run_id, source, username)
);

CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    username TEXT NOT NULL,
    post_id TEXT NOT NULL,
    url TEXT NOT NULL,
    created_at TEXT,
    text TEXT,
    metrics_json TEXT NOT NULL DEFAULT '{}',
    fetched_at TEXT,
    deleted_at TEXT,
    UNIQUE(run_id, source, post_id)
);

CREATE TABLE IF NOT EXISTS links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    source_a TEXT NOT NULL,
    username_a TEXT NOT NULL,
    source_b TEXT NOT NULL,
    username_b TEXT NOT NULL,
    score REAL NOT NULL,
    reasons_json TEXT NOT NULL DEFAULT '[]',
    UNIQUE(run_id, source_a, username_a, source_b, username_b)
);

CREATE TABLE IF NOT EXISTS clusters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    cluster_key TEXT NOT NULL,
    score REAL NOT NULL,
    size INTEGER NOT NULL,
    reasons_json TEXT NOT NULL DEFAULT '[]',
    UNIQUE(run_id, cluster_key)
);

CREATE TABLE IF NOT EXISTS cluster_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    cluster_key TEXT NOT NULL,
    source TEXT NOT NULL,
    username TEXT NOT NULL,
    UNIQUE(run_id, cluster_key, source, username)
);

CREATE TABLE IF NOT EXISTS entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    username TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    context TEXT,
    UNIQUE(run_id, source, username, kind, value)
);

CREATE INDEX IF NOT EXISTS idx_posts_source_user ON posts(source, username);

CREATE TABLE IF NOT EXISTS edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    platform TEXT NOT NULL,
    actor TEXT NOT NULL,
    target TEXT NOT NULL,
    direction TEXT NOT NULL DEFAULT 'follows',
    UNIQUE(run_id, platform, actor, target, direction)
);

CREATE TABLE IF NOT EXISTS profile_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    username TEXT NOT NULL,
    field TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    observed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cursors (
    source TEXT NOT NULL,
    username TEXT NOT NULL,
    cursor TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    PRIMARY KEY (source, username)
);

CREATE TABLE IF NOT EXISTS http_cache (
    url TEXT PRIMARY KEY,
    status INTEGER NOT NULL,
    content_type TEXT,
    etag TEXT,
    last_modified TEXT,
    body BLOB NOT NULL,
    fetched_at TEXT NOT NULL,
    final_url TEXT
);

CREATE TABLE IF NOT EXISTS raw (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    status INTEGER NOT NULL,
    body BLOB NOT NULL,
    fetched_at TEXT NOT NULL,
    run_id INTEGER
);

CREATE TABLE IF NOT EXISTS probe_cache (
    source TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    detail TEXT,
    checked_at TEXT NOT NULL,
    PRIMARY KEY (source, target)
);

CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    command TEXT NOT NULL,
    target TEXT,
    args_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS case_runs (
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    PRIMARY KEY (case_id, run_id)
);

CREATE TABLE IF NOT EXISTS tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_type TEXT NOT NULL,
    target TEXT NOT NULL,
    tag TEXT NOT NULL,
    UNIQUE(target_type, target, tag)
);

CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_type TEXT NOT NULL,
    target TEXT NOT NULL,
    note TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER REFERENCES runs(id) ON DELETE SET NULL,
    target_type TEXT NOT NULL DEFAULT 'run',
    target TEXT,
    sha256 TEXT NOT NULL,
    filename TEXT NOT NULL,
    media_type TEXT,
    size INTEGER NOT NULL,
    note TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_attachments_run ON attachments(run_id);
CREATE INDEX IF NOT EXISTS idx_attachments_sha ON attachments(sha256);
CREATE INDEX IF NOT EXISTS idx_attachments_target ON attachments(target_type, target);

CREATE INDEX IF NOT EXISTS idx_checks_run ON checks(run_id);
CREATE INDEX IF NOT EXISTS idx_checks_source ON checks(source);
CREATE INDEX IF NOT EXISTS idx_profiles_run ON profiles(run_id);
CREATE INDEX IF NOT EXISTS idx_profiles_username ON profiles(username);
CREATE INDEX IF NOT EXISTS idx_posts_run ON posts(run_id);
CREATE INDEX IF NOT EXISTS idx_posts_username ON posts(username);
CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at);
CREATE INDEX IF NOT EXISTS idx_links_run ON links(run_id);
CREATE INDEX IF NOT EXISTS idx_entities_value ON entities(value);
CREATE INDEX IF NOT EXISTS idx_edges_actor ON edges(actor);
CREATE INDEX IF NOT EXISTS idx_history_target ON profile_history(source, username);
CREATE INDEX IF NOT EXISTS idx_raw_url ON raw(url);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit(at);
"""

FTS = """
CREATE VIRTUAL TABLE IF NOT EXISTS posts_fts USING fts5(
    text, username, source, content='posts', content_rowid='id'
);
CREATE TRIGGER IF NOT EXISTS posts_ai AFTER INSERT ON posts BEGIN
    INSERT INTO posts_fts(rowid, text, username, source)
    VALUES (new.id, new.text, new.username, new.source);
END;
CREATE TRIGGER IF NOT EXISTS posts_ad AFTER DELETE ON posts BEGIN
    INSERT INTO posts_fts(posts_fts, rowid, text, username, source)
    VALUES ('delete', old.id, old.text, old.username, old.source);
END;
"""

COLUMNS = {
    "profiles": {
        "avatar_hash": "TEXT",
        "lang": "TEXT",
        "timezone": "TEXT",
    },
    "posts": {
        "fetched_at": "TEXT",
        "deleted_at": "TEXT",
    },
    "http_cache": {
        "final_url": "TEXT",
    },
}
