"""Content-addressed evidence storage.

Evidence bytes live under ``<database dir>/evidence/<sha[:2]>/<sha>`` so the
same file is stored once no matter how many runs reference it. SQLite holds the
metadata row (attachments) and the SHA-256 lets us verify integrity later.
"""

from __future__ import annotations

import contextlib
import hashlib
import mimetypes
import os
import tempfile
from pathlib import Path
from typing import Any

from .store import Store
from .utils import is_sha256


def evidence_root(db_path: Path) -> Path:
    return Path(db_path).expanduser().parent / "evidence"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _store_blob(root: Path, digest: str, data: bytes) -> Path:
    if not is_sha256(digest):
        raise ValueError(f"invalid evidence digest: {digest!r}")
    directory = root / digest[:2]
    directory.mkdir(parents=True, exist_ok=True)
    for folder in (root, directory):
        with contextlib.suppress(OSError):
            os.chmod(folder, 0o700)
    destination = directory / digest
    if destination.is_file():
        with contextlib.suppress(OSError):
            os.chmod(destination, 0o600)
        return destination
    with tempfile.NamedTemporaryFile(dir=directory, delete=False) as handle:
        handle.write(data)
        temp_path = Path(handle.name)
    with contextlib.suppress(OSError):
        os.chmod(temp_path, 0o600)
    os.replace(temp_path, destination)
    with contextlib.suppress(OSError):
        os.chmod(destination, 0o600)
    return destination


def _store_blob_from_path(root: Path, path: Path) -> tuple[str, int]:
    """Stream *path* into a content-addressed blob without loading it into RAM."""
    root.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(root, 0o700)
    digest = hashlib.sha256()
    size = 0
    # The temp file lives under the evidence root so the final rename stays on
    # one filesystem (os.replace across mounts raises EXDEV).
    with tempfile.NamedTemporaryFile(dir=root, delete=False) as handle:
        temp_path = Path(handle.name)
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
                handle.write(chunk)
    hexdigest = digest.hexdigest()
    directory = root / hexdigest[:2]
    try:
        directory.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            os.chmod(directory, 0o700)
        destination = directory / hexdigest
        if destination.is_file():
            with contextlib.suppress(OSError):
                os.chmod(destination, 0o600)
            temp_path.unlink(missing_ok=True)
            return hexdigest, size
        with contextlib.suppress(OSError):
            os.chmod(temp_path, 0o600)
        os.replace(temp_path, destination)
    except OSError:
        temp_path.unlink(missing_ok=True)
        raise
    with contextlib.suppress(OSError):
        os.chmod(destination, 0o600)
    return hexdigest, size


def add_evidence(
    store: Store,
    *,
    data: bytes | None = None,
    source_path: Path | None = None,
    filename: str | None = None,
    media_type: str | None = None,
    run_id: int | None = None,
    target_type: str = "run",
    target: str | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    """Store a file (or bytes) content-addressed and record metadata."""
    if data is None and source_path is None:
        raise ValueError("provide data or source_path")
    root = evidence_root(store.path)
    if data is None:
        if source_path is None:
            raise ValueError("provide data or source_path")
        source_path = Path(source_path)
        if not source_path.is_file():
            raise ValueError(f"not a file: {source_path}")
        digest, size = _store_blob_from_path(root, source_path)
        filename = filename or source_path.name
    else:
        digest = _sha256_bytes(data)
        size = len(data)
        _store_blob(root, digest, data)
    filename = filename or "evidence.bin"
    media_type = media_type or mimetypes.guess_type(filename)[0] or "application/octet-stream"
    attachment_id = store.add_attachment(
        run_id=run_id,
        target_type=target_type,
        target=target,
        sha256=digest,
        filename=filename,
        media_type=media_type,
        size=size,
        note=note,
    )
    return {
        "id": attachment_id,
        "sha256": digest,
        "filename": filename,
        "media_type": media_type,
        "size": size,
        "path": str(root / digest[:2] / digest),
        "run_id": run_id,
        "target_type": target_type,
        "target": target,
        "note": note,
    }


def evidence_path(store: Store, sha256: str) -> Path:
    if not is_sha256(sha256):
        raise ValueError(f"invalid evidence digest: {sha256!r}")
    return evidence_root(store.path) / sha256[:2] / sha256


def verify_evidence(store: Store, page_size: int = 1000) -> list[dict[str, Any]]:
    """Return problems for attachments whose blob is missing or corrupted.

    Pages through the table so a large evidence store is not loaded at once.
    """
    problems: list[dict[str, Any]] = []
    offset = 0
    while True:
        rows = store.attachments(limit=page_size, offset=offset)
        if not rows:
            break
        for row in rows:
            if not is_sha256(row["sha256"]):
                problems.append(
                    {"id": row["id"], "sha256": row["sha256"], "problem": "invalid digest"}
                )
                continue
            path = evidence_path(store, row["sha256"])
            if not path.is_file():
                problems.append(
                    {"id": row["id"], "sha256": row["sha256"], "problem": "missing file"}
                )
                continue
            actual = _sha256_file(path)
            if actual != row["sha256"]:
                problems.append(
                    {
                        "id": row["id"],
                        "sha256": row["sha256"],
                        "problem": f"hash mismatch ({actual})",
                    }
                )
        offset += len(rows)
    return problems
