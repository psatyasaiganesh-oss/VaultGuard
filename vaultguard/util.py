"""Small cryptographic, JSON, time, and path helpers."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .errors import SecurityError, ValidationError

DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
SNAPSHOT_RE = re.compile(r"^[0-9a-f]{32}$")


def canonical_json(value: Any) -> bytes:
    """Return the one JSON encoding used for hashes and durable metadata."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_utc(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValidationError("timestamp must be a string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"invalid UTC timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ValidationError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def utc_text(value: datetime | None = None) -> str:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValidationError("datetime must be timezone-aware")
    return current.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def validate_digest(value: str) -> str:
    if not isinstance(value, str) or not DIGEST_RE.fullmatch(value):
        raise ValidationError("invalid SHA-256 digest")
    return value


def validate_snapshot_id(value: str) -> str:
    if not isinstance(value, str) or not SNAPSHOT_RE.fullmatch(value):
        raise ValidationError("snapshot id must be 32 lowercase hexadecimal characters")
    return value


def validate_relative_path(value: str) -> str:
    """Validate the canonical POSIX path stored in a manifest."""

    if not isinstance(value, str) or not value or len(value) > 4096:
        raise SecurityError("manifest path must be a non-empty string up to 4096 chars")
    if "\x00" in value or "\\" in value or value.startswith("/"):
        raise SecurityError(f"unsafe manifest path: {value!r}")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise SecurityError(f"unsafe manifest path: {value!r}")
    return value


def ensure_plain_directory(path: Path, *, create: bool = False) -> Path:
    """Resolve a directory without accepting a symlink at the final component."""

    absolute = path.expanduser().absolute()
    if absolute.is_symlink():
        raise SecurityError(f"symlink directories are not accepted: {absolute}")
    if create:
        absolute.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not absolute.exists() or not absolute.is_dir():
        raise ValidationError(f"directory does not exist: {absolute}")
    return absolute.resolve()


def is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def validate_source_tree(root: Path) -> list[Path]:
    """Return regular files in deterministic order and reject every symlink/special file."""

    root = ensure_plain_directory(root)
    files: list[Path] = []
    for directory, dir_names, file_names in os.walk(root, followlinks=False):
        base = Path(directory)
        dir_names.sort()
        file_names.sort()
        for name in list(dir_names):
            candidate = base / name
            mode = candidate.lstat().st_mode
            if stat.S_ISLNK(mode):
                raise SecurityError(f"source contains a symlink directory: {candidate}")
            if not stat.S_ISDIR(mode):
                raise SecurityError(f"source contains a special directory entry: {candidate}")
        for name in file_names:
            candidate = base / name
            mode = candidate.lstat().st_mode
            if stat.S_ISLNK(mode):
                raise SecurityError(f"source contains a symlink file: {candidate}")
            if not stat.S_ISREG(mode):
                raise SecurityError(f"source contains a non-regular file: {candidate}")
            validate_relative_path(candidate.relative_to(root).as_posix())
            files.append(candidate)
    return sorted(files, key=lambda item: item.relative_to(root).as_posix())


def merkle_root(leaves: Iterable[bytes]) -> str:
    """Build a binary SHA-256 Merkle root, duplicating an odd final node."""

    level = [hashlib.sha256(b"leaf\x00" + leaf).digest() for leaf in leaves]
    if not level:
        return hashlib.sha256(b"empty-merkle-tree").hexdigest()
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(b"node\x00" + level[index] + level[index + 1]).digest()
            for index in range(0, len(level), 2)
        ]
    return level[0].hex()


def file_tree_fingerprint(root: Path) -> str:
    """Hash relative paths, modes, sizes, and content for demo/test comparisons."""

    root = ensure_plain_directory(root)
    leaves: list[bytes] = []
    for file_path in validate_source_tree(root):
        relative = file_path.relative_to(root).as_posix()
        hasher = hashlib.sha256()
        with file_path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                hasher.update(block)
        entry = {
            "digest": hasher.hexdigest(),
            "mode": stat.S_IMODE(file_path.stat().st_mode),
            "path": relative,
            "size": file_path.stat().st_size,
        }
        leaves.append(canonical_json(entry))
    return merkle_root(leaves)
