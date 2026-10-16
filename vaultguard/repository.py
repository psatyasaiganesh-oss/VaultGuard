"""Transactional snapshot metadata plus content-addressed primary/mirror storage."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import uuid
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from .errors import (
    CorruptionError,
    NotFoundError,
    RepositoryError,
    RetentionError,
    SecurityError,
    ValidationError,
)
from .util import (
    canonical_json,
    ensure_plain_directory,
    is_relative_to,
    merkle_root,
    parse_utc,
    sha256_bytes,
    utc_text,
    validate_digest,
    validate_relative_path,
    validate_snapshot_id,
    validate_source_tree,
)

SCHEMA_VERSION = 1
MIN_CHUNK_SIZE = 512
MAX_CHUNK_SIZE = 8 * 1024 * 1024
MAX_RETENTION_SECONDS = 10 * 365 * 24 * 60 * 60
MAX_MANIFEST_BYTES = 64 * 1024 * 1024


class VaultRepository:
    """A local backup repository with integrity verification and mirror repair."""

    def __init__(self, root: str | os.PathLike[str]):
        candidate = Path(root).expanduser().absolute()
        if candidate.is_symlink():
            raise SecurityError(f"repository cannot be a symlink: {candidate}")
        if not candidate.is_dir():
            raise RepositoryError(f"repository does not exist: {candidate}")
        self.root = candidate.resolve()
        self.config_path = self.root / "config.json"
        self.database_path = self.root / "metadata.sqlite3"
        self.manifests_dir = self.root / "manifests"
        self.primary_dir = self.root / "chunks" / "primary"
        self.mirror_dir = self.root / "chunks" / "mirror"
        self._config = self._load_config()
        self.chunk_size = int(self._config["chunk_size"])
        if not self.database_path.is_file():
            raise RepositoryError("repository metadata database is missing")
        for required in (self.manifests_dir, self.primary_dir, self.mirror_dir):
            if required.is_symlink() or not required.is_dir():
                raise RepositoryError(f"repository directory is missing or unsafe: {required}")

    @classmethod
    def initialize(
        cls,
        root: str | os.PathLike[str],
        *,
        chunk_size: int = 4096,
        now: datetime | None = None,
    ) -> "VaultRepository":
        if not isinstance(chunk_size, int) or isinstance(chunk_size, bool):
            raise ValidationError("chunk size must be an integer")
        if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
            raise ValidationError(
                f"chunk size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE} bytes"
            )
        target = Path(root).expanduser().absolute()
        if target.is_symlink():
            raise SecurityError(f"repository cannot be a symlink: {target}")
        if target.exists() and (not target.is_dir() or any(target.iterdir())):
            raise RepositoryError("repository path must be absent or an empty directory")
        target.mkdir(parents=True, exist_ok=True, mode=0o700)
        target = target.resolve()
        for relative in ("manifests", "chunks/primary", "chunks/mirror"):
            (target / relative).mkdir(parents=True, mode=0o700)

        created_at = utc_text(now)
        config = {
            "chunk_size": chunk_size,
            "created_at": created_at,
            "repository_id": str(uuid.uuid4()),
            "schema_version": SCHEMA_VERSION,
        }
        cls._write_atomic_file(target / "config.json", canonical_json(config), exclusive=True)
        database = target / "metadata.sqlite3"
        connection = sqlite3.connect(database)
        try:
            connection.executescript(
                """
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = FULL;
                PRAGMA foreign_keys = ON;
                CREATE TABLE metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    source_label TEXT NOT NULL,
                    retained_until TEXT NOT NULL,
                    manifest_digest TEXT NOT NULL,
                    merkle_root TEXT NOT NULL,
                    logical_bytes INTEGER NOT NULL CHECK (logical_bytes >= 0),
                    file_count INTEGER NOT NULL CHECK (file_count >= 0),
                    status TEXT NOT NULL CHECK (status IN ('active', 'deleted')),
                    deleted_at TEXT
                );
                CREATE TABLE chunks (
                    digest TEXT PRIMARY KEY,
                    size INTEGER NOT NULL CHECK (size >= 0),
                    ref_count INTEGER NOT NULL CHECK (ref_count >= 0)
                );
                CREATE TABLE audit (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    recorded_at TEXT NOT NULL,
                    event TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE
                );
                """
            )
            connection.executemany(
                "INSERT INTO metadata(key, value) VALUES (?, ?)",
                (("schema_version", str(SCHEMA_VERSION)), ("audit_count", "0"), ("audit_head", "")),
            )
            cls._append_audit(
                connection,
                "repository_initialized",
                {"chunk_size": chunk_size, "repository_id": config["repository_id"]},
                created_at,
            )
            connection.commit()
        finally:
            connection.close()
        os.chmod(database, 0o600)
        return cls(target)

    def backup(
        self,
        source: str | os.PathLike[str],
        *,
        retain_seconds: int = 86_400,
        label: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Create an immutable snapshot manifest and store any unseen chunks."""

        if not isinstance(retain_seconds, int) or isinstance(retain_seconds, bool):
            raise ValidationError("retention must be an integer number of seconds")
        if not 0 <= retain_seconds <= MAX_RETENTION_SECONDS:
            raise ValidationError(
                f"retention must be between 0 and {MAX_RETENTION_SECONDS} seconds"
            )
        source_root = ensure_plain_directory(Path(source))
        if is_relative_to(source_root, self.root) or is_relative_to(self.root, source_root):
            raise SecurityError("source and repository directories must not overlap")
        source_label = label if label is not None else source_root.name
        if not isinstance(source_label, str) or not source_label.strip() or len(source_label) > 200:
            raise ValidationError("label must contain 1 to 200 characters")

        current = self._utc_now(now)
        created_at = utc_text(current)
        retained_until = utc_text(current + timedelta(seconds=retain_seconds))
        files = validate_source_tree(source_root)
        manifest_files: list[dict[str, Any]] = []
        references: Counter[str] = Counter()
        chunk_sizes: dict[str, int] = {}
        logical_bytes = 0

        for path in files:
            entry = self._capture_file(source_root, path)
            manifest_files.append(entry)
            logical_bytes += int(entry["size"])
            for chunk in entry["chunks"]:
                digest = str(chunk["digest"])
                references[digest] += 1
                chunk_sizes[digest] = int(chunk["size"])

        root_hash = merkle_root(canonical_json(entry) for entry in manifest_files)
        manifest: dict[str, Any] = {
            "chunk_size": self.chunk_size,
            "created_at": created_at,
            "files": manifest_files,
            "logical_bytes": logical_bytes,
            "merkle_root": root_hash,
            "retained_until": retained_until,
            "schema_version": SCHEMA_VERSION,
            "source_label": source_label.strip(),
        }
        manifest_bytes = canonical_json(manifest)
        manifest_digest = sha256_bytes(manifest_bytes)
        snapshot_id = manifest_digest[:32]
        manifest_path = self.manifests_dir / f"{snapshot_id}.json"

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            collision = connection.execute(
                "SELECT 1 FROM snapshots WHERE snapshot_id = ?", (snapshot_id,)
            ).fetchone()
            if collision:
                raise RepositoryError(
                    "an identical snapshot identifier already exists; retry with a later timestamp"
                )
            existing = {
                row[0]
                for row in connection.execute(
                    "SELECT digest FROM chunks WHERE digest IN ({})".format(
                        ",".join("?" for _ in references) or "NULL"
                    ),
                    tuple(references),
                )
            }
            newly_stored_bytes = sum(
                chunk_sizes[digest] for digest in references if digest not in existing
            )
            self._write_atomic_file(manifest_path, manifest_bytes, exclusive=True)
            for digest, count in references.items():
                size = chunk_sizes[digest]
                row = connection.execute(
                    "SELECT size FROM chunks WHERE digest = ?", (digest,)
                ).fetchone()
                if row is None:
                    connection.execute(
                        "INSERT INTO chunks(digest, size, ref_count) VALUES (?, ?, ?)",
                        (digest, size, count),
                    )
                else:
                    if int(row[0]) != size:
                        raise CorruptionError(f"chunk metadata size mismatch for {digest}")
                    connection.execute(
                        "UPDATE chunks SET ref_count = ref_count + ? WHERE digest = ?",
                        (count, digest),
                    )
            connection.execute(
                """
                INSERT INTO snapshots(
                    snapshot_id, created_at, source_label, retained_until,
                    manifest_digest, merkle_root, logical_bytes, file_count, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active')
                """,
                (
                    snapshot_id,
                    created_at,
                    source_label.strip(),
                    retained_until,
                    manifest_digest,
                    root_hash,
                    logical_bytes,
                    len(manifest_files),
                ),
            )
            self._append_audit(
                connection,
                "snapshot_created",
                {
                    "file_count": len(manifest_files),
                    "logical_bytes": logical_bytes,
                    "manifest_digest": manifest_digest,
                    "retained_until": retained_until,
                    "snapshot_id": snapshot_id,
                },
                created_at,
            )

        return {
            "chunk_references": sum(references.values()),
            "created_at": created_at,
            "file_count": len(manifest_files),
            "logical_bytes": logical_bytes,
            "merkle_root": root_hash,
            "new_chunk_bytes": newly_stored_bytes,
            "retained_until": retained_until,
            "snapshot_id": snapshot_id,
            "unique_chunks": len(references),
        }

    def list_snapshots(self, *, include_deleted: bool = False) -> list[dict[str, Any]]:
        where = "" if include_deleted else "WHERE status = 'active'"
        with self._connect() as connection:
            rows = connection.execute(
                f"""
                SELECT snapshot_id, created_at, source_label, retained_until,
                       logical_bytes, file_count, status, deleted_at, merkle_root
                FROM snapshots {where} ORDER BY created_at, snapshot_id
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def verify_snapshot(self, snapshot_id: str, *, repair: bool = False) -> dict[str, Any]:
        """Validate a manifest, every referenced chunk, and every reconstructed file hash."""

        snapshot_id = validate_snapshot_id(snapshot_id)
        row = self._snapshot_row(snapshot_id)
        problems: list[dict[str, str]] = []
        repaired: list[str] = []
        try:
            manifest, manifest_bytes = self._read_manifest(snapshot_id)
            self._validate_manifest(manifest)
        except (OSError, ValueError, ValidationError, SecurityError) as exc:
            return {
                "bytes_checked": 0,
                "files_checked": 0,
                "manifest_ok": False,
                "ok": False,
                "problems": [{"kind": "manifest", "detail": str(exc)}],
                "repaired_chunks": 0,
                "snapshot_id": snapshot_id,
                "unique_chunks_checked": 0,
            }

        computed_manifest_digest = sha256_bytes(manifest_bytes)
        if computed_manifest_digest != row["manifest_digest"]:
            problems.append({"kind": "manifest_digest", "detail": "manifest digest mismatch"})
        if computed_manifest_digest[:32] != snapshot_id:
            problems.append({"kind": "snapshot_id", "detail": "snapshot id does not match manifest"})
        if manifest["merkle_root"] != row["merkle_root"]:
            problems.append({"kind": "merkle_root", "detail": "database Merkle root mismatch"})

        chunk_map: dict[str, int] = {}
        for entry in manifest["files"]:
            for chunk in entry["chunks"]:
                chunk_map[str(chunk["digest"])] = int(chunk["size"])

        valid_primary: set[str] = set()
        for digest, size in sorted(chunk_map.items()):
            primary_path = self._chunk_path(self.primary_dir, digest)
            mirror_path = self._chunk_path(self.mirror_dir, digest)
            primary_state = self._chunk_state(primary_path, digest, size)
            mirror_state = self._chunk_state(mirror_path, digest, size)
            if primary_state == "ok":
                valid_primary.add(digest)
            if primary_state == "ok" and mirror_state == "ok":
                continue
            if primary_state != "ok" and mirror_state == "ok":
                if repair:
                    mirror_data = mirror_path.read_bytes()
                    if len(mirror_data) != size or sha256_bytes(mirror_data) != digest:
                        problems.append(
                            {
                                "kind": f"primary_{primary_state}",
                                "detail": f"{digest}; mirror changed during repair",
                            }
                        )
                        continue
                    self._write_atomic_file(primary_path, mirror_data, exclusive=False)
                    repaired.append(digest)
                    valid_primary.add(digest)
                else:
                    problems.append({"kind": f"primary_{primary_state}", "detail": digest})
                continue
            if primary_state == "ok" and mirror_state != "ok":
                if repair:
                    primary_data = primary_path.read_bytes()
                    if len(primary_data) != size or sha256_bytes(primary_data) != digest:
                        valid_primary.discard(digest)
                        problems.append(
                            {
                                "kind": f"mirror_{mirror_state}",
                                "detail": f"{digest}; primary changed during repair",
                            }
                        )
                        continue
                    self._write_atomic_file(mirror_path, primary_data, exclusive=False)
                    repaired.append(digest)
                else:
                    problems.append({"kind": f"mirror_{mirror_state}", "detail": digest})
                continue
            if primary_state != "ok" and mirror_state != "ok":
                problems.append(
                    {
                        "kind": f"primary_{primary_state}",
                        "detail": f"{digest}; mirror_{mirror_state}",
                    }
                )

        bytes_checked = 0
        files_checked = 0
        for entry in manifest["files"]:
            if any(str(chunk["digest"]) not in valid_primary for chunk in entry["chunks"]):
                continue
            hasher = hashlib.sha256()
            reconstructed_size = 0
            for chunk in entry["chunks"]:
                data = self._chunk_path(self.primary_dir, str(chunk["digest"])).read_bytes()
                hasher.update(data)
                reconstructed_size += len(data)
            bytes_checked += reconstructed_size
            files_checked += 1
            if reconstructed_size != int(entry["size"]):
                problems.append(
                    {"kind": "file_size", "detail": f"{entry['path']}: reconstructed size mismatch"}
                )
            if hasher.hexdigest() != entry["file_digest"]:
                problems.append(
                    {"kind": "file_digest", "detail": f"{entry['path']}: digest mismatch"}
                )

        if repair:
            with self._connect() as connection:
                self._append_audit(
                    connection,
                    "snapshot_scrubbed",
                    {
                        "remaining_problems": len(problems),
                        "repaired_chunks": len(repaired),
                        "snapshot_id": snapshot_id,
                    },
                    utc_text(),
                )

        return {
            "bytes_checked": bytes_checked,
            "files_checked": files_checked,
            "manifest_ok": not any(
                problem["kind"] in {"manifest_digest", "snapshot_id", "merkle_root"}
                for problem in problems
            ),
            "ok": not problems,
            "problems": problems,
            "repaired_chunks": len(repaired),
            "snapshot_id": snapshot_id,
            "unique_chunks_checked": len(chunk_map),
        }

    def scrub(self, *, repair: bool = False) -> dict[str, Any]:
        results = [
            self.verify_snapshot(row["snapshot_id"], repair=repair)
            for row in self.list_snapshots()
        ]
        return {
            "ok": all(result["ok"] for result in results),
            "repair": repair,
            "snapshots": results,
            "snapshots_checked": len(results),
            "total_repaired_chunks": sum(result["repaired_chunks"] for result in results),
        }

    def restore(
        self,
        snapshot_id: str,
        destination: str | os.PathLike[str],
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Verify first, then restore without following destination symlinks."""

        snapshot_id = validate_snapshot_id(snapshot_id)
        verification = self.verify_snapshot(snapshot_id)
        if not verification["ok"]:
            raise CorruptionError("snapshot failed verification; restore was not started")
        manifest, _ = self._read_manifest(snapshot_id)
        target = Path(destination).expanduser().absolute()
        if target.is_symlink():
            raise SecurityError(f"restore destination cannot be a symlink: {target}")
        if target.exists() and (not target.is_dir() or any(target.iterdir())):
            raise ValidationError("restore destination must be absent or an empty directory")
        target.mkdir(parents=True, exist_ok=True, mode=0o700)
        target = target.resolve()
        if is_relative_to(target, self.root) or is_relative_to(self.root, target):
            raise SecurityError("restore destination and repository must not overlap")

        restored_bytes = 0
        restored_files = 0
        try:
            for entry in manifest["files"]:
                relative = validate_relative_path(str(entry["path"]))
                output = self._safe_output_path(target, relative)
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(output, flags, 0o600)
                hasher = hashlib.sha256()
                size = 0
                try:
                    for chunk in entry["chunks"]:
                        digest = str(chunk["digest"])
                        data = self._chunk_path(self.primary_dir, digest).read_bytes()
                        if sha256_bytes(data) != digest:
                            raise CorruptionError(f"chunk changed during restore: {digest}")
                        view = memoryview(data)
                        while view:
                            written = os.write(descriptor, view)
                            if written <= 0:
                                raise OSError("restore write made no progress")
                            view = view[written:]
                        hasher.update(data)
                        size += len(data)
                    os.fsync(descriptor)
                    os.fchmod(descriptor, int(entry["mode"]) & 0o777)
                finally:
                    os.close(descriptor)
                if size != int(entry["size"]) or hasher.hexdigest() != entry["file_digest"]:
                    raise CorruptionError(f"restored file failed validation: {relative}")
                os.utime(output, ns=(int(entry["mtime_ns"]), int(entry["mtime_ns"])))
                restored_bytes += size
                restored_files += 1
        except Exception:
            # Partial restores are intentionally left for inspection; existing files are never overwritten.
            raise

        completed_at = utc_text(now)
        with self._connect() as connection:
            self._append_audit(
                connection,
                "snapshot_restored",
                {
                    "restored_bytes": restored_bytes,
                    "restored_files": restored_files,
                    "snapshot_id": snapshot_id,
                },
                completed_at,
            )
        return {
            "completed_at": completed_at,
            "destination": str(target),
            "restored_bytes": restored_bytes,
            "restored_files": restored_files,
            "snapshot_id": snapshot_id,
            "verified_before_restore": True,
        }

    def delete_snapshot(
        self, snapshot_id: str, *, now: datetime | None = None
    ) -> dict[str, Any]:
        """Create a tombstone only after the snapshot retention period expires."""

        snapshot_id = validate_snapshot_id(snapshot_id)
        current = self._utc_now(now)
        deleted_at = utc_text(current)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT retained_until, status FROM snapshots WHERE snapshot_id = ?",
                (snapshot_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError(f"snapshot not found: {snapshot_id}")
            if row["status"] == "deleted":
                raise ValidationError("snapshot is already deleted")
            retained_until = parse_utc(row["retained_until"])
            if current < retained_until:
                raise RetentionError(
                    f"snapshot is locked until {utc_text(retained_until)}"
                )
            connection.execute(
                "UPDATE snapshots SET status = 'deleted', deleted_at = ? WHERE snapshot_id = ?",
                (deleted_at, snapshot_id),
            )
            self._append_audit(
                connection,
                "snapshot_deleted",
                {"snapshot_id": snapshot_id},
                deleted_at,
            )
        return {"deleted_at": deleted_at, "snapshot_id": snapshot_id, "status": "deleted"}

    def verify_audit(self) -> dict[str, Any]:
        """Verify the append-order hash chain and its stored head/count checkpoint."""

        previous = ""
        expected_sequence = 1
        problem: str | None = None
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT sequence, recorded_at, event, payload_json, previous_hash, entry_hash "
                "FROM audit ORDER BY sequence"
            ).fetchall()
            metadata = dict(
                connection.execute(
                    "SELECT key, value FROM metadata WHERE key IN ('audit_count', 'audit_head')"
                ).fetchall()
            )
        for row in rows:
            if row["sequence"] != expected_sequence:
                problem = f"sequence gap at {expected_sequence}"
                break
            if row["previous_hash"] != previous:
                problem = f"previous hash mismatch at sequence {row['sequence']}"
                break
            try:
                payload = json.loads(row["payload_json"])
            except json.JSONDecodeError:
                problem = f"invalid payload JSON at sequence {row['sequence']}"
                break
            core = {
                "event": row["event"],
                "payload": payload,
                "previous_hash": row["previous_hash"],
                "recorded_at": row["recorded_at"],
                "sequence": row["sequence"],
            }
            computed = sha256_bytes(canonical_json(core))
            if computed != row["entry_hash"]:
                problem = f"entry hash mismatch at sequence {row['sequence']}"
                break
            previous = computed
            expected_sequence += 1
        if problem is None and int(metadata.get("audit_count", "-1")) != len(rows):
            problem = "audit count checkpoint mismatch"
        if problem is None and metadata.get("audit_head", "") != previous:
            problem = "audit head checkpoint mismatch"
        return {
            "entries": len(rows),
            "head": previous,
            "ok": problem is None,
            "problem": problem,
        }

    def storage_stats(self) -> dict[str, Any]:
        with self._connect() as connection:
            chunk = connection.execute(
                "SELECT COUNT(*), COALESCE(SUM(size), 0), COALESCE(SUM(ref_count), 0) FROM chunks"
            ).fetchone()
            snapshot = connection.execute(
                "SELECT COUNT(*), COALESCE(SUM(logical_bytes), 0) FROM snapshots"
            ).fetchone()
        primary_bytes = int(chunk[1])
        return {
            "chunk_references": int(chunk[2]),
            "logical_snapshot_bytes": int(snapshot[1]),
            "mirrored_physical_bytes": primary_bytes * 2,
            "primary_content_bytes": primary_bytes,
            "snapshot_count": int(snapshot[0]),
            "unique_chunks": int(chunk[0]),
        }

    def _capture_file(self, source_root: Path, path: Path) -> dict[str, Any]:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise SecurityError(f"source entry changed type during backup: {path}")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        chunks: list[dict[str, Any]] = []
        file_hasher = hashlib.sha256()
        size = 0
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise SecurityError(f"source is no longer a regular file: {path}")
            while True:
                data = os.read(descriptor, self.chunk_size)
                if not data:
                    break
                digest = sha256_bytes(data)
                self._ensure_chunk(digest, data)
                chunks.append({"digest": digest, "size": len(data)})
                file_hasher.update(data)
                size += len(data)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValidationError(f"source file changed while it was being backed up: {path}")
        return {
            "chunks": chunks,
            "file_digest": file_hasher.hexdigest(),
            "mode": stat.S_IMODE(after.st_mode),
            "mtime_ns": after.st_mtime_ns,
            "path": path.relative_to(source_root).as_posix(),
            "size": size,
        }

    def _ensure_chunk(self, digest: str, data: bytes) -> None:
        validate_digest(digest)
        if sha256_bytes(data) != digest:
            raise CorruptionError("refusing to store content under the wrong digest")
        primary = self._chunk_path(self.primary_dir, digest)
        mirror = self._chunk_path(self.mirror_dir, digest)
        primary_state = self._chunk_state(primary, digest, len(data))
        mirror_state = self._chunk_state(mirror, digest, len(data))
        if primary_state != "ok" and mirror_state != "ok":
            if primary_state != "missing" or mirror_state != "missing":
                raise CorruptionError(f"both copies of existing chunk are unusable: {digest}")
            self._write_atomic_file(primary, data, exclusive=False)
            self._write_atomic_file(mirror, data, exclusive=False)
            return
        if primary_state != "ok":
            self._write_atomic_file(primary, data, exclusive=False)
        if mirror_state != "ok":
            self._write_atomic_file(mirror, data, exclusive=False)

    def _validate_manifest(self, manifest: Any) -> None:
        if not isinstance(manifest, dict):
            raise ValidationError("manifest root must be an object")
        required = {
            "chunk_size",
            "created_at",
            "files",
            "logical_bytes",
            "merkle_root",
            "retained_until",
            "schema_version",
            "source_label",
        }
        if set(manifest) != required:
            raise ValidationError("manifest fields do not match schema")
        if manifest["schema_version"] != SCHEMA_VERSION:
            raise ValidationError("unsupported manifest schema version")
        if manifest["chunk_size"] != self.chunk_size:
            raise ValidationError("manifest chunk size differs from repository")
        parse_utc(manifest["created_at"])
        parse_utc(manifest["retained_until"])
        if not isinstance(manifest["source_label"], str) or not manifest["source_label"]:
            raise ValidationError("invalid source label")
        if not isinstance(manifest["files"], list):
            raise ValidationError("manifest files must be a list")
        paths: set[str] = set()
        total = 0
        previous_path = ""
        for entry in manifest["files"]:
            if not isinstance(entry, dict) or set(entry) != {
                "chunks",
                "file_digest",
                "mode",
                "mtime_ns",
                "path",
                "size",
            }:
                raise ValidationError("invalid manifest file entry")
            relative = validate_relative_path(entry["path"])
            if relative in paths or (previous_path and relative <= previous_path):
                raise ValidationError("manifest file paths must be unique and sorted")
            previous_path = relative
            paths.add(relative)
            validate_digest(entry["file_digest"])
            if not isinstance(entry["size"], int) or entry["size"] < 0:
                raise ValidationError("invalid file size")
            if not isinstance(entry["mode"], int) or not 0 <= entry["mode"] <= 0o7777:
                raise ValidationError("invalid file mode")
            if (
                not isinstance(entry["mtime_ns"], int)
                or entry["mtime_ns"] < 0
                or entry["mtime_ns"] > 2**63 - 1
            ):
                raise ValidationError("invalid file mtime")
            if not isinstance(entry["chunks"], list):
                raise ValidationError("file chunks must be a list")
            chunk_total = 0
            for index, chunk in enumerate(entry["chunks"]):
                if not isinstance(chunk, dict) or set(chunk) != {"digest", "size"}:
                    raise ValidationError("invalid chunk reference")
                validate_digest(chunk["digest"])
                if not isinstance(chunk["size"], int) or not 1 <= chunk["size"] <= self.chunk_size:
                    raise ValidationError("invalid chunk size")
                if index < len(entry["chunks"]) - 1 and chunk["size"] != self.chunk_size:
                    raise ValidationError("only the final file chunk may be short")
                chunk_total += chunk["size"]
            if chunk_total != entry["size"]:
                raise ValidationError("file size does not equal its chunk sizes")
            if entry["size"] == 0 and entry["chunks"]:
                raise ValidationError("empty file cannot contain chunks")
            total += entry["size"]
        if manifest["logical_bytes"] != total:
            raise ValidationError("manifest logical byte total is incorrect")
        computed_root = merkle_root(canonical_json(entry) for entry in manifest["files"])
        validate_digest(manifest["merkle_root"])
        if computed_root != manifest["merkle_root"]:
            raise ValidationError("manifest Merkle root is incorrect")

    def _read_manifest(self, snapshot_id: str) -> tuple[dict[str, Any], bytes]:
        path = self.manifests_dir / f"{snapshot_id}.json"
        if path.is_symlink():
            raise SecurityError("manifest cannot be a symlink")
        if not path.is_file():
            raise ValidationError("manifest file is missing")
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            raise ValidationError("manifest exceeds the size limit")
        raw = path.read_bytes()
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationError("manifest is not valid UTF-8 JSON") from exc
        canonical = canonical_json(value)
        if raw != canonical:
            raise ValidationError("manifest is not in canonical form")
        return value, canonical

    def _snapshot_row(self, snapshot_id: str) -> sqlite3.Row:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM snapshots WHERE snapshot_id = ?", (snapshot_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError(f"snapshot not found: {snapshot_id}")
        return row

    def _load_config(self) -> dict[str, Any]:
        if self.config_path.is_symlink() or not self.config_path.is_file():
            raise RepositoryError("repository configuration is missing or unsafe")
        try:
            raw = self.config_path.read_bytes()
            if len(raw) > 64 * 1024:
                raise ValueError("configuration is too large")
            value = json.loads(raw)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise RepositoryError("repository configuration is invalid") from exc
        expected = {"chunk_size", "created_at", "repository_id", "schema_version"}
        if not isinstance(value, dict) or set(value) != expected:
            raise RepositoryError("repository configuration fields are invalid")
        if value["schema_version"] != SCHEMA_VERSION:
            raise RepositoryError("repository schema version is unsupported")
        if not isinstance(value["chunk_size"], int) or not (
            MIN_CHUNK_SIZE <= value["chunk_size"] <= MAX_CHUNK_SIZE
        ):
            raise RepositoryError("repository chunk size is invalid")
        return value

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database_path, timeout=10.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _append_audit(
        connection: sqlite3.Connection,
        event: str,
        payload: dict[str, Any],
        recorded_at: str,
    ) -> str:
        if not event or len(event) > 100:
            raise ValidationError("invalid audit event")
        previous_row = connection.execute(
            "SELECT sequence, entry_hash FROM audit ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 1 if previous_row is None else int(previous_row[0]) + 1
        previous_hash = "" if previous_row is None else str(previous_row[1])
        core = {
            "event": event,
            "payload": payload,
            "previous_hash": previous_hash,
            "recorded_at": recorded_at,
            "sequence": sequence,
        }
        entry_hash = sha256_bytes(canonical_json(core))
        connection.execute(
            """
            INSERT INTO audit(sequence, recorded_at, event, payload_json, previous_hash, entry_hash)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                sequence,
                recorded_at,
                event,
                canonical_json(payload).decode("utf-8"),
                previous_hash,
                entry_hash,
            ),
        )
        connection.execute(
            "UPDATE metadata SET value = ? WHERE key = 'audit_count'", (str(sequence),)
        )
        connection.execute(
            "UPDATE metadata SET value = ? WHERE key = 'audit_head'", (entry_hash,)
        )
        return entry_hash

    @staticmethod
    def _write_atomic_file(path: Path, data: bytes, *, exclusive: bool) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.parent.is_symlink():
            raise SecurityError(f"refusing to write through a symlink directory: {path.parent}")
        if exclusive and path.exists():
            raise RepositoryError(f"file already exists: {path.name}")
        temporary = path.parent / f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        descriptor = os.open(temporary, flags, 0o600)
        try:
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            if exclusive and path.exists():
                raise RepositoryError(f"file already exists: {path.name}")
            os.replace(temporary, path)
            directory_descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        finally:
            if temporary.exists():
                temporary.unlink()

    @staticmethod
    def _chunk_state(path: Path, expected_digest: str, expected_size: int) -> str:
        try:
            if path.parent.is_symlink() or path.is_symlink():
                return "unsafe"
            data = path.read_bytes()
        except FileNotFoundError:
            return "missing"
        except OSError:
            return "unreadable"
        if len(data) != expected_size:
            return "size_mismatch"
        if sha256_bytes(data) != expected_digest:
            return "digest_mismatch"
        return "ok"

    @staticmethod
    def _chunk_path(base: Path, digest: str) -> Path:
        validate_digest(digest)
        return base / digest[:2] / f"{digest}.chunk"

    @staticmethod
    def _safe_output_path(root: Path, relative: str) -> Path:
        parts = validate_relative_path(relative).split("/")
        current = root
        for component in parts[:-1]:
            current = current / component
            if current.is_symlink():
                raise SecurityError(f"restore path contains a symlink: {current}")
            current.mkdir(mode=0o700, exist_ok=True)
            if not current.is_dir() or current.is_symlink():
                raise SecurityError(f"restore path is not a safe directory: {current}")
        output = current / parts[-1]
        if output.exists() or output.is_symlink():
            raise SecurityError(f"restore refuses to overwrite: {output}")
        if not is_relative_to(output.absolute(), root):
            raise SecurityError("restore path escaped its destination")
        return output

    @staticmethod
    def _utc_now(value: datetime | None) -> datetime:
        current = value or datetime.now(timezone.utc)
        if current.tzinfo is None:
            raise ValidationError("datetime must be timezone-aware")
        return current.astimezone(timezone.utc)

