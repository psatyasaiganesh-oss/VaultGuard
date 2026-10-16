"""Deterministic ransomware-style corruption and recovery demonstration."""

from __future__ import annotations

import hashlib
import os
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .errors import RetentionError
from .repository import VaultRepository
from .util import file_tree_fingerprint

DEMO_MTIME_NS = int(datetime(2026, 10, 15, tzinfo=timezone.utc).timestamp() * 1_000_000_000)


def _block(number: int, size: int = 4096) -> bytes:
    seed = hashlib.sha256(f"vaultguard-synthetic-block-{number}".encode()).digest()
    return (seed * ((size + len(seed) - 1) // len(seed)))[:size]


def _build_baseline(root: Path) -> None:
    """Create 96 files with deliberately repeated blocks to model incremental backups."""

    for index in range(96):
        directory = root / f"team-{index % 8:02d}"
        directory.mkdir(parents=True, exist_ok=True)
        data = b"".join(_block((index * 7 + part * 11) % 48) for part in range(8))
        path = directory / f"record-{index:03d}.bin"
        path.write_bytes(data)
        path.chmod(0o640)
        os.utime(path, ns=(DEMO_MTIME_NS, DEMO_MTIME_NS))
    empty = root / "team-00" / "empty-marker"
    empty.write_bytes(b"")
    empty.chmod(0o600)
    os.utime(empty, ns=(DEMO_MTIME_NS, DEMO_MTIME_NS))


def _mutate_increment(root: Path) -> None:
    for index in range(16):
        path = root / f"team-{index % 8:02d}" / f"record-{index:03d}.bin"
        blocks = [path.read_bytes()[part * 4096 : (part + 1) * 4096] for part in range(8)]
        blocks[2] = _block(1000 + index * 2)
        blocks[5] = _block(1001 + index * 2)
        path.write_bytes(b"".join(blocks))
        path.chmod(0o640)
        os.utime(
            path,
            ns=(DEMO_MTIME_NS + 300_000_000_000, DEMO_MTIME_NS + 300_000_000_000),
        )
    for index in range(92, 96):
        (root / f"team-{index % 8:02d}" / f"record-{index:03d}.bin").unlink()
    for index in range(96, 100):
        directory = root / f"team-{index % 8:02d}"
        directory.mkdir(parents=True, exist_ok=True)
        data = b"".join(_block(2000 + index * 8 + part) for part in range(8))
        path = directory / f"record-{index:03d}.bin"
        path.write_bytes(data)
        path.chmod(0o640)
        os.utime(
            path,
            ns=(DEMO_MTIME_NS + 300_000_000_000, DEMO_MTIME_NS + 300_000_000_000),
        )


def _run_in(root: Path) -> dict[str, Any]:
    started = time.perf_counter()
    source = root / "source"
    repository_path = root / "repository"
    restored = root / "restored"
    source.mkdir(parents=True)
    _build_baseline(source)

    first_time = datetime(2026, 10, 15, 0, 0, tzinfo=timezone.utc)
    repository = VaultRepository.initialize(repository_path, chunk_size=4096, now=first_time)
    first = repository.backup(
        source,
        retain_seconds=86_400,
        label="synthetic-team-share",
        now=first_time + timedelta(seconds=1),
    )

    _mutate_increment(source)
    expected_fingerprint = file_tree_fingerprint(source)
    second_time = first_time + timedelta(minutes=5)
    second = repository.backup(
        source,
        retain_seconds=86_400,
        label="synthetic-team-share",
        now=second_time,
    )
    manifest, _ = repository._read_manifest(second["snapshot_id"])
    digests = sorted(
        {chunk["digest"] for entry in manifest["files"] for chunk in entry["chunks"]}
    )
    selected = digests[:6]
    for index, digest in enumerate(selected):
        path = repository._chunk_path(repository.primary_dir, digest)
        original = path.read_bytes()
        if index % 2:
            path.write_bytes(original[:-17])
        else:
            changed = bytearray(original)
            changed[index] ^= 0xFF
            path.write_bytes(bytes(changed))

    damaged = repository.verify_snapshot(second["snapshot_id"])
    detected = sum(
        1 for problem in damaged["problems"] if problem["kind"].startswith("primary_")
    )
    repaired = repository.verify_snapshot(second["snapshot_id"], repair=True)
    restored_result = repository.restore(
        second["snapshot_id"], restored, now=second_time + timedelta(minutes=1)
    )
    restored_fingerprint = file_tree_fingerprint(restored)

    retention_blocked = False
    try:
        repository.delete_snapshot(
            second["snapshot_id"], now=second_time + timedelta(minutes=2)
        )
    except RetentionError:
        retention_blocked = True

    audit = repository.verify_audit()
    stats = repository.storage_stats()
    avoided = stats["logical_snapshot_bytes"] - stats["primary_content_bytes"]
    reduction = (
        round(avoided * 100 / stats["logical_snapshot_bytes"], 2)
        if stats["logical_snapshot_bytes"]
        else 0.0
    )
    success = all(
        (
            not damaged["ok"],
            detected == len(selected),
            repaired["ok"],
            repaired["repaired_chunks"] == len(selected),
            restored_fingerprint == expected_fingerprint,
            retention_blocked,
            audit["ok"],
        )
    )
    return {
        "audit_chain": {"entries": audit["entries"], "ok": audit["ok"]},
        "corruption": {
            "detected_chunks": detected,
            "injected_chunks": len(selected),
            "post_repair_ok": repaired["ok"],
            "repaired_chunks": repaired["repaired_chunks"],
        },
        "deduplication": {
            "logical_bytes_across_snapshots": stats["logical_snapshot_bytes"],
            "primary_bytes_avoided": avoided,
            "primary_content_bytes": stats["primary_content_bytes"],
            "primary_reduction_percent": reduction,
            "stored_bytes_including_mirror": stats["mirrored_physical_bytes"],
            "unique_chunks": stats["unique_chunks"],
        },
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        "first_snapshot": first,
        "independent_implementation": True,
        "retention_delete_blocked": retention_blocked,
        "restore": {
            "files": restored_result["restored_files"],
            "fingerprint_match": restored_fingerprint == expected_fingerprint,
            "logical_bytes": restored_result["restored_bytes"],
            "verified_before_restore": restored_result["verified_before_restore"],
        },
        "second_snapshot": second,
        "success": success,
    }


def run_demo(workspace: str | Path | None = None) -> dict[str, Any]:
    """Run in a disposable directory unless a new explicit workspace is supplied."""

    if workspace is None:
        with tempfile.TemporaryDirectory(prefix="vaultguard-demo-") as temporary:
            return _run_in(Path(temporary))
    root = Path(workspace).expanduser().absolute()
    if root.exists() and (not root.is_dir() or any(root.iterdir())):
        raise ValueError("demo workspace must be absent or an empty directory")
    root.mkdir(parents=True, exist_ok=True)
    return _run_in(root.resolve())
