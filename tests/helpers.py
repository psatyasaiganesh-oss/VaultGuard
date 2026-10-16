from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path


FIXED_TIME = datetime(2026, 10, 15, 1, 0, tzinfo=timezone.utc)


def block(label: str, size: int = 1024) -> bytes:
    seed = hashlib.sha256(label.encode()).digest()
    return (seed * ((size + len(seed) - 1) // len(seed)))[:size]


def make_source(root: Path) -> Path:
    source = root / "source"
    (source / "nested").mkdir(parents=True)
    (source / "alpha.bin").write_bytes(block("shared") + block("alpha"))
    (source / "nested" / "beta.bin").write_bytes(block("shared") + block("beta"))
    (source / "nested" / "empty.txt").write_bytes(b"")
    (source / "alpha.bin").chmod(0o640)
    (source / "nested" / "beta.bin").chmod(0o600)
    return source
