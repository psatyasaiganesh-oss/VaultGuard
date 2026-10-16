"""Command-line interface for VaultGuard."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from typing import Any, Sequence

from . import __version__
from .demo import run_demo
from .errors import VaultGuardError
from .repository import VaultRepository


def _print(value: Any, *, stream: Any | None = None) -> None:
    print(json.dumps(value, indent=2, sort_keys=True), file=stream or sys.stdout)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vaultguard",
        description="Create, verify, repair, and safely restore content-addressed snapshots.",
    )
    parser.add_argument("--version", action="version", version=f"VaultGuard {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    initialize = commands.add_parser("init", help="initialize an empty repository")
    initialize.add_argument("repository")
    initialize.add_argument("--chunk-size", type=int, default=4096)

    backup = commands.add_parser("backup", help="create a snapshot")
    backup.add_argument("repository")
    backup.add_argument("source")
    backup.add_argument("--label")
    backup.add_argument("--retain-seconds", type=int, default=86_400)

    listing = commands.add_parser("list", help="list snapshots")
    listing.add_argument("repository")
    listing.add_argument("--include-deleted", action="store_true")

    verify = commands.add_parser("verify", help="verify one snapshot")
    verify.add_argument("repository")
    verify.add_argument("snapshot_id")
    verify.add_argument("--repair", action="store_true")

    scrub = commands.add_parser("scrub", help="verify every active snapshot")
    scrub.add_argument("repository")
    scrub.add_argument("--repair", action="store_true")

    restore = commands.add_parser("restore", help="verify and restore a snapshot")
    restore.add_argument("repository")
    restore.add_argument("snapshot_id")
    restore.add_argument("destination")

    delete = commands.add_parser("delete", help="tombstone an expired snapshot")
    delete.add_argument("repository")
    delete.add_argument("snapshot_id")

    audit = commands.add_parser("audit", help="verify the audit hash chain")
    audit.add_argument("repository")

    stats = commands.add_parser("stats", help="show logical and physical storage totals")
    stats.add_argument("repository")

    demo = commands.add_parser("demo", help="run the synthetic corruption/recovery lab")
    demo.add_argument("--workspace")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "init":
            repository = VaultRepository.initialize(
                arguments.repository, chunk_size=arguments.chunk_size
            )
            result: Any = {
                "chunk_size": repository.chunk_size,
                "repository": str(repository.root),
                "status": "initialized",
            }
        elif arguments.command == "demo":
            result = run_demo(arguments.workspace)
        else:
            repository = VaultRepository(arguments.repository)
            if arguments.command == "backup":
                result = repository.backup(
                    arguments.source,
                    retain_seconds=arguments.retain_seconds,
                    label=arguments.label,
                )
            elif arguments.command == "list":
                result = {
                    "snapshots": repository.list_snapshots(
                        include_deleted=arguments.include_deleted
                    )
                }
            elif arguments.command == "verify":
                result = repository.verify_snapshot(
                    arguments.snapshot_id, repair=arguments.repair
                )
            elif arguments.command == "scrub":
                result = repository.scrub(repair=arguments.repair)
            elif arguments.command == "restore":
                result = repository.restore(
                    arguments.snapshot_id, arguments.destination
                )
            elif arguments.command == "delete":
                result = repository.delete_snapshot(arguments.snapshot_id)
            elif arguments.command == "audit":
                result = repository.verify_audit()
            elif arguments.command == "stats":
                result = repository.storage_stats()
            else:  # pragma: no cover - argparse guarantees a known command.
                raise AssertionError(f"unhandled command: {arguments.command}")
        _print(result)
        if isinstance(result, dict):
            passed = result.get("ok", result.get("success", True))
            return 0 if passed else 1
        return 0
    except (VaultGuardError, OSError, ValueError, sqlite3.Error) as exc:
        _print({"error": exc.__class__.__name__, "message": str(exc)}, stream=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
