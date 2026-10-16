from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from vaultguard import VaultRepository
from vaultguard.errors import (
    CorruptionError,
    NotFoundError,
    RepositoryError,
    RetentionError,
    SecurityError,
    ValidationError,
)
from vaultguard.repository import MAX_RETENTION_SECONDS
from vaultguard.util import file_tree_fingerprint

from .helpers import FIXED_TIME, block, make_source


class RepositoryFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = make_source(self.root)
        self.repository = VaultRepository.initialize(
            self.root / "repo", chunk_size=1024, now=FIXED_TIME
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def backup(self, **kwargs):
        values = {"now": FIXED_TIME + timedelta(seconds=1), "retain_seconds": 60}
        values.update(kwargs)
        return self.repository.backup(self.source, **values)


class InitializationTests(unittest.TestCase):
    def test_initialization_creates_required_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            repository = VaultRepository.initialize(root, chunk_size=2048, now=FIXED_TIME)
            self.assertEqual(repository.chunk_size, 2048)
            self.assertTrue((root / "chunks" / "primary").is_dir())
            self.assertTrue(repository.verify_audit()["ok"])

    def test_nonempty_repository_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            (root / "existing").write_text("keep")
            with self.assertRaises(RepositoryError):
                VaultRepository.initialize(root)

    def test_invalid_chunk_sizes_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for index, value in enumerate((0, 511, 8 * 1024 * 1024 + 1, True)):
                with self.subTest(value=value), self.assertRaises(ValidationError):
                    VaultRepository.initialize(Path(temporary) / f"repo-{index}", chunk_size=value)

    def test_missing_repository_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(RepositoryError):
                VaultRepository(Path(temporary) / "missing")

    def test_repository_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            VaultRepository.initialize(root / "real")
            os.symlink(root / "real", root / "link")
            with self.assertRaises(SecurityError):
                VaultRepository(root / "link")


class BackupTests(RepositoryFixture):
    def test_backup_creates_verifiable_manifest(self) -> None:
        snapshot = self.backup()
        report = self.repository.verify_snapshot(snapshot["snapshot_id"])
        self.assertTrue(report["ok"])
        self.assertEqual(report["files_checked"], 3)
        self.assertEqual(report["bytes_checked"], 4096)

    def test_backup_preserves_empty_file(self) -> None:
        snapshot = self.backup()
        destination = self.root / "restore"
        self.repository.restore(snapshot["snapshot_id"], destination)
        self.assertEqual((destination / "nested" / "empty.txt").read_bytes(), b"")

    def test_incremental_snapshot_deduplicates_chunks(self) -> None:
        first = self.backup()
        (self.source / "alpha.bin").write_bytes(block("shared") + block("changed"))
        second = self.repository.backup(
            self.source, now=FIXED_TIME + timedelta(seconds=2), retain_seconds=60
        )
        stats = self.repository.storage_stats()
        self.assertLess(second["new_chunk_bytes"], second["logical_bytes"])
        self.assertLess(stats["primary_content_bytes"], first["logical_bytes"] + second["logical_bytes"])

    def test_snapshot_collision_is_rejected(self) -> None:
        self.backup()
        with self.assertRaises(RepositoryError):
            self.backup()

    def test_source_repository_overlap_is_rejected(self) -> None:
        with self.assertRaises(SecurityError):
            self.repository.backup(self.repository.root)

    def test_source_symlink_is_rejected(self) -> None:
        os.symlink(self.source / "alpha.bin", self.source / "unsafe-link")
        with self.assertRaises(SecurityError):
            self.backup()

    def test_invalid_retention_is_rejected(self) -> None:
        for value in (-1, MAX_RETENTION_SECONDS + 1, 1.5, True):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                self.repository.backup(self.source, retain_seconds=value)

    def test_invalid_label_is_rejected(self) -> None:
        for value in ("", " " * 3, "x" * 201):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                self.repository.backup(self.source, label=value)

    def test_list_returns_active_snapshot_metadata(self) -> None:
        snapshot = self.backup(label="finance-share")
        listed = self.repository.list_snapshots()
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["snapshot_id"], snapshot["snapshot_id"])
        self.assertEqual(listed[0]["source_label"], "finance-share")


class IntegrityTests(RepositoryFixture):
    def _snapshot_and_chunk(self):
        snapshot = self.backup()
        manifest, _ = self.repository._read_manifest(snapshot["snapshot_id"])
        digest = manifest["files"][0]["chunks"][0]["digest"]
        return snapshot, digest

    def test_primary_corruption_is_detected(self) -> None:
        snapshot, digest = self._snapshot_and_chunk()
        path = self.repository._chunk_path(self.repository.primary_dir, digest)
        path.write_bytes(b"broken")
        report = self.repository.verify_snapshot(snapshot["snapshot_id"])
        self.assertFalse(report["ok"])
        self.assertTrue(report["problems"][0]["kind"].startswith("primary_"))

    def test_missing_primary_is_repaired_from_mirror(self) -> None:
        snapshot, digest = self._snapshot_and_chunk()
        self.repository._chunk_path(self.repository.primary_dir, digest).unlink()
        report = self.repository.verify_snapshot(snapshot["snapshot_id"], repair=True)
        self.assertTrue(report["ok"])
        self.assertEqual(report["repaired_chunks"], 1)

    def test_corrupt_mirror_is_detected_and_repaired_from_primary(self) -> None:
        snapshot, digest = self._snapshot_and_chunk()
        mirror = self.repository._chunk_path(self.repository.mirror_dir, digest)
        mirror.write_bytes(b"bad mirror")
        damaged = self.repository.verify_snapshot(snapshot["snapshot_id"])
        self.assertFalse(damaged["ok"])
        self.assertTrue(damaged["problems"][0]["kind"].startswith("mirror_"))
        repaired = self.repository.verify_snapshot(snapshot["snapshot_id"], repair=True)
        self.assertTrue(repaired["ok"])
        self.assertEqual(repaired["repaired_chunks"], 1)

    def test_dual_corruption_cannot_be_repaired(self) -> None:
        snapshot, digest = self._snapshot_and_chunk()
        self.repository._chunk_path(self.repository.primary_dir, digest).write_bytes(b"bad")
        self.repository._chunk_path(self.repository.mirror_dir, digest).write_bytes(b"bad")
        report = self.repository.verify_snapshot(snapshot["snapshot_id"], repair=True)
        self.assertFalse(report["ok"])
        self.assertIn("mirror_", report["problems"][0]["detail"])

    def test_manifest_whitespace_tampering_is_detected(self) -> None:
        snapshot = self.backup()
        path = self.repository.manifests_dir / f"{snapshot['snapshot_id']}.json"
        path.write_bytes(path.read_bytes() + b"\n")
        report = self.repository.verify_snapshot(snapshot["snapshot_id"])
        self.assertFalse(report["ok"])
        self.assertFalse(report["manifest_ok"])

    def test_database_manifest_digest_tampering_is_detected(self) -> None:
        snapshot = self.backup()
        with sqlite3.connect(self.repository.database_path) as connection:
            connection.execute(
                "UPDATE snapshots SET manifest_digest = ? WHERE snapshot_id = ?",
                ("0" * 64, snapshot["snapshot_id"]),
            )
        report = self.repository.verify_snapshot(snapshot["snapshot_id"])
        self.assertFalse(report["ok"])
        self.assertIn("manifest_digest", {item["kind"] for item in report["problems"]})

    def test_scrub_checks_all_active_snapshots(self) -> None:
        self.backup()
        (self.source / "new.txt").write_bytes(b"next")
        self.repository.backup(
            self.source, now=FIXED_TIME + timedelta(seconds=2), retain_seconds=60
        )
        result = self.repository.scrub()
        self.assertTrue(result["ok"])
        self.assertEqual(result["snapshots_checked"], 2)

    def test_unknown_snapshot_is_rejected(self) -> None:
        with self.assertRaises(NotFoundError):
            self.repository.verify_snapshot("0" * 32)


class RestoreTests(RepositoryFixture):
    def test_restore_matches_source_fingerprint_and_modes(self) -> None:
        expected = file_tree_fingerprint(self.source)
        snapshot = self.backup()
        destination = self.root / "restore"
        result = self.repository.restore(snapshot["snapshot_id"], destination)
        self.assertTrue(result["verified_before_restore"])
        self.assertEqual(file_tree_fingerprint(destination), expected)
        self.assertEqual((destination / "alpha.bin").stat().st_mode & 0o777, 0o640)

    def test_restore_refuses_nonempty_destination(self) -> None:
        snapshot = self.backup()
        destination = self.root / "restore"
        destination.mkdir()
        (destination / "keep").write_text("do not overwrite")
        with self.assertRaises(ValidationError):
            self.repository.restore(snapshot["snapshot_id"], destination)

    def test_restore_refuses_symlink_destination(self) -> None:
        snapshot = self.backup()
        actual = self.root / "actual"
        actual.mkdir()
        link = self.root / "restore-link"
        os.symlink(actual, link)
        with self.assertRaises(SecurityError):
            self.repository.restore(snapshot["snapshot_id"], link)

    def test_restore_stops_on_corrupt_snapshot(self) -> None:
        snapshot = self.backup()
        manifest, _ = self.repository._read_manifest(snapshot["snapshot_id"])
        digest = manifest["files"][0]["chunks"][0]["digest"]
        self.repository._chunk_path(self.repository.primary_dir, digest).write_bytes(b"bad")
        with self.assertRaises(CorruptionError):
            self.repository.restore(snapshot["snapshot_id"], self.root / "restore")
        self.assertFalse((self.root / "restore").exists())


class RetentionAndAuditTests(RepositoryFixture):
    def test_retention_blocks_early_delete(self) -> None:
        snapshot = self.backup(retain_seconds=60)
        with self.assertRaises(RetentionError):
            self.repository.delete_snapshot(
                snapshot["snapshot_id"], now=FIXED_TIME + timedelta(seconds=30)
            )

    def test_expired_snapshot_is_tombstoned(self) -> None:
        snapshot = self.backup(retain_seconds=1)
        result = self.repository.delete_snapshot(
            snapshot["snapshot_id"], now=FIXED_TIME + timedelta(seconds=3)
        )
        self.assertEqual(result["status"], "deleted")
        self.assertEqual(self.repository.list_snapshots(), [])
        self.assertEqual(len(self.repository.list_snapshots(include_deleted=True)), 1)

    def test_duplicate_delete_is_rejected(self) -> None:
        snapshot = self.backup(retain_seconds=0)
        self.repository.delete_snapshot(
            snapshot["snapshot_id"], now=FIXED_TIME + timedelta(seconds=1)
        )
        with self.assertRaises(ValidationError):
            self.repository.delete_snapshot(
                snapshot["snapshot_id"], now=FIXED_TIME + timedelta(seconds=2)
            )

    def test_audit_chain_records_mutations(self) -> None:
        snapshot = self.backup()
        self.repository.restore(snapshot["snapshot_id"], self.root / "restore")
        audit = self.repository.verify_audit()
        self.assertTrue(audit["ok"])
        self.assertEqual(audit["entries"], 3)

    def test_audit_payload_tampering_is_detected(self) -> None:
        self.backup()
        with sqlite3.connect(self.repository.database_path) as connection:
            connection.execute("UPDATE audit SET payload_json = '{}' WHERE sequence = 2")
        audit = self.repository.verify_audit()
        self.assertFalse(audit["ok"])
        self.assertIn("entry hash mismatch", audit["problem"])

    def test_audit_tail_deletion_is_detected_by_checkpoint(self) -> None:
        self.backup()
        with sqlite3.connect(self.repository.database_path) as connection:
            connection.execute("DELETE FROM audit WHERE sequence = 2")
        audit = self.repository.verify_audit()
        self.assertFalse(audit["ok"])
        self.assertIn("checkpoint mismatch", audit["problem"])
