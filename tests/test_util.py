from __future__ import annotations

import math
import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from vaultguard.errors import SecurityError, ValidationError
from vaultguard.util import (
    canonical_json,
    file_tree_fingerprint,
    merkle_root,
    parse_utc,
    utc_text,
    validate_relative_path,
    validate_snapshot_id,
    validate_source_tree,
)

from .helpers import make_source


class JsonAndHashTests(unittest.TestCase):
    def test_canonical_json_is_stable(self) -> None:
        self.assertEqual(canonical_json({"b": 2, "a": 1}), b'{"a":1,"b":2}')

    def test_canonical_json_rejects_nan(self) -> None:
        with self.assertRaises(ValueError):
            canonical_json({"bad": math.nan})

    def test_empty_merkle_root_is_stable(self) -> None:
        self.assertEqual(merkle_root([]), merkle_root([]))
        self.assertEqual(len(merkle_root([])), 64)

    def test_merkle_root_depends_on_order(self) -> None:
        self.assertNotEqual(merkle_root([b"a", b"b"]), merkle_root([b"b", b"a"]))

    def test_merkle_root_handles_odd_leaf_count(self) -> None:
        self.assertEqual(len(merkle_root([b"a", b"b", b"c"])), 64)


class ValidationTests(unittest.TestCase):
    def test_valid_relative_path(self) -> None:
        self.assertEqual(validate_relative_path("a/b.txt"), "a/b.txt")

    def test_unsafe_relative_paths_are_rejected(self) -> None:
        for value in ("../x", "a/../x", "/etc/passwd", "a//b", "a\\b", "", "./x"):
            with self.subTest(value=value), self.assertRaises(SecurityError):
                validate_relative_path(value)

    def test_snapshot_id_requires_canonical_hex(self) -> None:
        self.assertEqual(validate_snapshot_id("a" * 32), "a" * 32)
        for value in ("a" * 31, "A" * 32, "z" * 32):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                validate_snapshot_id(value)

    def test_utc_round_trip(self) -> None:
        value = "2026-10-15T01:02:03.000000Z"
        self.assertEqual(utc_text(parse_utc(value)), value)

    def test_naive_datetime_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            utc_text(datetime(2026, 1, 1))

    def test_invalid_timestamp_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            parse_utc("not-a-time")


class TreeTests(unittest.TestCase):
    def test_source_tree_is_globally_sorted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = make_source(Path(temporary))
            paths = [path.relative_to(source).as_posix() for path in validate_source_tree(source)]
            self.assertEqual(paths, sorted(paths))

    def test_source_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = make_source(root)
            os.symlink(source / "alpha.bin", source / "link")
            with self.assertRaises(SecurityError):
                validate_source_tree(source)

    def test_tree_fingerprint_changes_with_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = make_source(Path(temporary))
            before = file_tree_fingerprint(source)
            (source / "alpha.bin").write_bytes(b"changed")
            self.assertNotEqual(before, file_tree_fingerprint(source))
