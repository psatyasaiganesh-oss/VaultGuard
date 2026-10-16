from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from vaultguard.__main__ import main
from vaultguard.demo import run_demo

from .helpers import make_source


class DemoTests(unittest.TestCase):
    def test_demo_recovers_every_injected_corruption(self) -> None:
        result = run_demo()
        self.assertTrue(result["success"])
        self.assertEqual(result["corruption"]["injected_chunks"], 6)
        self.assertEqual(result["corruption"]["repaired_chunks"], 6)
        self.assertTrue(result["restore"]["fingerprint_match"])

    def test_demo_can_keep_an_explicit_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "lab"
            result = run_demo(workspace)
            self.assertTrue(result["success"])
            self.assertTrue((workspace / "repository" / "metadata.sqlite3").is_file())


class CliTests(unittest.TestCase):
    def invoke(self, *arguments: str):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(list(arguments))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_cli_init_backup_list_verify_restore(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = make_source(root)
            repository = root / "repo"
            code, output, _ = self.invoke("init", str(repository), "--chunk-size", "1024")
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output)["status"], "initialized")
            code, output, _ = self.invoke(
                "backup", str(repository), str(source), "--retain-seconds", "0"
            )
            self.assertEqual(code, 0)
            snapshot_id = json.loads(output)["snapshot_id"]
            code, output, _ = self.invoke("verify", str(repository), snapshot_id)
            self.assertEqual(code, 0)
            self.assertTrue(json.loads(output)["ok"])
            code, output, _ = self.invoke("list", str(repository))
            self.assertEqual(len(json.loads(output)["snapshots"]), 1)
            code, output, _ = self.invoke(
                "restore", str(repository), snapshot_id, str(root / "restore")
            )
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output)["restored_files"], 3)

    def test_cli_expected_error_is_structured_json(self) -> None:
        code, output, error = self.invoke("stats", "/definitely/missing/vaultguard")
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        payload = json.loads(error)
        self.assertEqual(payload["error"], "RepositoryError")
