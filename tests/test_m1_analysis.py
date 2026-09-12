#!/usr/bin/env python3
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tools" / "macsandbox_run.py"


class M1AnalysisTests(unittest.TestCase):
    def run_runner(self, analysis_dir: Path, *extra: str):
        cmd = [
            sys.executable,
            str(RUNNER),
            "--analysis-dir", str(analysis_dir),
            "--machine-profile", "macii-ci",
            "--config-fingerprint", "m1-test",
            "--backend-revision", "test-revision",
            "--rom-sha256", "a" * 64,
            "--system-software-id", "system-7-ci-placeholder",
            "--system-software-sha256", "b" * 64,
            *extra,
        ]
        return subprocess.run(cmd, text=True, capture_output=True)

    def test_lifecycle_contract(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "analysis"
            result = self.run_runner(out)
            self.assertEqual(result.returncode, 0, result.stderr)

            session = json.loads((out / "session.json").read_text(encoding="utf-8"))
            self.assertEqual(session["schema"], "macsandbox.session/1")
            self.assertEqual(session["backend"], "basiliskii")
            self.assertEqual(session["machine_profile"], "macii-ci")
            self.assertEqual(session["rom_sha256"], "a" * 64)
            self.assertEqual(session["system_software"]["sha256"], "b" * 64)
            self.assertEqual(session["network"], "disabled")
            self.assertEqual(session["host_shared_folders"], "disabled")
            self.assertEqual(session["jit"], "disabled")
            self.assertEqual(session["exit_code"], 0)

            events = [json.loads(line) for line in (out / "events.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual([event["type"] for event in events], ["session.start", "session.stop"])
            self.assertTrue(all(event["schema"] == "macsandbox.event/1" for event in events))

    def test_refuses_nonempty_evidence_directory(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "analysis"
            out.mkdir()
            (out / "existing.txt").write_text("do not overwrite", encoding="utf-8")
            result = self.run_runner(out)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("absent or empty", result.stderr)


if __name__ == "__main__":
    unittest.main()
