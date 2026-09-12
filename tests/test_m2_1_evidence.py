#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class M2EvidenceTests(unittest.TestCase):
    def test_source_hooks_are_wired(self) -> None:
        glue = (ROOT / "BasiliskII/src/uae_cpu/basilisk_glue.cpp").read_text(encoding="utf-8")
        memory = (ROOT / "BasiliskII/src/uae_cpu/memory.h").read_text(encoding="utf-8")
        recorder = (ROOT / "BasiliskII/src/macsandbox_analysis.cpp").read_text(encoding="utf-8")
        self.assertIn('MacSandbox_RecordCpuSnapshot("reset")', glue)
        self.assertIn("MacSandbox_RecordTrap(trap)", glue)
        self.assertIn("MacSandbox_RecordInterrupt(1)", glue)
        self.assertGreaterEqual(memory.count("MacSandbox_RecordMemoryWrite"), 6)
        self.assertIn('"memory.write"', recorder)
        self.assertIn("MACSANDBOX_EVENT_LIMIT", recorder)
        self.assertIn("MACSANDBOX_WATCH_START", recorder)
        self.assertIn("MACSANDBOX_WATCH_END", recorder)

    def test_synthetic_m2_1_contract(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            session = {
                "schema": "macsandbox.session/1",
                "backend": "basiliskii",
                "backend_revision": "ci-contract",
                "machine_profile": "quadra650-system753",
                "rom_sha256": "a" * 64,
                "system_software": {"id": "ci-placeholder", "sha256": "b" * 64},
                "network": "disabled",
                "host_shared_folders": "disabled",
                "jit": "disabled",
                "core_event_limit": 16,
                "core_event_count": 2,
                "memory_watch": {"start": 0x1000, "end": 0x1FFF},
            }
            cpu = {
                "schema": "macsandbox.event/1",
                "type": "cpu.snapshot",
                "source": "macsandbox.uae_cpu",
                "phase": "reset",
                "pc": 0x4080002A,
                "sr": 0x2700,
                "d": list(range(8)),
                "a": list(range(8, 16)),
            }
            write = {
                "schema": "macsandbox.event/1",
                "type": "memory.write",
                "source": "macsandbox.uae_memory",
                "address": 0x1234,
                "size": 2,
                "value": 0xABCD,
                "pc": 0x40801000,
                "sr": 0x2000,
                "d": list(range(8)),
                "a": list(range(8, 16)),
            }
            (root / "session.json").write_text(json.dumps(session) + "\n", encoding="utf-8")
            (root / "core-events.jsonl").write_text(
                "\n".join(json.dumps(e) for e in (cpu, write)) + "\n", encoding="utf-8"
            )
            unified = [
                {"schema": "macsandbox.event/1", "type": "session.start"},
                cpu,
                write,
                {"schema": "macsandbox.event/1", "type": "session.stop"},
            ]
            (root / "events.jsonl").write_text(
                "\n".join(json.dumps(e) for e in unified) + "\n", encoding="utf-8"
            )
            proc = subprocess.run(
                [sys.executable, str(ROOT / "tools/qualify_m2_1.py"), "--analysis-dir", str(root)],
                text=True,
                capture_output=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            verdict = json.loads((root / "m2_1-qualification.json").read_text(encoding="utf-8"))
            self.assertEqual(verdict["schema"], "macsandbox.m2_1.qualification/1")
            self.assertEqual(verdict["result"], "HOST_EVIDENCE_PASS")
            self.assertEqual(verdict["cpu_events"], 1)
            self.assertEqual(verdict["memory_write_events"], 1)


if __name__ == "__main__":
    unittest.main()
