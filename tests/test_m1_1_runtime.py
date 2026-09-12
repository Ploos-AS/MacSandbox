#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tools" / "macsandbox_basilisk_runtime.py"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        binary = root / "BasiliskII"
        binary.write_text(
            "#!/usr/bin/env python3\n"
            "import signal,time\n"
            "signal.signal(signal.SIGTERM, lambda *_: exit(0))\n"
            "time.sleep(60)\n",
            encoding="utf-8",
        )
        binary.chmod(0o755)
        rom_bytes = b"harmless-ci-rom-placeholder\n"
        disk_bytes = b"harmless-ci-system-disk-placeholder\n"
        rom = root / "ROM"
        disk = root / "system.img"
        rom.write_bytes(rom_bytes)
        disk.write_bytes(disk_bytes)
        out = root / "evidence"

        cmd = [
            sys.executable,
            str(RUNNER),
            "--analysis-dir", str(out),
            "--basilisk-binary", str(binary),
            "--rom", str(rom),
            "--system-disk", str(disk),
            "--system-software-id", "ci-placeholder",
            "--machine-profile", "mac68k-ci",
            "--config-fingerprint", "m1.1-ci",
            "--backend-revision", "ci-stub",
            "--runtime-seconds", "0.2",
            "--grace-seconds", "1.0",
        ]
        subprocess.run(cmd, check=True)

        session = json.loads((out / "session.json").read_text(encoding="utf-8"))
        assert session["schema"] == "macsandbox.session/1"
        assert session["backend"] == "basiliskii"
        assert session["runtime_adapter"] == "macsandbox.m1_1"
        assert session["rom_sha256"] == sha256(rom_bytes)
        assert session["system_software"]["sha256"] == sha256(disk_bytes)
        assert session["network"] == "disabled"
        assert session["host_shared_folders"] == "disabled"
        assert session["jit"] == "disabled"
        assert session["termination"] in {"sigterm", "sigkill"}

        events = [json.loads(line) for line in (out / "events.jsonl").read_text(encoding="utf-8").splitlines()]
        kinds = [e["type"] for e in events]
        assert kinds[0] == "session.start"
        assert "backend.start" in kinds
        assert "backend.terminate" in kinds
        assert kinds[-1] == "session.stop"
        assert (out / "basiliskii.stdout.log").is_file()
        assert (out / "basiliskii.stderr.log").is_file()

    print("M1.1 PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
