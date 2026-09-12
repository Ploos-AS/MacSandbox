#!/usr/bin/env python3
"""MacSandbox M1.2 local real-runtime qualification.

Requires user-supplied lawful Macintosh ROM and bootable System Software disk.
No Apple assets are downloaded, bundled, or uploaded by this tool.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fp:
        for block in iter(lambda: fp.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main() -> int:
    p = argparse.ArgumentParser(description="Qualify MacSandbox M1.2 with real local Basilisk II assets")
    p.add_argument("--basilisk", required=True, type=Path)
    p.add_argument("--rom", required=True, type=Path)
    p.add_argument("--system-disk", required=True, type=Path)
    p.add_argument("--analysis-dir", required=True, type=Path)
    p.add_argument("--runtime-timeout", type=int, default=90)
    p.add_argument("--machine-profile", default="quadra650-system753")
    args = p.parse_args()

    for label, path in (("Basilisk II", args.basilisk), ("ROM", args.rom), ("system disk", args.system_disk)):
        if not path.is_file():
            raise SystemExit(f"{label} is not a regular file: {path}")

    if args.analysis_dir.exists() and any(args.analysis_dir.iterdir()):
        raise SystemExit("analysis directory must be absent or empty")
    args.analysis_dir.mkdir(parents=True, exist_ok=True)

    rom_hash = sha256(args.rom)
    disk_hash = sha256(args.system_disk)

    with tempfile.TemporaryDirectory(prefix="macsandbox-m1_2-") as td:
        command = [
            sys.executable,
            "tools/macsandbox_basilisk_runtime.py",
            "--analysis-dir", str(args.analysis_dir),
            "--machine-profile", args.machine_profile,
            "--config-fingerprint", f"m1.2:{rom_hash[:16]}:{disk_hash[:16]}",
            "--backend-revision", "local-real-runtime",
            "--rom", str(args.rom),
            "--system-disk", str(args.system_disk),
            "--system-software-id", "Mac OS 7.5.3",
            "--runtime-timeout", str(args.runtime_timeout),
            "--basilisk", str(args.basilisk),
        ]
        proc = subprocess.run(command, check=False)
        if proc.returncode not in (0, 124):
            raise SystemExit(f"runtime adapter failed: {proc.returncode}")

    session_path = args.analysis_dir / "session.json"
    events_path = args.analysis_dir / "events.jsonl"
    if not session_path.is_file() or not events_path.is_file():
        raise SystemExit("missing session.json/events.jsonl")

    session = json.loads(session_path.read_text(encoding="utf-8"))
    if session.get("rom_sha256") != rom_hash:
        raise SystemExit("ROM hash binding mismatch")
    system = session.get("system_software", {})
    if system.get("sha256") != disk_hash:
        raise SystemExit("system disk hash binding mismatch")
    if session.get("network") != "disabled" or session.get("host_shared_folders") != "disabled":
        raise SystemExit("deny-by-default runtime state not recorded")

    events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    types = {e.get("type") for e in events}
    if not {"session.start", "session.stop"}.issubset(types):
        raise SystemExit("missing lifecycle events")

    verdict = {
        "schema": "macsandbox.qualification/1",
        "milestone": "M1.2",
        "machine_profile": args.machine_profile,
        "rom_sha256": rom_hash,
        "system_disk_sha256": disk_hash,
        "network": "disabled",
        "host_shared_folders": "disabled",
        "result": "HOST_EVIDENCE_PASS",
        "note": "Visible successful Macintosh boot must be confirmed by the analyst before M1.2 is declared fully PASS.",
    }
    (args.analysis_dir / "qualification.json").write_text(json.dumps(verdict, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("MacSandbox M1.2 host evidence: PASS; visible guest boot confirmation still required")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
