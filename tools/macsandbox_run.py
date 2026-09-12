#!/usr/bin/env python3
"""MacSandbox M1 analysis evidence lifecycle runner.

M1 intentionally does not boot Basilisk II yet. It establishes the stable
session/event contract that later runtime instrumentation will feed.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path

SESSION_SCHEMA = "macsandbox.session/1"
EVENT_SCHEMA = "macsandbox.event/1"


def write_json(path: Path, value: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def append_event(path: Path, event: dict) -> None:
    with path.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="MacSandbox M1 analysis lifecycle runner")
    parser.add_argument("--analysis-dir", required=True)
    parser.add_argument("--machine-profile", required=True)
    parser.add_argument("--config-fingerprint", required=True)
    parser.add_argument("--backend-revision", required=True)
    parser.add_argument("--rom-sha256", required=True)
    parser.add_argument("--system-software-id", required=True)
    parser.add_argument("--system-software-sha256", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER,
                        help="optional harmless command for lifecycle qualification")
    args = parser.parse_args()

    analysis_dir = Path(args.analysis_dir).resolve()
    if analysis_dir.exists():
        if any(analysis_dir.iterdir()):
            raise SystemExit("analysis directory must be absent or empty")
    else:
        analysis_dir.mkdir(parents=True, mode=0o700)

    started = time.time()
    session_path = analysis_dir / "session.json"
    events_path = analysis_dir / "events.jsonl"

    session = {
        "schema": SESSION_SCHEMA,
        "backend": "basiliskii",
        "backend_revision": args.backend_revision,
        "machine_profile": args.machine_profile,
        "config_fingerprint": args.config_fingerprint,
        "rom_sha256": args.rom_sha256,
        "system_software": {
            "id": args.system_software_id,
            "sha256": args.system_software_sha256,
        },
        "network": "disabled",
        "host_shared_folders": "disabled",
        "jit": "disabled",
        "started_unix": started,
        "ended_unix": None,
        "exit_code": None,
    }
    write_json(session_path, session)
    append_event(events_path, {
        "schema": EVENT_SCHEMA,
        "type": "session.start",
        "timestamp_unix": started,
    })

    exit_code = 0
    if args.command:
        exit_code = subprocess.run(args.command, check=False).returncode

    ended = time.time()
    append_event(events_path, {
        "schema": EVENT_SCHEMA,
        "type": "session.stop",
        "timestamp_unix": ended,
        "exit_code": exit_code,
    })
    session["ended_unix"] = ended
    session["exit_code"] = exit_code
    write_json(session_path, session)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
