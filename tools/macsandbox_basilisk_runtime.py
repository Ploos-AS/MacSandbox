#!/usr/bin/env python3
"""MacSandbox Basilisk II runtime adapter.

Launches an externally supplied Basilisk II binary using an isolated HOME,
hashes lawful user-supplied ROM/System Software assets, records lifecycle and
core instrumentation evidence, and enforces a bounded runtime.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import tempfile
import time
from pathlib import Path

SESSION_SCHEMA = "macsandbox.session/1"
EVENT_SCHEMA = "macsandbox.event/1"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path: Path, value: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def append_event(path: Path, event: dict) -> None:
    with path.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")


def require_regular_file(path: Path, label: str) -> Path:
    resolved = path.expanduser().resolve(strict=True)
    if not resolved.is_file() or resolved.is_symlink():
        raise SystemExit(f"{label} must be a regular non-symlink file")
    return resolved


def int_auto(value: str) -> int:
    return int(value, 0)


def merge_core_events(core_path: Path, events_path: Path, limit: int) -> int:
    if not core_path.is_file():
        return 0
    count = 0
    for line in core_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        if event.get("schema") != EVENT_SCHEMA:
            raise SystemExit("unexpected core event schema")
        append_event(events_path, event)
        count += 1
        if count > limit:
            raise SystemExit("core evidence exceeded configured event limit")
    return count


def main() -> int:
    p = argparse.ArgumentParser(description="MacSandbox Basilisk II runtime adapter")
    p.add_argument("--analysis-dir", required=True)
    p.add_argument("--basilisk-binary", required=True)
    p.add_argument("--rom", required=True)
    p.add_argument("--system-disk", required=True)
    p.add_argument("--system-software-id", required=True)
    p.add_argument("--machine-profile", required=True)
    p.add_argument("--config-fingerprint", required=True)
    p.add_argument("--backend-revision", required=True)
    p.add_argument("--runtime-seconds", type=float, default=10.0)
    p.add_argument("--grace-seconds", type=float, default=3.0)
    p.add_argument("--display", default=None)
    p.add_argument("--core-event-limit", type=int, default=4096)
    p.add_argument("--watch-start", type=int_auto, default=0)
    p.add_argument("--watch-end", type=int_auto, default=0xFFFFFFFF)
    args = p.parse_args()

    if args.runtime_seconds <= 0 or args.grace_seconds <= 0:
        raise SystemExit("runtime and grace periods must be positive")
    if args.core_event_limit <= 0:
        raise SystemExit("core event limit must be positive")
    if not (0 <= args.watch_start <= args.watch_end <= 0xFFFFFFFF):
        raise SystemExit("invalid memory watch range")

    analysis_dir = Path(args.analysis_dir).resolve()
    if analysis_dir.exists() and any(analysis_dir.iterdir()):
        raise SystemExit("analysis directory must be absent or empty")
    analysis_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    binary = require_regular_file(Path(args.basilisk_binary), "Basilisk II binary")
    if not os.access(binary, os.X_OK):
        raise SystemExit("Basilisk II binary is not executable")
    rom = require_regular_file(Path(args.rom), "ROM")
    system_disk = require_regular_file(Path(args.system_disk), "system disk")

    rom_sha = sha256_file(rom)
    system_sha = sha256_file(system_disk)
    started = time.time()
    session_path = analysis_dir / "session.json"
    events_path = analysis_dir / "events.jsonl"
    core_path = analysis_dir / "core-events.jsonl"
    stdout_path = analysis_dir / "basiliskii.stdout.log"
    stderr_path = analysis_dir / "basiliskii.stderr.log"

    session = {
        "schema": SESSION_SCHEMA,
        "backend": "basiliskii",
        "backend_revision": args.backend_revision,
        "machine_profile": args.machine_profile,
        "config_fingerprint": args.config_fingerprint,
        "rom_sha256": rom_sha,
        "system_software": {"id": args.system_software_id, "sha256": system_sha},
        "network": "disabled",
        "host_shared_folders": "disabled",
        "jit": "disabled",
        "runtime_adapter": "macsandbox.m2_1",
        "runtime_limit_seconds": args.runtime_seconds,
        "core_evidence": "core-events.jsonl",
        "core_event_limit": args.core_event_limit,
        "memory_watch": {"start": args.watch_start, "end": args.watch_end},
        "core_event_count": 0,
        "started_unix": started,
        "ended_unix": None,
        "exit_code": None,
        "termination": None,
    }
    write_json(session_path, session)
    append_event(events_path, {
        "schema": EVENT_SCHEMA,
        "type": "session.start",
        "timestamp_unix": started,
        "rom_sha256": rom_sha,
        "system_software_sha256": system_sha,
    })

    with tempfile.TemporaryDirectory(prefix="macsandbox-home-") as home, \
         stdout_path.open("wb") as out, stderr_path.open("wb") as err:
        home_path = Path(home)
        prefs = home_path / ".basilisk_ii_prefs"
        prefs.write_text(
            "\n".join([
                f"rom {rom}",
                f"disk {system_disk}",
                "ether false",
                "seriala none",
                "serialb none",
                "jit false",
                "extfs none",
                "nocdrom true",
                "nosound true",
                "frameskip 0",
            ]) + "\n",
            encoding="utf-8",
        )
        env = os.environ.copy()
        env["HOME"] = str(home_path)
        env["MACSANDBOX_ANALYSIS_DIR"] = str(analysis_dir)
        env["MACSANDBOX_EVENT_LIMIT"] = str(args.core_event_limit)
        env["MACSANDBOX_WATCH_START"] = hex(args.watch_start)
        env["MACSANDBOX_WATCH_END"] = hex(args.watch_end)
        if args.display is not None:
            env["DISPLAY"] = args.display

        proc = subprocess.Popen(
            [str(binary)],
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=err,
            env=env,
            start_new_session=True,
        )
        append_event(events_path, {
            "schema": EVENT_SCHEMA,
            "type": "backend.start",
            "timestamp_unix": time.time(),
            "pid": proc.pid,
        })
        termination = "natural"
        try:
            proc.wait(timeout=args.runtime_seconds)
        except subprocess.TimeoutExpired:
            termination = "sigterm"
            os.killpg(proc.pid, signal.SIGTERM)
            append_event(events_path, {
                "schema": EVENT_SCHEMA,
                "type": "backend.terminate",
                "timestamp_unix": time.time(),
                "signal": "SIGTERM",
            })
            try:
                proc.wait(timeout=args.grace_seconds)
            except subprocess.TimeoutExpired:
                termination = "sigkill"
                os.killpg(proc.pid, signal.SIGKILL)
                append_event(events_path, {
                    "schema": EVENT_SCHEMA,
                    "type": "backend.kill",
                    "timestamp_unix": time.time(),
                    "signal": "SIGKILL",
                })
                proc.wait()

    ended = time.time()
    exit_code = proc.returncode
    core_count = merge_core_events(core_path, events_path, args.core_event_limit)
    append_event(events_path, {
        "schema": EVENT_SCHEMA,
        "type": "session.stop",
        "timestamp_unix": ended,
        "exit_code": exit_code,
        "termination": termination,
        "core_event_count": core_count,
    })
    session["core_event_count"] = core_count
    session["ended_unix"] = ended
    session["exit_code"] = exit_code
    session["termination"] = termination
    write_json(session_path, session)
    return 0 if exit_code in (0, -signal.SIGTERM, -signal.SIGKILL) else exit_code


if __name__ == "__main__":
    raise SystemExit(main())
