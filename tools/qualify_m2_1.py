#!/usr/bin/env python3
"""Validate MacSandbox M2/M2.1 evidence from a lawful local runtime."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

EVENT_SCHEMA = "macsandbox.event/1"


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def validate_registers(event: dict) -> None:
    if not isinstance(event.get("pc"), int) or not isinstance(event.get("sr"), int):
        raise SystemExit("CPU event missing integer PC/SR")
    for bank in ("d", "a"):
        regs = event.get(bank)
        if not isinstance(regs, list) or len(regs) != 8:
            raise SystemExit(f"CPU event has invalid {bank.upper()} register bank")
        if not all(isinstance(value, int) and 0 <= value <= 0xFFFFFFFF for value in regs):
            raise SystemExit(f"CPU event has invalid {bank.upper()} register value")


def main() -> int:
    p = argparse.ArgumentParser(description="Qualify MacSandbox M2.1 runtime evidence")
    p.add_argument("--analysis-dir", type=Path, required=True)
    p.add_argument("--visible-boot-confirmed", action="store_true")
    args = p.parse_args()

    root = args.analysis_dir.resolve()
    session_path = root / "session.json"
    events_path = root / "events.jsonl"
    core_path = root / "core-events.jsonl"
    for path in (session_path, events_path, core_path):
        if not path.is_file():
            raise SystemExit(f"missing evidence file: {path.name}")

    session = json.loads(session_path.read_text(encoding="utf-8"))
    if session.get("schema") != "macsandbox.session/1":
        raise SystemExit("unexpected session schema")
    if session.get("network") != "disabled" or session.get("host_shared_folders") != "disabled":
        raise SystemExit("sandbox deny-by-default state not recorded")
    if session.get("jit") != "disabled":
        raise SystemExit("JIT must be disabled for qualified analysis")

    core = read_jsonl(core_path)
    if not core:
        raise SystemExit("empty core evidence")
    limit = session.get("core_event_limit")
    if not isinstance(limit, int) or limit <= 0 or len(core) > limit:
        raise SystemExit("invalid or exceeded core event limit")
    if session.get("core_event_count") != len(core):
        raise SystemExit("core event count binding mismatch")

    for event in core:
        if event.get("schema") != EVENT_SCHEMA:
            raise SystemExit("unexpected core event schema")

    cpu = [e for e in core if e.get("type") in {"cpu.snapshot", "cpu.interrupt.request", "mac.toolbox_trap"}]
    writes = [e for e in core if e.get("type") == "memory.write"]
    if not cpu:
        raise SystemExit("missing M2 CPU/trap evidence")
    if not writes:
        raise SystemExit("missing M2.1 memory.write evidence")

    for event in cpu:
        validate_registers(event)
    watch = session.get("memory_watch", {})
    start, end = watch.get("start"), watch.get("end")
    if not isinstance(start, int) or not isinstance(end, int) or start > end:
        raise SystemExit("invalid session memory watch range")
    for event in writes:
        validate_registers(event)
        for key in ("address", "size", "value"):
            if not isinstance(event.get(key), int):
                raise SystemExit(f"invalid memory.write field: {key}")
        if event["size"] not in (1, 2, 4):
            raise SystemExit("invalid memory.write size")
        if not start <= event["address"] <= end:
            raise SystemExit("memory.write outside configured watch range")

    unified = read_jsonl(events_path)
    if not any(e.get("type") == "session.start" for e in unified):
        raise SystemExit("missing session.start")
    if not any(e.get("type") == "session.stop" for e in unified):
        raise SystemExit("missing session.stop")
    if sum(1 for e in unified if e.get("type") == "memory.write") != len(writes):
        raise SystemExit("unified evidence stream does not contain all core memory events")

    verdict = {
        "schema": "macsandbox.m2_1.qualification/1",
        "milestone": "M2.1",
        "machine_profile": session.get("machine_profile"),
        "backend_revision": session.get("backend_revision"),
        "cpu_events": len(cpu),
        "memory_write_events": len(writes),
        "core_event_limit": limit,
        "rom_sha256": session.get("rom_sha256"),
        "system_disk_sha256": session.get("system_software", {}).get("sha256"),
        "visible_boot_confirmed": args.visible_boot_confirmed,
        "result": "PASS" if args.visible_boot_confirmed else "HOST_EVIDENCE_PASS",
    }
    (root / "m2_1-qualification.json").write_text(
        json.dumps(verdict, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if args.visible_boot_confirmed:
        print(f"MacSandbox M2.1 PASS: {len(cpu)} CPU/trap events, {len(writes)} memory writes")
    else:
        print("MacSandbox M2.1 host evidence PASS; visible lawful Macintosh boot confirmation remains required")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
