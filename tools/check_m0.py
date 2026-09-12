#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
required = [
    ROOT / "README.md",
    ROOT / "BasiliskII",
    ROOT / "docs" / "M0_FOUNDATION.md",
    ROOT / "docs" / "SAFETY.md",
    ROOT / "docs" / "ROADMAP.md",
]
missing = [str(p.relative_to(ROOT)) for p in required if not p.exists()]
if missing:
    print("M0 FAIL: missing " + ", ".join(missing))
    sys.exit(1)

foundation = (ROOT / "docs" / "M0_FOUNDATION.md").read_text(encoding="utf-8")
safety = (ROOT / "docs" / "SAFETY.md").read_text(encoding="utf-8")
roadmap = (ROOT / "docs" / "ROADMAP.md").read_text(encoding="utf-8")
checks = {
    "Basilisk II scope": "Basilisk II" in foundation,
    "68k scope": "68k" in foundation,
    "session evidence": "session.json" in foundation,
    "event evidence": "events.jsonl" in foundation,
    "network deny default": "networking disabled" in safety,
    "no writable host shares": "writable host shared folders" in safety,
    "ROM handling": "ROM" in safety and "must not be committed" in safety,
    "M1 roadmap": "M1 — Analysis mode foundation" in roadmap,
    "ASW integration": "ASW" in foundation,
}
failed = [name for name, ok in checks.items() if not ok]
if failed:
    print("M0 FAIL: " + ", ".join(failed))
    sys.exit(1)
print("M0 PASS")
