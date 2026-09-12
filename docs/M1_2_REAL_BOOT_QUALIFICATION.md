# M1.2 — Real Basilisk II boot qualification

M1.2 is the first MacSandbox gate that requires real Macintosh runtime assets.

## Reference profile

The initial reference profile is:

- backend: Basilisk II
- machine class: Quadra-class 68040 Macintosh
- preferred qualification label: `quadra650-system753`
- System Software target: Mac OS / System 7.5.3
- visible emulator execution required for the final local verdict

The Quadra 650 is a suitable reference because it is a 68040 Macintosh and Apple documents support for System 7.5.3 on that model.

## Asset policy

MacSandbox does **not** bundle, download, mirror, or redistribute Apple Macintosh ROM images or Apple System Software.

The analyst supplies locally held assets:

1. a Basilisk II-compatible 68k Macintosh ROM obtained lawfully;
2. a bootable System Software disk/image the analyst is entitled to use.

The assets stay outside the repository. MacSandbox records SHA-256 identities in evidence. No ROM or System Software bytes may be uploaded as GitHub Actions artifacts.

## Qualification command

```sh
python3 tools/qualify_m1_2.py \
  --basilisk /path/to/BasiliskII \
  --rom /path/to/ROM \
  --system-disk /path/to/system753.img \
  --analysis-dir /tmp/macsandbox-m1_2 \
  --runtime-timeout 90
```

The runtime must remain visible for the analyst. A host-side evidence PASS alone is not a full M1.2 PASS.

## Required evidence

The qualification directory must contain at least:

- `session.json`
- `events.jsonl`
- `qualification.json`
- captured Basilisk II stdout/stderr produced by the runtime adapter

The session binds the run to the ROM SHA-256 and System Software disk SHA-256 and records deny-by-default network and host-share state.

## Final gate

M1.2 is fully PASS only when all of these are true:

- Basilisk II starts using the supplied assets;
- a Macintosh desktop or otherwise unambiguous successful System Software boot is visibly observed;
- ROM and system-disk hashes are bound into the session;
- networking is disabled;
- writable host-directory sharing is disabled;
- `session.start` and `session.stop` exist;
- the runtime is stopped within the bounded lifecycle;
- evidence remains available after the disposable runtime state is destroyed.

Until visible guest boot is observed, report the result only as `HOST_EVIDENCE_PASS`, never as full M1.2 PASS.
