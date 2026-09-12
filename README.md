# MacSandbox

**MacSandbox — Basilisk II Malware Analysis Edition**

MacSandbox is a malware-analysis-oriented derivative of the macemu/Basilisk II codebase for classic **68k Macintosh** systems. The inherited macemu tree also contains SheepShaver and cxmon, but the initial MacSandbox analysis backend is deliberately scoped to Basilisk II and 68k Macintosh.

The project is intended to become the `mac68k` runtime backend for ASW Core. M0 establishes provenance, safety boundaries, evidence contracts and the roadmap; it does **not** yet claim hostile-sample runtime qualification.

Key M0 rules:

- external guest networking disabled by default in future analysis mode
- no broad writable host shared folders
- disposable writable guest media
- explicit sample ingress and artifact egress
- exact emulator revision/build recorded
- exact ROM and System Software identities/hashes recorded
- Apple ROM/System Software assets are not committed to this repository
- minimum future evidence is `session.json` plus `events.jsonl`
- physical runtime claims require visible local qualification

See `docs/M0_FOUNDATION.md`, `docs/SAFETY.md` and `docs/ROADMAP.md`.

## Upstream provenance

MacSandbox tracks the `kanjitalk755/macemu` lineage. The M0 baseline is commit `892eeb74ab9d70dfb034138a0b39057b14f275bc`. Upstream licensing and notices remain authoritative for inherited code.

## Qualification

```sh
python3 tools/check_m0.py
```

## Upstream build notes

### BasiliskII

```text
macOS     x86_64 JIT / arm64 non-JIT
Linux x86 x86_64 JIT / arm64 non-JIT
MinGW x86        JIT
```

### SheepShaver

```text
macOS     x86_64 JIT / arm64 non-JIT
Linux x86 x86_64 JIT / arm64 non-JIT
MinGW x86        JIT
```

These builds need SDL 2.0.14+ framework/library.

### BasiliskII — Linux

On arm64, install GMP and MPFR first.

```sh
cd BasiliskII/src/Unix
./autogen.sh
make
```

### BasiliskII — macOS

Install required GMP/MPFR libraries, then:

```sh
cd BasiliskII/src/MacOSX
xcodebuild build -project BasiliskII.xcodeproj -configuration Release
```

### BasiliskII — MinGW32/MSYS2

```sh
pacman -S base-devel mingw-w64-i686-toolchain autoconf automake mingw-w64-i686-SDL2
cd BasiliskII/src/Windows
../Unix/autogen.sh
make
```

SheepShaver remains inherited upstream functionality and is not part of the initial MacSandbox 68k malware-analysis qualification path.
