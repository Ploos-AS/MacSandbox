# M1.1 — Basilisk II runtime adapter

M1.1 connects the MacSandbox evidence contract to a real, externally supplied Basilisk II executable without redistributing Apple ROM images or System Software.

## Runtime inputs

The adapter requires:

- an executable Basilisk II binary;
- an external Macintosh ROM image;
- an external boot/system disk image;
- a machine profile identifier;
- an exact backend revision;
- a configuration fingerprint;
- a human-readable System Software identifier.

The ROM and system disk are read in place and SHA-256 hashed before launch. They are not copied into the repository or evidence directory.

## Isolation

The adapter creates a private temporary `HOME`, writes a private `.basilisk_ii_prefs`, and launches Basilisk II without `shell=True`.

The generated preferences disable or neutralize the features MacSandbox must not expose by default:

- Ethernet: disabled;
- host directory sharing (`extfs`): disabled;
- serial devices: disabled;
- JIT: disabled;
- CD-ROM passthrough: disabled;
- sound: disabled for deterministic qualification.

A production malware-analysis host must add an OS-level sandbox around the emulator. Emulator configuration alone is not a sufficient security boundary.

## Lifecycle

The process is started in a new process session and receives a bounded runtime. On timeout the adapter sends `SIGTERM`, waits a bounded grace period, and escalates to `SIGKILL` if required.

Evidence includes:

- `session.json` (`macsandbox.session/1`);
- `events.jsonl` (`macsandbox.event/1`);
- Basilisk II stdout/stderr logs;
- exact ROM SHA-256;
- exact system disk SHA-256;
- backend revision;
- machine profile and config fingerprint;
- process start/termination events and exit status.

## CI qualification

Public CI cannot contain proprietary Apple ROM or System Software. Therefore the M1.1 GitHub qualification uses a harmless executable stub plus non-Apple placeholder files to verify lifecycle, hashing, timeout, termination, and evidence semantics.

That CI result proves the host-side adapter contract only. It does **not** prove that a Macintosh has booted.

A real Basilisk II qualification requires locally supplied lawful ROM/System Software and is a separate gate. Later milestones should add a deterministic benign guest workload and visible local qualification before hostile samples are introduced.
