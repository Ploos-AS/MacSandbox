# M0 — MacSandbox foundation

MacSandbox is the Macintosh 68k malware-analysis edition of the macemu/Basilisk II codebase.

## Scope

M0 establishes project identity, provenance, safety boundaries, analysis artifacts and the milestone path. It does not yet claim runtime malware-analysis qualification.

The initial runtime target is **Basilisk II / 68k Macintosh**. SheepShaver is retained from upstream but is outside the initial MacSandbox malware-analysis scope because it targets PowerPC Macintosh systems.

## Upstream baseline

- project family: macemu
- primary runtime: Basilisk II
- source repository used for this fork: kanjitalk755/macemu lineage
- MacSandbox baseline commit: `892eeb74ab9d70dfb034138a0b39057b14f275bc`
- default branch at M0: `master`
- upstream licensing and notices remain authoritative for inherited code

MacSandbox-specific changes must remain clearly identifiable so future upstream synchronization is practical.

## Analysis contract

Future analysis mode will emit at minimum:

- `session.json`
- `events.jsonl`

The evidence contract is versioned. A session must bind the exact MacSandbox revision/build, machine profile, ROM identity/hash, System Software identity/hash where applicable, analysis configuration and security state.

Planned event families include:

- session lifecycle
- CPU/register snapshots
- exceptions and vectors
- memory writes/watchpoints
- Toolbox/trap observations where practical
- INIT/extension activity
- resource-fork and file mutations
- System Folder changes
- block-device writes
- pre/post disk hashes
- screenshots and explicit analyst captures

## Initial machine direction

The first supported profiles should cover representative 68k Macintosh configurations suitable for Basilisk II, beginning with a conservative Mac II-class profile before expanding the matrix.

Original Apple ROM and System Software are not committed to this repository. Full qualification uses lawfully obtained local assets with hashes recorded in evidence.

## ASW integration

MacSandbox is the planned runtime backend for the `mac68k` platform in ASW Core. ASW owns sample custody, immutable originals, platform namespace separation, evidence association and approval workflow. MacSandbox owns guest execution and low-level runtime evidence.

## M0 exit criteria

- inherited macemu/Basilisk II code remains buildable in principle and provenance is documented
- project scope is explicitly 68k Macintosh for the initial backend
- security defaults are documented
- minimum evidence contract is documented
- Apple ROM/System Software handling is explicit
- roadmap exists
- repository-side M0 checker and CI workflow exist

M0 does not claim that hostile samples can safely be executed yet.
