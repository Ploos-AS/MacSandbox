# MacSandbox roadmap

## M0 — Foundation

- project identity and upstream provenance
- 68k/Basilisk II scope
- safety model
- versioned evidence direction
- lawful ROM/System Software handling
- CI gate

## M1 — Analysis mode foundation

- explicit MacSandbox analysis mode
- versioned `session.json` and `events.jsonl`
- deterministic machine/config fingerprint
- lifecycle events
- evidence directory ownership and overwrite protection

## M1.1 — Harmless runtime qualification

- build Basilisk II on GitHub Actions where practical
- exercise host-side analysis lifecycle without proprietary assets
- define the boundary between CI-qualified host behavior and local ROM/System runtime qualification

## M2 — CPU and exception evidence

Implemented foundation:

- bounded 68k register snapshots (D0-D7, A0-A7, PC, SR)
- reset-state snapshot
- interrupt-request observations
- Mac 68k Toolbox/trap observations
- versioned `macsandbox.event/1` core evidence
- host-side event-volume limit

Remaining refinement:

- direct UAE `Exception()` vector-entry instrumentation for complete exception coverage
- periodic sampling policy beyond event-triggered snapshots
- lawful real-runtime qualification with visible Macintosh boot

## M2.1 — Memory-write/watchpoint evidence

Implemented foundation:

- CPU-visible byte/word/long guest memory-write events
- write address, width, value and CPU register context
- configurable `MACSANDBOX_WATCH_START` / `MACSANDBOX_WATCH_END`
- bounded `MACSANDBOX_EVENT_LIMIT`
- raw `core-events.jsonl` plus merged ASW-consumable `events.jsonl`
- local qualification gate requiring both CPU/trap and memory-write evidence

Public CI validates the evidence contract without Apple assets. Full runtime PASS remains gated on lawful local Macintosh ROM/System Software and visible guest boot confirmation.

## M3 — Macintosh OS behavior evidence

- Toolbox/trap observations where practical
- INIT/extension loading
- System Folder changes
- file/resource-fork mutation evidence

## M4 — Disk and filesystem evidence

- disposable guest disks
- block-write observations
- pre/post disk hashes
- explicit sample ingress image
- no writable host share dependency

## M5 — Runtime control and analyst artifacts

- local-only control channel
- bounded timeout and clean shutdown
- screenshots and analyst captures
- crash/timeout evidence
- deterministic cleanup

## M6 — ASW integration

- `mac68k` ASW Core adapter
- hash-bound evidence manifests
- harmless cross-repository qualification
- downstream Mac-specific forensic interpretation contract

## M7 — Physical qualification

- visible local qualification with lawful Macintosh ROM/System Software assets
- benign sample first
- exact machine/ROM/System hashes
- network/share denial verification
- real malware only after all preceding gates pass
