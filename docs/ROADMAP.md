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

- periodic 68k register snapshots
- PC/SR capture
- exception/vector observations
- bounded sampling and event volume

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
