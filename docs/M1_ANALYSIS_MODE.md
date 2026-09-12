# M1 — Analysis mode foundation

M1 establishes MacSandbox's stable host-side evidence contract before Basilisk II runtime instrumentation is introduced.

## Scope

The M1 runner creates one fresh analysis directory and emits:

- `session.json` using schema `macsandbox.session/1`
- `events.jsonl` using schema `macsandbox.event/1`

The lifecycle contains at least `session.start` and `session.stop` events.

The session binds the run to:

- Basilisk II backend identity and exact revision
- Mac machine profile
- deterministic configuration fingerprint
- Macintosh ROM SHA-256
- System Software identity and SHA-256
- networking disabled
- writable host shared folders disabled
- JIT disabled for analysis qualification
- start/end timestamps and exit status

ROM and System Software bytes are not stored by this contract and must not be committed to the repository. Only identifiers and hashes are recorded.

## Safety

The M1 runner is a lifecycle/evidence harness. It does not execute malware and does not yet boot Basilisk II. An optional command exists only for harmless CI lifecycle qualification and is invoked with an argument vector through `subprocess.run`, never through a shell.

The evidence directory must be absent or empty. Existing evidence is never silently overwritten.

## Qualification

M1 is repository-qualified when:

1. the M0 foundation check passes;
2. the M1 unit tests pass;
3. the GitHub Actions M1 workflow validates generated JSON/JSONL evidence;
4. no proprietary Macintosh ROM or System Software is required by CI.

A real Basilisk II boot is a later milestone because a lawful ROM/System Software path is required. Repository-side M1 PASS therefore means the stable analysis lifecycle contract is qualified, not that a classic Mac runtime has yet been qualified.
