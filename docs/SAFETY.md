# MacSandbox safety model

MacSandbox is designed for analysis of potentially hostile classic Macintosh 68k software. Emulator instrumentation is defense-in-depth and is not a complete security boundary.

Default policy for analysis mode:

- external guest networking disabled
- no broad writable host shared folders
- disposable writable guest media
- explicit sample ingress and artifact egress
- immutable source sample outside the guest runtime
- exact ROM/System Software hashes recorded
- exact MacSandbox revision/build recorded
- no signing, publishing or production credentials in the emulator runtime
- analysis output written only to an explicit evidence directory
- analyst-visible qualification required for physical-runtime claims

Original Apple ROM images and System Software must not be committed to this repository. CI must not assume redistribution rights for proprietary Apple assets. Full local qualification uses lawfully obtained assets.

Before real malware is introduced, qualification must demonstrate harmless sample execution, bounded lifecycle control, evidence production, cleanup and denial of unexpected host/network access.
