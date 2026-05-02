# M07: chio-kernel-mobile MVP + Device Attestation

**Wave:** W2  |  **Trust-boundary:** yes  |  **Tickets:** 25  |  **Effort weeks:** 8/11/15

## In one paragraph

M07 ships a real iOS + Android kernel binding with hardware-attested
keys via Apple App Attest and Android Play Integrity (D11). Release-
gate anchor is PROTOCOL: mobile receipts verify against the M01
hosted oracle and the attestation chain is documented under
`.planning/trajectory-3/audits/M07-mobile-mvp.md`. Implementation is
inventory + audit-doc fill at P0 (the
`crates/chio-kernel-mobile/` crate already exists at ~1226 LOC), then
three new UDL entries at P1 to grow the C-ABI surface from 4 to 7,
then iOS Swift framework at P2 and Android Kotlin AAR at P3, then a
hosted-oracle round trip at P4, then an Opus mobile patient-app
demo at P5.

## Phases at a glance

| Phase | Tickets | One-liner |
|-------|---------|-----------|
| P0    | 4 | Inventory + audit-doc fill (NOT scaffold-from-zero); pin counts + threat-model rows |
| P1    | 5 | Three new UDL entries (`attest_app_attest`, `attest_play_integrity`, `verify_mobile_receipt`); cross-platform parity test |
| P2    | 5 | iOS Swift framework (XCFramework + SPM) + App Attest integration |
| P3    | 5 | Android Kotlin AAR (Gradle) + Play Integrity integration |
| P4    | 4 | Mobile receipt verification against the M01 hosted oracle + offline-queue path |
| P5    | 4 | Opus mobile patient-app extension demo (Expo Module bridge) + closure attestations |

Sub-totals: 4 + 5 + 5 + 5 + 4 + 4 = **27** tickets across six
phases. (P1 includes a reference-doc refresh ticket; P0 includes a
threat-model row ticket alongside the inventory work.)

## Locked decisions

- **D11** App Attest + Play Integrity only; no custom HSM lane;
  iOS + Android both ship.

## Active freezes

`m07-kernel-mobile-pivot` covers
`crates/chio-kernel-mobile/**`, `sdks/swift/**`, `sdks/kotlin/**`,
and `crates/chio-custody-hw/src/attestation/**` from M07.P1.T1
through M07.P4.T5. Hot-fix bypass: `hotfix/* + [trajectory-3]`.

`m01-m07-audit-handoff` (owned by M01, consumed by M07) holds
`.planning/trajectory-3/audits/M01-opus-pilot.md` stable from
M01.P5.T1 through M01.P5.T5; M07.P5 starts only after M01.P5.T5
merges.

`m01-m09-audit-handoff` (owned by M01, soft-consumed by M07.P4.T3)
holds `spec/audit-log/export-schema.v1.json` stable from M01.P3.T1
through M01.P5.T5; M07's mobile-receipt round-trip test consumes
the schema once it lands.

## Soft blockers

- **M07.P4.T3** is soft-blocked on **M01.P3.T1** (audit-log export
  schema v1). The mobile receipt POST endpoint URL + auth shape
  depends on the M01-published schema.
- **M07.P5** starts after **M01.P5.T5** merges (Opus operator
  runbook + first-30-day pilot evidence).

## Cross-trajectory references (informational, not blockers)

- `crates/chio-custody-hw/` extension: M07 adds a new
  `attestation/` submodule complementary to the trajectory-2 M10
  WebAuthn passkey path. The trajectory-2 M10 freeze is closed on
  `main`; M07 is the active owner of the attestation subdirectory.
- `crates/chio-kernel-browser/` (trajectory-2 M08): the mobile
  UniFFI surface stays symmetric with the WASM browser kernel
  shape; cross-platform parity test (P1.T4) asserts byte-equal
  verdicts.
- `crates/chio-bindings-ffi/` and `crates/chio-cpp-kernel-ffi/`:
  the mobile UniFFI surface mirrors `chio-cpp-kernel-ffi`'s
  JSON-in / JSON-out shape; not edited.

## Customer

Opus mobile patient-app extension (Backbay healthcare cluster mobile
app; M01 design partner extension per **D09**). M07.P5 ships the
SDK consumption surface; the demo recording + cross-repo PR live in
the Opus cluster repo.

## When this milestone is done

- iOS XCFramework + Android AAR build clean and verify mobile
  receipts against the M01 hosted oracle.
- Apple / Google attestation services issue valid attestations
  against the binaries (their issuance IS the third-party evidence
  per the verdict's external-evidence column).
- Opus mobile patient-app demo green; M01 P5 hand-off consumed.
- Three new threat-model rows
  (`mobile_attestation_replay`, `device_key_extraction`,
  `play_integrity_token_replay`) flip to `coverage_state: covered`.
- Audit doc at
  `.planning/trajectory-3/audits/M07-mobile-mvp.md` closes with the
  measured before / after counts plus the App Attest / Play
  Integrity attestation chain documentation.
