# M06 Audit: Focused Formal Invariants + Supply-Chain Hygiene v2

**Trajectory:** trajectory-3
**Milestone:** M06
**Wave:** W2
**Status:** P0 baseline open
**Audit start:** 2026-05-02
**Audit close:** <fill at P5 final ticket merge>

## 1. Audit scope

M06 closes 4 highest-leverage TLA+/Apalache invariants on a kernel-state
subset (D04 caps the formal scope) and ships supply-chain hygiene v2
(cargo-vet adoption, SBOM publication, CVE alerting; D05 caps the
supply-chain scope). Release gates: QUALIFICATION (the formal half) plus
RELEASE_AUDIT (the supply-chain half).

The Apalache invariants are:

1. `MonotoneLogApalache` (port of TLA+ `MonotoneLog` from
   `RevocationPropagation.tla`).
2. `RevocationCutCompleteness` (new; lifts Lean `revocation_is_cut` to a
   state-machine invariant).
3. `ReceiptBeforeAllow` (new; names the joint discharge of
   `RETIRED-SQLITE-CROSS-ROW` as a single Apalache invariant).
4. `KernelTransitionCancelSafe` (new; covers cross-step interleaving Kani
   cannot model).

Out of scope per D04 / D05: full delegation FSM Apalache model (deferred to
trajectory-4); crate consolidation 88 -> <=70 (deferred to trajectory-4);
new Lean theorems; new Kani harnesses; SPDX SBOM emission unless the M09
assessor demands it.

Reference-runner contract for the Apalache CI lane: GitHub Actions hosted
`ubuntu-24.04`, Apalache 0.51.0 (or latest tagged at the P0 open date), Z3
default solver, bounded sets `Authorities = 1..3`, `CapSet = 1..6`,
`EpochMax = 4`, per-invariant SMT timeout 30 minutes. The reference runner
contract is identical to the M03 hosted CI runner (D13).

## 2. Hard counts

### At P0 (measured 2026-05-02)

The ticket seed expected 90 workspace crates, 891 cargo-vet exemption rows,
10 deny.toml advisory ignores, 30 Kani proofs, 83 Lean theorems, and 8 TLA+
named invariants. Current repo state has drifted since that scaffold. This
baseline records both the seed values needed for trajectory gate continuity
and the measured counts that M06 must close against.

- Lean theorem inventory rows: 71 in `formal/theorem-inventory.json`.
- Raw Lean theorem grep hits: 89, including comments and private helpers.
- Lean `sorry` markers: 0.
- Lean audited assumptions inside `theorem-inventory.json`: 0.
- Active assumption registry rows: 10 in `formal/assumptions.toml`.
- TLA+ named invariants: 8 (5 in `RevocationPropagation.tla`, 3 in
  `DelegationDepthBound.tla`).
- Apalache invariants today: 0 (`formal/apalache/` does not exist).
- Kani `#[kani::proof]` attributes: 30.
- Workspace crate count: 107 current members; ticket seed expected 90.
- Cargo.lock package records: 1159 current records; ticket seed expected
  1147.
- cargo-vet first-party certifications: 26.
- cargo-vet exemption rows (audit-this-later baseline): 891.
- cargo-vet import feeds: 4 (bytecode-alliance, google, mozilla, zcash).
- deny.toml advisory-ignore rows: 13 current rows; ticket seed expected 10.
- CVE alerts open against current deps: `cargo audit --quiet` reported 10
  vulnerability findings and 12 allowed warnings on 2026-05-02.

Current deny.toml ignore list:

- `RUSTSEC-2026-0049`
- `RUSTSEC-2026-0098`
- `RUSTSEC-2026-0099`
- `RUSTSEC-2026-0104`
- `RUSTSEC-2025-0141`
- `RUSTSEC-2024-0436`
- `RUSTSEC-2025-0134`
- `RUSTSEC-2025-0068`
- `RUSTSEC-2026-0097`
- `RUSTSEC-2023-0071`
- `RUSTSEC-2021-0139`
- `RUSTSEC-2024-0375`
- `RUSTSEC-2024-0370`

Cargo-audit P0 findings:

- Vulnerability findings: `RUSTSEC-2025-0020` (`pyo3` 0.22.6),
  `RUSTSEC-2023-0071` (`rsa` 0.9.10), `RUSTSEC-2026-0104`
  (`rustls-webpki` 0.101.7 and 0.103.9), `RUSTSEC-2026-0098`
  (`rustls-webpki` 0.101.7 and 0.103.9), `RUSTSEC-2026-0099`
  (`rustls-webpki` 0.101.7 and 0.103.9), `RUSTSEC-2026-0049`
  (`rustls-webpki` 0.103.9), and `RUSTSEC-2026-0114` (`wasmtime`
  43.0.1).
- Allowed warnings: `RUSTSEC-2021-0139`, `RUSTSEC-2024-0375`,
  `RUSTSEC-2025-0141`, `RUSTSEC-2024-0388`, `RUSTSEC-2024-0436`,
  `RUSTSEC-2024-0370`, `RUSTSEC-2025-0134`, `RUSTSEC-2021-0145`,
  `RUSTSEC-2025-0067`, `RUSTSEC-2026-0097`, and `RUSTSEC-2025-0068`.

### top-50 transitive dependency centrality target

Generated from `cargo metadata --format-version 1` over the current
workspace resolve graph. Centrality is the number of unique package nodes that
directly depend on a non-workspace package id.

1. `serde` 1.0.228 - reverse_edges=223
2. `serde_json` 1.0.149 - reverse_edges=156
3. `quote` 1.0.45 - reverse_edges=102
4. `syn` 2.0.117 - reverse_edges=96
5. `proc-macro2` 1.0.106 - reverse_edges=93
6. `thiserror` 1.0.69 - reverse_edges=87
7. `tokio` 1.50.0 - reverse_edges=65
8. `tracing` 0.1.44 - reverse_edges=63
9. `libc` 0.2.183 - reverse_edges=58
10. `log` 0.4.29 - reverse_edges=54
11. `bytes` 1.11.1 - reverse_edges=53
12. `cfg-if` 1.0.4 - reverse_edges=45
13. `sha2` 0.10.9 - reverse_edges=45
14. `zeroize` 1.8.2 - reverse_edges=35
15. `http` 1.4.0 - reverse_edges=34
16. `pin-project-lite` 0.2.17 - reverse_edges=34
17. `indexmap` 2.13.0 - reverse_edges=33
18. `anyhow` 1.0.102 - reverse_edges=32
19. `once_cell` 1.21.4 - reverse_edges=32
20. `url` 2.5.8 - reverse_edges=31
21. `hex` 0.4.3 - reverse_edges=29
22. `bitflags` 2.11.0 - reverse_edges=27
23. `num-traits` 0.2.19 - reverse_edges=27
24. `alloy-primitives` 1.5.7 - reverse_edges=26
25. `base64` 0.22.1 - reverse_edges=26
26. `chrono` 0.4.44 - reverse_edges=26
27. `futures-core` 0.3.32 - reverse_edges=25
28. `rand_core` 0.6.4 - reverse_edges=25
29. `subtle` 2.6.1 - reverse_edges=24
30. `thiserror` 2.0.18 - reverse_edges=24
31. `futures-util` 0.3.32 - reverse_edges=23
32. `cc` 1.2.57 - reverse_edges=22
33. `memchr` 2.8.0 - reverse_edges=22
34. `percent-encoding` 2.3.2 - reverse_edges=21
35. `regex` 1.12.3 - reverse_edges=21
36. `smallvec` 1.15.1 - reverse_edges=21
37. `windows-sys` 0.61.2 - reverse_edges=20
38. `digest` 0.10.7 - reverse_edges=19
39. `serde_core` 1.0.228 - reverse_edges=19
40. `tower-service` 0.3.3 - reverse_edges=19
41. `proptest` 1.10.0 - reverse_edges=18
42. `serde_derive` 1.0.228 - reverse_edges=18
43. `wasm-bindgen` 0.2.114 - reverse_edges=18
44. `async-trait` 0.1.89 - reverse_edges=17
45. `heck` 0.5.0 - reverse_edges=17
46. `http-body` 1.0.1 - reverse_edges=17
47. `http-body-util` 0.1.3 - reverse_edges=17
48. `itoa` 1.0.17 - reverse_edges=17
49. `rustls-pki-types` 1.14.0 - reverse_edges=17
50. `tempfile` 3.27.0 - reverse_edges=17

Crypto dependency note: `ed25519-dalek` ranked 86 with reverse_edges=8 and
must still be included in the M06.P2 cargo-vet certification target because
capability and receipt signing make it trust-boundary critical even though its
reverse-edge centrality is below the top-50 threshold.

### At P2 cargo-vet sign-off (measured 2026-05-02)

M06.P2.T5 cargo-vet end-of-freeze sign-off:

- `supply-chain/audits.toml` now carries 179 first-party `@bb-connor`
  certification rows, up from the P0 baseline of 26.
- `supply-chain/config.toml` now carries 836 exemption blocks by the ticket's
  grep-based count, down from the P0 baseline of 891 and inside the required
  791-841 chase-down band.
- `cargo vet --locked` completed with `Vetting Succeeded (307 fully audited,
  811 exempted)` after `cargo vet fmt` normalized the store.
- `cargo vet regenerate imports` was rerun during P2. The command reported
  that first-party pseudo-crates such as `chio-a2a-adapter` cannot be fetched
  from crates.io, so `supply-chain/imports.lock` had no content diff. The
  locked vet gate above remains the enforcement signal.
- Standalone CI redundancy was added at `.github/workflows/cargo-vet.yml`,
  pinned to cargo-vet 0.10.2 on `ubuntu-24.04` with `cargo vet --locked`.
- `m06-revocation-oracle-pivot` reaches its close trigger at M06.P2.T5. The
  broader `m06-supply-chain-pivot` remains open until M06.P3.T5 and M06.P4.T5
  close.

### At P3 SBOM publication handoff (measured 2026-05-02)

M06.P3 pins SBOM publication to `supply-chain/sbom/v{tag}/`:

- Source SBOM: `supply-chain/sbom/v{tag}/source.cdx.json`.
- Binary SBOMs: `supply-chain/sbom/v{tag}/{target}.binary.cdx.json`.
- Standalone workflow: `.github/workflows/sbom.yml`, triggered by release
  tags, weekly cron, manual dispatch, and successful `Release Binaries`
  workflow completion.
- Syft pin: 1.18.1, emitting CycloneDX 1.6 JSON with the same
  `infra/sbom/syft.yaml` excludes for `target`, `node_modules`, `.git`, and
  `.worktrees`.
- Determinism probe: source-tree SBOM generation runs twice against `dir:.`
  and fails if the two CycloneDX outputs differ byte-for-byte.
- Signing: each `*.cdx.json` SBOM is signed with `cosign sign-blob` using
  the same GitHub OIDC keyless identity pattern as `release-binaries.yml`.
- Git evidence path: `.gitignore` explicitly leaves `supply-chain/sbom/**`
  committable for release closeout.
- HITRUST assessor handshake: M06 confirms CycloneDX 1.6 SBOMs are
  consumable in the M09 assessor portal evidence package; the cross-reference
  remains the M09 P0 evidence row in
  `.planning/trajectory-3/audits/M09-vendor-evidence.md` for M06 SBOM
  artifacts.

### At P5 close (after-counts; M06.P5.T3 ticket fills)

[TODO M06 milestone agent fill at P5 merge:]

- Apalache invariants checked: 4 (`MonotoneLogApalache`,
  `RevocationCutCompleteness`, `ReceiptBeforeAllow`,
  `KernelTransitionCancelSafe`).
- `formal/MAPPING.md` rows added: 4.
- cargo-vet first-party certifications: 26 + N (N from M06.P2.T1).
- cargo-vet exemption rows after M06.P2.T4 chase-down: 791-841 target.
- deny.toml advisory-ignore rows after M06.P4.T4 refresh: <closed-by-bump
  count>, <re-justified count>; total <= 10.
- Source SBOM published: `supply-chain/sbom/v{tag}/source.cdx.json`
  byte-size and content-hash.
- Binary SBOM published per target:
  `supply-chain/sbom/v{tag}/{target}.binary.cdx.json`.
- Lean theorem inventory drift: 0 expected (sealed by D04).

## 3. Apalache contractor record

### Pre-contract scoping (M06.P0.T3)

- Primary contractor approached: Informal Systems (Igor Konnov / Jure
  Kukovec).
- Fallback contractor approached: Runtime Verification Inc.
- Backup independent: Andrey Kuprianov.
- Scoping call date: 2026-05-02.
- Outcome: fallback pending. Primary packet is queued for Informal Systems;
  Runtime Verification fallback packet is queued if the primary calendar
  cannot meet the 7-10 week M06 window.
- Contracted entity: pending response.
- Contract value (per D07 budget posture, $40-60k band): pending final
  quote.
- Engagement model: fixed-fee per-invariant ($10k-$15k each, 4 invariants).
- Calendar window: 7-10 weeks (M06 W2 placement).

### P5 sign-off (M06.P5.T1)

[Pasted from `formal/apalache/CONTRACTOR-SIGNOFF.md`.]

- Apalache version used: <fill>.
- SMT solver: <fill, default Z3>.
- Per-invariant SMT solver invocation parameters: <fill>.
- Bounded model sizes attempted vs final:
  - Authorities: attempted <fill>, final <fill>.
  - CapSet: attempted <fill>, final <fill>.
  - EpochMax: attempted <fill>, final <fill>.
- Counterexamples surfaced: <fill, with per-counterexample resolution>.
- Sign-off date: <fill>.

## 4. Closure attestations

[TODO M06 milestone agent fill at P5 close:]

- Apalache spec validates: <`apalache-mc check` output URLs per invariant
  from `.github/workflows/apalache-nightly.yml`>.
- 7-consecutive-night-green check: <run-count from CI>.
- cargo-vet enforced in CI: <`.github/workflows/cargo-vet.yml` workflow run
  URL>.
- SBOM published per release at:
  `supply-chain/sbom/v{tag}/source.cdx.json` and
  `supply-chain/sbom/v{tag}/{target}.binary.cdx.json`.
- SBOM cosign signing identity verified: <cosign verify-blob output>.
- CVE-alert workflow live: <`.github/workflows/cve-monitor.yml` workflow run
  URL>.
- Synthetic advisory-db hit produced GitHub Issue routed to `@bb-connor`:
  <issue URL>.
- M09 HITRUST assessor receipt of SBOM: <cross-ref to M09 P0/P1 evidence row
  in `.planning/trajectory-3/audits/M09-vendor-evidence.md`>.
- Lean theorem inventory drift check: <byte-diff against P0 baseline; expected
  0>.
- m06-supply-chain-pivot freeze closed: <date>.
- m06-revocation-oracle-pivot freeze closed: <date>.

## 5. Risk register update

Initial risk register lives in
`.planning/trajectory-3/06-focused-formal-and-supply-chain.md` "Risks and
mitigations" section. M06 milestone agent fills any risk realisations here at
P5:

[TODO M06 milestone agent fill at P5 close.]

- Risks realised: <list any risks from R1..R9 that fired>.
- Mitigation actions taken: <list>.
- Halt triggers fired: <list, expected empty>.
- Outstanding follow-ups deferred to trajectory-4: <list>.
