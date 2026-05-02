# M06 Audit: Focused Formal Invariants + Supply-Chain Hygiene v2

**Trajectory:** trajectory-3
**Milestone:** M06
**Wave:** W2
**Status:** TEMPLATE (filled by M06 milestone agent at P0 wave-opener merge and P5 close)
**Audit start:** <fill at P0 wave-opener merge>
**Audit close:** <fill at P5 final ticket merge>

## 1. Audit scope

M06 closes 4 highest-leverage TLA+/Apalache invariants on a kernel-
state subset (D04 caps the formal scope) and ships supply-chain
hygiene v2 (cargo-vet adoption, SBOM publication, CVE alerting; D05
caps the supply-chain scope). Release gates: QUALIFICATION (the
formal half) plus RELEASE_AUDIT (the supply-chain half).

The Apalache invariants are:

1. `MonotoneLogApalache` (port of TLA+ `MonotoneLog` from
   `RevocationPropagation.tla`).
2. `RevocationCutCompleteness` (new; lifts Lean
   `revocation_is_cut` to a state-machine invariant).
3. `ReceiptBeforeAllow` (new; names the joint-discharge of
   `RETIRED-SQLITE-CROSS-ROW` as a single Apalache invariant).
4. `KernelTransitionCancelSafe` (new; covers cross-step
   interleaving Kani cannot model).

Out of scope per D04 / D05: full delegation FSM Apalache model
(deferred to trajectory-4); crate consolidation 88 -> <=70
(deferred to trajectory-4); new Lean theorems; new Kani harnesses;
SPDX SBOM emission unless M09 assessor demands it.

Reference-runner contract for the Apalache CI lane: GitHub Actions
hosted `ubuntu-24.04`, Apalache 0.51.0 (or latest tagged at the
P0 open date), Z3 default solver, bounded sets `Authorities = 1..3`,
`CapSet = 1..6`, `EpochMax = 4`, per-invariant SMT timeout 30
minutes. The reference runner contract is identical to the M03
hosted CI runner (D13).

## 2. Hard counts

### At P0 (measured 2026-04-30; M06.P0.T1 ticket re-runs and pins)

[TODO M06 milestone agent fill at P0 merge:]

- Lean theorems closed: 83 (from `theorem-inventory.json`).
- Lean `sorry` markers: 0.
- Lean audited axioms: 1 (`assumption.crypto.verify_capability_signature`).
- TLA+ named invariants: 8 (5 in `RevocationPropagation.tla`,
  3 in `DelegationDepthBound.tla`).
- Apalache invariants today: 0 (`formal/apalache/` does not exist).
- Kani `#[kani::proof]` attributes: 30 (18 public, 12 internal).
- Active assumptions: 10.
- Workspace crate count: 90 (baseline 88; trajectory-2 drift +2).
- Cargo.lock package records: 1147.
- cargo-vet first-party certifications: 26.
- cargo-vet exemption rows (audit-this-later baseline): 891.
- cargo-vet import feeds: 4 (bytecode-alliance, google, mozilla,
  zcash).
- deny.toml advisory-ignore rows: 10.
- CVE alerts open against current deps (re-run at P0): <fill from
  `cargo audit` output>.
- Top-50 transitive dep list (from M06.P0.T2 cargo-tree centrality
  computation): <fill in P0 ticket>.

### At P5 close (after-counts; M06.P5.T3 ticket fills)

[TODO M06 milestone agent fill at P5 merge:]

- Apalache invariants checked: 4 (`MonotoneLogApalache`,
  `RevocationCutCompleteness`, `ReceiptBeforeAllow`,
  `KernelTransitionCancelSafe`).
- `formal/MAPPING.md` rows added: 4.
- cargo-vet first-party certifications: 26 + N (N from
  M06.P2.T1).
- cargo-vet exemption rows after M06.P2.T4 chase-down: 791-841
  target.
- deny.toml advisory-ignore rows after M06.P4.T4 refresh:
  <closed-by-bump count>, <re-justified count>; total <= 10.
- Source SBOM published: `supply-chain/sbom/v{tag}/source.cdx.json`
  byte-size and content-hash.
- Binary SBOM published per target: `supply-chain/sbom/v{tag}/{target}.binary.cdx.json`.
- Lean theorem inventory drift: 0 expected (sealed by D04).

## 3. Apalache contractor record

[TODO M06 milestone agent fill at P0 (scoping) and P5 (sign-off):]

### Pre-contract scoping (M06.P0.T3)

- Primary contractor approached: Informal Systems
  (Igor Konnov / Jure Kukovec).
- Fallback contractor approached: Runtime Verification Inc.
- Backup independent: Andrey Kuprianov.
- Scoping call date: <fill>.
- Outcome: signed | fallback | declined.
- Contracted entity: <fill>.
- Contract value (per D07 budget posture, $40-60k band):
  <fill>.
- Engagement model: fixed-fee per-invariant ($10k-$15k each, 4
  invariants).
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

- Apalache spec validates: <`apalache-mc check` output URLs per
  invariant from `.github/workflows/apalache-nightly.yml`>.
- 7-consecutive-night-green check: <run-count from CI>.
- cargo-vet enforced in CI: <`.github/workflows/cargo-vet.yml`
  workflow run URL>.
- SBOM published per release at:
  `supply-chain/sbom/v{tag}/source.cdx.json` and
  `supply-chain/sbom/v{tag}/{target}.binary.cdx.json`.
- SBOM cosign signing identity verified: <cosign verify-blob
  output>.
- CVE-alert workflow live: <`.github/workflows/cve-monitor.yml`
  workflow run URL>.
- Synthetic advisory-db hit produced GitHub Issue routed to
  `@bb-connor`: <issue URL>.
- M09 HITRUST assessor receipt of SBOM: <cross-ref to M09 P0/P1
  evidence row in `.planning/trajectory-3/audits/M09-vendor-evidence.md`>.
- Lean theorem inventory drift check: <byte-diff against P0
  baseline; expected 0>.
- m06-supply-chain-pivot freeze closed: <date>.
- m06-revocation-oracle-pivot freeze closed: <date>.

## 5. Risk register update

Initial risk register lives in
`.planning/trajectory-3/06-focused-formal-and-supply-chain.md`
"Risks and mitigations" section. M06 milestone agent fills any
risk realisations here at P5:

[TODO M06 milestone agent fill at P5 close.]

- Risks realised: <list any risks from R1..R9 that fired>.
- Mitigation actions taken: <list>.
- Halt triggers fired: <list, expected empty>.
- Outstanding follow-ups deferred to trajectory-4: <list>.
