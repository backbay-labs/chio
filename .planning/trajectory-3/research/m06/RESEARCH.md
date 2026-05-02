# M06 Research: Focused Formal Invariants + Supply-Chain Hygiene v2

**Trajectory:** trajectory-3
**Milestone:** M06
**Wave:** W2
**Phase:** RESEARCH (pre-IMPLEMENT)
**Author:** research agent
**Date:** 2026-04-30

This document is the RESEARCH-phase brief for M06. It frames the
state of the formal stack and the supply-chain pipeline as of the
trajectory-3 genesis date, identifies the highest-leverage focused
invariants permitted under D04, and enumerates the supply-chain
work permitted under D05. The IMPLEMENT-phase agent uses this as
the base for the per-phase ticket scaffold.

## Formal coverage state inventory

The codebase already carries non-trivial formal substrate. The
M06 lens is incremental: add the highest-leverage Apalache
invariants on top of the existing TLA+ / Lean / Kani lattice
without disturbing what trajectory-2 shipped.

### Lean 4

- 83 theorems across `formal/lean4/Chio/`. 0 `lemma` declarations,
  0 `axiom` declarations exposed at the file root, 0 `sorry`
  markers. The Lean stack is sealed: every theorem closes.
- Root modules from `formal/proof-manifest.toml` `root_modules`:
  - `Chio.lean`, `Chio/Core/Capability.lean`,
    `Chio/Core/Scope.lean`, `Chio/Core/Receipt.lean`,
    `Chio/Core/Revocation.lean`, `Chio/Core/Protocol.lean`
  - `Chio/Spec/Properties.lean`,
    `Chio/Proofs/Monotonicity.lean`,
    `Chio/Proofs/Receipt.lean`, `Chio/Proofs/Revocation.lean`,
    `Chio/Proofs/Evaluation.lean`,
    `Chio/Proofs/Protocol.lean`,
    `Chio/Proofs/AeneasEquivalence.lean`,
    `Chio/Proofs/FormalClosure.lean`
  - `Chio/Capability/Delegation.lean`
- One declared `axiom` lives inside theorem-inventory.json:
  `assumption.crypto.verify_capability_signature`
  (`Chio.Core.verifyCapabilitySignature`), an audited assumption
  for capability-signature verification over a trusted key set.
  This is registered as `audited_axiom`, not a closure gap.
- Per the milestone narrative line 50 "Lean theorems (no edits)":
  M06 does NOT touch Lean. Edits land in `formal/tla/`,
  `formal/apalache/`, and supply-chain only.

### TLA+

- 2 specifications under `formal/tla/`:
  - `RevocationPropagation.tla` (PROCS=4, CAPS=8, DEPTH_MAX=4 in
    `MCRevocationPropagation.cfg`). Carries 5 named TLA+
    invariants surfaced in `formal/MAPPING.md`:
    `NoAllowAfterRevoke`, `MonotoneLog`,
    `AttenuationPreserving`, `RevocationFreshness`, plus the
    aggregate `SafetyInv` and the liveness property
    `RevocationEventuallySeen`.
  - `DelegationDepthBound.tla` (DEPTH_MAX=4, PEERS=3 in
    `MCDelegationDepthBound.cfg`). Carries 3 named invariants:
    `DepthBoundedByRoot`, `AttenuatedAtEachStep`,
    `RevokedSubtreeNotObservable`, plus `SafetyInv`.
- Total 24 top-level TLA+ definitions across both specs (counted
  by grep `^[A-Z][A-Za-z]+ ==`); 8 of those are named safety /
  liveness invariants per the mapping table.
- Counterexamples directory exists at
  `formal/tla/counterexamples/` (currently empty under
  `.gitkeep`).

### Apalache

- `formal/apalache/` does NOT exist. M06 creates it.
- The TLA+ specs above are TLC-shaped (CONSTANTS plus
  SPECIFICATION plus INVARIANT). They will need an Apalache
  shim (annotation comments, type declarations) to be checked
  by `apalache-mc check`.
- Reference: `formal/MAPPING.md` line 36 says
  "fourth row is the named liveness property
  `RevocationEventuallySeen`, which the nightly Apalache lane
  checks via `--temporal=`". So an Apalache lane is partly
  conceived of, but not present on disk.

### Kani

- 30 `#[kani::proof]` attributes across the workspace. 18 of
  those live in
  `crates/chio-kernel-core/src/kani_public_harnesses.rs` and
  are registered in `formal/MAPPING.md` (the public-core
  enforced set). The remaining 12 live in
  `crates/chio-kernel-core/src/kani_harnesses.rs` (internal
  helpers, not gated by `check-mapping.sh`).
- Public Kani names (per MAPPING.md): includes
  `verify_delegate_no_widen`,
  `verify_delegation_receipt_canonical`,
  `verify_revocation_view_freshness`,
  `verify_oracle_inclusion_soundness`,
  `verify_receipt_roundtrip`,
  `verify_budget_checked_add_no_overflow`,
  plus eight `public_*` predicates.

### Aeneas

- `formal/aeneas/` carries `pilot.toml` (status:
  `active_pilot`), `production.toml`, and `verified_core.rs`.
  Six extracted Rust symbols: `time_window_valid`,
  `dpop_subset`, `budget_precheck`,
  `governed_approval_passes`,
  `evaluate_signature_time_scope`,
  `report_may_use_verified_label`.
- Out of M06 scope (Lean/Aeneas not edited).

### Active assumptions (10)

`formal/assumptions.toml` lists exactly 10 active assumptions in
`required_assumption_ids`:

1. `ASSUME-ED25519` (audited_crypto)
2. `ASSUME-SHA256` (audited_crypto)
3. `ASSUME-CANONICAL-JSON` (audited_serialization, RFC 8785)
4. `ASSUME-OS-CLOCK` (audited_platform)
5. `ASSUME-SQLITE-ATOMICITY` (audited_storage, per-row only)
6. `ASSUME-TLS` (audited_transport)
7. `ASSUME-NETWORK-TRANSPORT` (audited_transport)
8. `ASSUME-EXTERNAL-REGISTRIES` (audited_service)
9. `ASSUME-SUBPROCESS-ISOLATION` (audited_platform)
10. `ASSUME-CHAIN-FINALITY` (audited_external)

Plus 1 retired assumption (`RETIRED-SQLITE-CROSS-ROW`,
discharged jointly by `MonotoneLog` and the budget per-row
invariant). This matches the trajectory-2 "10 active
assumptions" claim cited in the M06 prompt.

## Highest-leverage invariants (top 3-4)

D04 caps the Apalache scope to 3-4 invariants on a kernel-state
subset. Candidates from the prompt and the MAPPING table, scored
on (a) load-bearing for protocol semantics, (b) NOT yet
mechanized as an Apalache spec, (c) tractable in 7-10 weeks
under a 0.5-FTE contractor:

| Candidate | Already in TLA+? | Already in Lean? | Already in Kani? | Recommend for Apalache? |
| --- | --- | --- | --- | --- |
| Receipt-log monotonicity (per-authority append-only, strictly increasing timestamps) | yes (`MonotoneLog`) | yes (`proof.applyProof_append`, `proof.checkpoint_consistency`) | partial (`verify_receipt_roundtrip`) | YES, primary: easy Apalache port; closes RETIRED-SQLITE-CROSS-ROW under explicit Apalache check |
| Capability attenuation under composition (no widening across N steps) | yes (`AttenuationPreserving`) | yes (`compose_preserves_algebra`, `attenuation_monotone`) | yes (`verify_delegate_no_widen`) | NO, redundant: Lean already closes it; Apalache adds little |
| Revocation-cut completeness (any ancestor revocation cuts the descendant) | partial (`NoAllowAfterRevoke` is local) | yes (`revocation_is_cut`) | partial (`verify_revocation_view_freshness`) | YES: lift the Lean cut theorem to a state-machine invariant under concurrent epoch updates |
| Anchor-chain integrity (sparse Merkle inclusion proofs are sound) | no | no | yes (`verify_oracle_inclusion_soundness`, mod ASSUME-SHA256) | NO: TLA+/Apalache is wrong-shaped for cryptographic invariants; keep in Kani |
| Kernel state-transition CancelSafe (every observed pre-state plus aborted transition equals pre-state) | no | partial (budget overflow lemma) | yes (`verify_budget_checked_add_no_overflow`) | YES: Apalache models the cross-step interleaving Kani cannot |
| ReceiptBeforeAllow ordering (no allow receipt outruns its log entry) | partial (jointly discharged via `MonotoneLog` plus `budget_per_row_invariant`) | partial | no | YES: name it explicitly so the M08 reviewer can cite it; close the gap surfaced by RETIRED-SQLITE-CROSS-ROW |

### Recommended top 4 (rank order)

1. **`MonotoneLogApalache`** - port `MonotoneLog` from
   `RevocationPropagation.tla` to Apalache type-annotated form.
   Covers receipt-log monotonicity under explicit symbolic
   model-checking. Lowest risk. Estimated 1-2 weeks contractor.
2. **`RevocationCutCompleteness`** - new invariant: for every
   delegation chain, if any ancestor is revoked, no descendant
   capability produces an `allow` verdict in any reachable
   state. Closes the global-cut shape that `NoAllowAfterRevoke`
   leaves local. 2-3 weeks contractor.
3. **`ReceiptBeforeAllow`** - new invariant: every reachable
   state with an `allow` verdict for cap C has the C receipt
   already appended to the per-authority log. Names the
   joint-discharge of `RETIRED-SQLITE-CROSS-ROW` as a single
   Apalache invariant. 2 weeks contractor.
4. **`KernelTransitionCancelSafe`** - new invariant: if a
   transition T from state S aborts (budget overflow,
   revocation freshness fail, dpop fail), the resulting state
   is equal to S on the user-observable projection (budget,
   receipt log, revocation epoch). Covers the cross-step
   interleaving that single-shot Kani cannot. 2-3 weeks
   contractor.

Total: 7-10 weeks contractor at 0.5 FTE matches the D04 budget
window.

### Why these and not the alternates

- `AttenuationPreserving` is already covered in TLA+ AND Lean
  AND Kani; adding Apalache duplicates work.
- `Anchor-chain integrity` is a cryptographic property; TLA+
  cannot reason about hash collisions, so Apalache adds nothing
  beyond the existing Kani harness modulo `ASSUME-SHA256`.
- `RevocationEventuallySeen` is liveness; the nightly Apalache
  lane mentioned in `formal/MAPPING.md` line 36 SHOULD pick it
  up as a fifth (liveness) check, but it is out of the safety-
  invariant top-3-4 cap.

## Apalache scope reduction (D04)

Per D04 (decisions.yml), the full delegation FSM Apalache model
is deferred to trajectory-4 because it is a 16-20 week effort
under 0.5 SR. M06 ships the focused 3-4 invariants on a kernel-
state SUBSET. The minimum FSM subset that still covers the four
chosen invariants:

### State variables (subset)

- `receipt_log[a]` for each authority `a in Authorities`: a
  finite sequence of `Receipt = [cap, verdict, t, seen_epoch]`
  records.
- `revocation_epoch[a]` for each authority `a`: a non-negative
  integer.
- `cap_state[c]` for each capability `c in CapSet`: one of
  `{active, attenuated, revoked}`.
- `parent[c]`: a partial function CapSet -> CapSet (delegation
  DAG).
- `budget[c]`: non-negative integer; capacity per cap.

### Transitions (subset)

- `IssueReceipt(a, c, v, t)`: append a receipt; required
  pre-condition for `Allow`.
- `Allow(a, c, t)`: produces an `allow` verdict iff the receipt
  is in `receipt_log[a]` AND no ancestor of `c` is `revoked` in
  the visible epoch AND budget admits.
- `Revoke(a, c)`: marks `c` and the entire descendant subtree
  as `revoked`.
- `PropagateEpoch(a, b)`: lifts authority `b` from a stale
  epoch to authority `a`'s epoch (weak-fairness fairness condition for
  `RevocationEventuallySeen`).
- `Attenuate(c, c')`: produces a child cap with `parent[c']=c`
  and a strict-subset scope.

### Out of the subset (deferred to trajectory-4)

- Tool-level dispatch state (the guard pipeline; modeled in
  Kani but not surfaced to the FSM).
- Budget rollover semantics across a window boundary.
- Cross-tenant lineage (multi-tenant FSM is the trajectory-4
  full-FSM target).
- Mobile attestation handshake (M07 owns).

### Apalache-specific shape requirements

- Top-of-spec type annotations (`@type:`) on every variable;
  Apalache is symbolic and rejects ambiguous types.
- Bounded sets: `Authorities = 1..3`, `CapSet = 1..6`,
  `EpochMax = 4`. Bounds picked to keep the SMT problem
  tractable; reasonable since safety violations of the named
  invariants are local to small fragments.
- The `MCRevocationPropagation.cfg` constants (PROCS=4,
  CAPS=8, DEPTH_MAX=4) are TLC-shaped; the Apalache lane uses
  smaller bounds to fit the SMT envelope.

## Crate consolidation deferral note (D05)

D05 defers crate consolidation 88 -> <=70 to trajectory-4
because moving public symbols across crate boundaries forces a
breaking-change cascade. The M06 prompt named "88 baseline"; the
measured count today is 90 (from `Cargo.toml` workspace
members), with `Cargo.lock` carrying 1147 total package
records (transitive). Two extra crates over the 88 baseline
landed during trajectory-2 close (likely
`crates/chio-formal-diff-tests` plus one more); not material to
M06 since D05 explicitly preserves the workspace shape.

M06 supply-chain work treats the 90-crate shape as fixed. SBOM
emission and cargo-vet enforcement are crate-shape-agnostic.

## Supply-chain hygiene state

trajectory-2 already shipped a substantial supply-chain lattice.
M06 closes the gaps and adds the load-bearing pipelines.

### Already shipped

- **`supply-chain/audits.toml`** carries 26 first-party
  certifications signed `who = "@bb-connor"`, all
  `safe-to-deploy`. Crates covered: `anyhow`, `bitflags`,
  `cfg-if`, `darling_macro`, `hashbrown` (x2 versions),
  `ident_case`, `itertools` (x2), `itoa`, `memchr`,
  `num_cpus`, `once_cell`, `paste`, `pin-project-lite`,
  `proc-macro2`, `quote`, `ryu`, `scopeguard`, `semver`,
  `syn`, `thiserror` (x2), `typenum`, `unicode-ident`,
  `utf8parse`.
- **`supply-chain/config.toml`** carries 891 exemption rows
  (the audit-this-later baseline) and 4 imports
  (`bytecode-alliance`, `google`, `mozilla`, `zcash`).
- **`supply-chain/imports.lock`** is present (cached upstream
  audit feeds, regenerated via `cargo vet regenerate
  imports`).
- **`deny.toml`** is 533 lines, with an explicit advisory
  ignore list that names each ignored RUSTSEC ID and the
  upstream-fix path.
- **`.github/workflows/ci.yml`** ALREADY includes:
  - `cargo-vet` job (line 302; pinned to cargo-vet 0.10.2;
    runs `cargo vet --locked`).
  - `cargo-deny` job (line 318; pinned to cargo-deny 0.19.4;
    runs `cargo deny check`).
- **`.github/workflows/release-binaries.yml`** ALREADY
  includes:
  - `cargo-auditable` install (pinned to 0.7.4) on every
    target so the dep graph is embedded in the release
    binary.
  - `syft` install (pinned to 1.18.1; SHA-pinned download)
    that emits a CycloneDX 1.6 JSON SBOM per target
    (`out/sbom/chio-${CHIO_TARGET}.cyclonedx.json`).
  - `cosign sign-blob --yes` keyless Sigstore signing of
    every release archive plus the SBOM siblings.
- **`infra/sbom/syft.yaml`** pins the syft CycloneDX 1.6
  output and exclude paths (`./target/**`,
  `./node_modules/**`, `./.git/**`, `./.worktrees/**`).

### Gap inventory (what M06 still owes)

1. NO standalone `.github/workflows/sbom.yml` (the OWNERS
   manifest names it but the file does not yet exist; SBOM
   emission today is folded into `release-binaries.yml`).
2. NO standalone `.github/workflows/cargo-vet.yml` (vet runs
   inside `ci.yml` only; OWNERS names a dedicated workflow).
3. NO `.github/workflows/cve-monitor.yml` (no scheduled
   `cargo-audit` or `osv-scanner` lane; advisory-db monitoring
   today is on-pull only via cargo-deny).
4. The 891 exemption rows in `supply-chain/config.toml` are NOT
   the same as audit closure; they are "audit-this-later"
   markers. Top-50 by transitive-edge centrality are the
   candidate certifications for M06.P2.
5. NO Apalache spec files; `formal/apalache/` does not exist.
6. NO third-party reproducible-build verifier handoff (M03
   owns this; M06 publishes the SBOM that flows through it).
7. NO HITRUST-formatted SBOM provenance receipt (M09 P0 / P1
   evidence; M06 P3 produces it).

## Reproducible builds (coordinate with M03)

D13 names hosted CI on `ubuntu-24.04` (plus `macos-14`) with a
third-party rebuilder. M03 owns the reproducible-build pipeline
itself (`.github/workflows/reproducible-build.yml`); M06 is the
SUPPLIER of the SBOM that flows through it. Concretely:

- **M03 P2** scaffolds `reproducible-build.yml` (per the M03
  narrative, line 96): pins build environment via `Dockerfile`,
  records non-determinism sources in the M03 audit doc.
- **M03 P3** publishes SLSA-style provenance plus checksum
  publication.
- **M03 P4** records the third-party rebuild + hash match.
- **M06 P3** publishes the SBOM into the same release artifact
  set that M03 reproduces. The hash chain is:
  `Dockerfile (M03) -> binary (M03) -> SBOM (M06) -> cosign sig (existing) -> SLSA provenance (M03) -> third-party rebuild hash (M03)`.

### Two-builder hash-equal scheme

Per D13, the M03 third-party rebuilder is "an independent
contributor or a sister team". M06 does NOT introduce a second
builder; M06 just makes sure the SBOM emitted by builder A is
byte-equal to the SBOM emitted by builder B (so the rebuild
hash matches). syft is mostly deterministic on the same input
binary; the exception is timestamp emission, which we suppress
via the existing `syft.yaml` config (already excludes
`./target/**`).

### Coordination tickets

- M06 P3 depends on M03 P2 (the reproducible-build workflow
  must exist before M06 wires its SBOM into it).
- M06 P3 produces an artifact consumed by M03 P3 (SLSA
  provenance per release names the SBOM by content-hash).

## SBOM emission proposal

### Format choice: CycloneDX over SPDX

The repository ALREADY emits CycloneDX 1.6 JSON via syft (see
`infra/sbom/syft.yaml`). M06 inherits that choice. Rationale:

- CycloneDX 1.6 is the format the M09 HITRUST assessor
  consumes per its supply-chain control mapping.
- CycloneDX has a stronger vulnerability-disclosure schema
  (VEX) that integrates with `cargo-audit` and `osv-scanner`.
- syft emits CycloneDX deterministically on the same input.
- SPDX is supported by syft as a fallback (multi-output is
  one syft invocation away); not needed unless a downstream
  consumer asks for SPDX explicitly.

### Per-release artifact emission

Per the audit-doc template line 39, the publication path is
`supply-chain/sbom/v3.18.cdx.json` (versioned by tag). The M06
P3 work:

1. Add `.github/workflows/sbom.yml` as a standalone scheduled
   plus tag-triggered workflow that:
   - Runs `syft scan dir:.` on the source tree (the existing
     `release-binaries.yml` runs syft on the binary; M06
     adds a SOURCE-tree SBOM as well, distinct artifact).
   - Emits both
     `supply-chain/sbom/source/v{tag}.source.cdx.json` and
     `supply-chain/sbom/binary/v{tag}.{target}.binary.cdx.json`.
   - Validates each against the CycloneDX 1.6 JSON schema.
2. Pin the source-tree SBOM into the release artifact set
   alongside the per-target binary SBOMs already shipping.
3. Sign each SBOM file with `cosign sign-blob --yes`
   (Sigstore keyless), reusing the same signing identity the
   release-binaries lane already uses; do NOT introduce a
   separate signing key.

### Sigstore keyless signing - key conflict assessment

The cosign keyless signing already shipped via
`release-binaries.yml` uses a per-job OIDC identity
(`id-token: write`) and produces `.sig` plus `.pem` siblings.
The SBOM signing in M06 uses the same identity; no conflict
because each `cosign sign-blob` is independent. The risk:
identity-binding drift across jobs. Mitigation: M06 P3 wires
the SBOM signing inside the same release-binaries job (not a
separate job) so the identity provenance chain is unified.

## CVE alert pipeline

The prompt asks: cargo-audit, osv-scanner, GitHub Dependabot.
Pick one or layer. Recommend layered with cargo-audit as the
primary CI gate.

### Recommended layering

1. **cargo-audit** (primary CI). RustSec advisory-db is the
   most authoritative source for Rust crate CVEs; deny.toml
   ALREADY consults it via cargo-deny. M06 P4 adds a separate
   `.github/workflows/cve-monitor.yml` that runs on:
   - Every PR (block-on-new-advisory).
   - A nightly cron (catches advisories filed between PRs).
2. **osv-scanner** (secondary, scheduled-only). Covers Go,
   Python, JS, npm dependencies that `cargo-audit` does not.
   Chio is mostly Rust but has Python (`crates/chio-conformance/verdict_matrix/drivers/python/`)
   and JS / TS packages (npm ecosystem). osv-scanner's broader
   coverage is the right fit.
3. **Dependabot** (tertiary, version-bump PRs). Already wired
   in `.github/dependabot.yml` (assumed; verify in P0).
   Dependabot opens PRs; cargo-audit / osv-scanner BLOCK them
   if the new version still carries the advisory.

### Alert routing

Per the milestone narrative line 140: alerts fan out to
`@bb-connor` (single owner). M06 P4 adds a GitHub Issues
auto-file step on advisory-db hit; the issue carries the
RUSTSEC-/OSV- ID, the affected crate version, and the
remediation candidate.

### Why not just Dependabot

Dependabot lags advisory-db by 24-72 hours and does not block
merges. cargo-audit + osv-scanner are SYNCHRONOUS gates; the
M09 HITRUST control map demands a synchronous gate (the
"vulnerability management" control).

## Per-phase research findings (P0-P5)

### P0: Audit baseline (Apalache contractor scoping + invariant shortlist)

- Hard counts to lock at P0:
  - Workspace crate count: **90** (baseline 88; trajectory-2
    drift +2).
  - Workspace deps with no cargo-vet acknowledgement:
    **891** (`[[exemptions.*]]` rows in
    `supply-chain/config.toml`); the IMPLEMENT agent should
    confirm by `cargo vet --locked` plus
    `cargo vet suggest`.
  - CVE alerts open against current deps: **9** known
    advisory-db hits in `deny.toml` ignore list (see lines
    28-43): `RUSTSEC-2026-{0049,0098,0099,0104}`,
    `RUSTSEC-2025-{0141,0134,0068,0097}`,
    `RUSTSEC-2024-0436`, plus `RUSTSEC-2023-0071`. P0 audit
    re-runs `cargo audit` and pins the actual count.
  - Apalache invariants chosen: 4 (per the top-3-4 list
    above).
- Apalache contractor scoping (D07: ~$40-60k budget band):
  candidate roster includes Igor Konnov (UFM Apalache author,
  now at Informal Systems), Jure Kukovec (Informal Systems),
  Andrey Kuprianov, plus Runtime Verification Inc. (Apalache
  contracting offering). Recommend the IMPLEMENT-phase agent
  shortlists Informal Systems first (origin org of Apalache);
  fallback Runtime Verification.

### P1: Apalache spec for kernel-state subset

- Tickets (preliminary):
  - **M06.P1.T1**: scaffold `formal/apalache/` with
    `RevocationCutCompleteness.tla`, `MCRev*.cfg`, type
    annotations on existing TLA+ vars.
  - **M06.P1.T2**: port `MonotoneLog` to Apalache
    annotation-shaped form
    (`formal/apalache/MonotoneLogApalache.tla`).
  - **M06.P1.T3**: write `RevocationCutCompleteness.tla`
    invariant (new).
  - **M06.P1.T4**: write `ReceiptBeforeAllow.tla` invariant
    (new); cross-link to RETIRED-SQLITE-CROSS-ROW closure.
  - **M06.P1.T5**: write `KernelTransitionCancelSafe.tla`
    invariant (new).
  - **M06.P1.T6**: wire CI lane
    `.github/workflows/apalache-nightly.yml` running
    `apalache-mc check` against each MC config.

### P2: cargo-vet config + workspace import audit

- Tickets (preliminary):
  - **M06.P2.T1**: enumerate top-50 most-central transitive
    deps (by reverse-dep edge count from `cargo tree`); seed
    `audits.toml` certifications for any not yet covered.
    Current 26 first-party rows already cover the proc-macro
    sub-set; M06.P2 extends to async runtime
    (tokio, futures, tower, hyper, rustls family), serde
    family, ed25519/sha2/subtle/zeroize family, tracing
    family.
  - **M06.P2.T2**: refresh upstream imports
    (`cargo vet regenerate imports`); commit the diff.
  - **M06.P2.T3**: add a standalone
    `.github/workflows/cargo-vet.yml` (currently only inside
    `ci.yml`); OWNERS names the path.
  - **M06.P2.T4**: chase the 891-row exemption baseline DOWN
    by 50-100 rows (do not chase zero per the milestone
    narrative line 130).
  - **M06.P2.T5**: cargo-vet enforcement plus end-of-freeze
    sign-off.

### P3: SBOM generation pipeline + per-release publication

- Tickets (preliminary):
  - **M06.P3.T1**: add `.github/workflows/sbom.yml` as a
    standalone tag-triggered workflow emitting both source
    and binary SBOMs.
  - **M06.P3.T2**: extend `infra/sbom/syft.yaml` to support
    SOURCE-tree scanning (currently only binary scanning).
  - **M06.P3.T3**: pin SBOM publication path
    `supply-chain/sbom/v{tag}.cdx.json` per the audit-doc
    template.
  - **M06.P3.T4**: cosign-sign each SBOM file using the
    existing keyless identity.
  - **M06.P3.T5**: M09 assessor receipt: handshake doc
    confirming the SBOM is consumable in the HITRUST
    assessor portal (cross-ref M09 P0 evidence row).

### P4: CVE-alert workflow

- Tickets (preliminary):
  - **M06.P4.T1**: add `.github/workflows/cve-monitor.yml`
    running `cargo-audit` on every PR plus nightly.
  - **M06.P4.T2**: add the osv-scanner secondary lane to the
    same workflow (Python plus JS coverage).
  - **M06.P4.T3**: GitHub Issues auto-file on advisory hit;
    route to `@bb-connor`.
  - **M06.P4.T4**: refresh deny.toml ignore list (the 10
    current advisory ignores) - either close them by upstream
    bump or re-justify them.
  - **M06.P4.T5**: end-of-freeze sign-off; CVE workflow live
    on `main`.

### P5: Apalache contractor sign-off + audit doc closure

- Tickets (preliminary):
  - **M06.P5.T1**: contractor produces a sign-off memo
    naming the 3-4 invariants checked, the Apalache version,
    the SMT solver invocations, and the bounded model sizes.
  - **M06.P5.T2**: paste contractor memo into
    `.planning/trajectory-3/audits/M06-formal-supply-chain.md`
    section 3.
  - **M06.P5.T3**: M06 audit doc closure (sections 2 plus 4
    populated; HITRUST receipt cross-linked).

## Apalache contractor engagement

D07 budget posture allocates ~$40-60k to the Apalache
contractor. Engagement shape:

- **Scope**: write Apalache-shaped TLA+ specs for the 4
  invariants named above; produce model-checker output
  (`apalache-mc check` logs); deliver a sign-off memo.
- **Lead time per the milestone narrative line 124**: P0
  contractor scoping starts week 12; backup contractor named.
  This places contractor onboarding in W2 (M06 is a W2
  milestone), with P5 sign-off targeting end-of-trajectory
  W3.
- **Candidate orgs**:
  1. Informal Systems (Apalache origin org; Igor Konnov, Jure
     Kukovec).
  2. Runtime Verification Inc. (commercial formal-methods
     consultancy; Apalache + TLA+ engagement record).
  3. Backup independent: Andrey Kuprianov.
- **Engagement model**: fixed-fee per-invariant ($10k-$15k
  per invariant, 3-4 invariants, total $30-60k); 7-10 weeks
  calendar; pre-contract scoping call in P0 to confirm
  feasibility of the kernel-state subset.

## Risk register

1. **Apalache contractor unavailable / withdraws mid-engagement.**
   Mitigation: P0 scoping call confirms availability;
   pre-contract milestone (P0.T1) names a backup. If both
   primary and backup withdraw, fallback to TLA+ TLC-only
   checking (no Apalache symbolic check); record the
   degradation in the M06 audit doc.
2. **Chosen invariants prove non-mechanizable in Apalache.**
   Mitigation: P0 ticket lets contractor downgrade an
   invariant to "modeled in TLC, sketched in Apalache" and
   substitute another candidate from the top-6 list.
   Fallback: ship 3 invariants instead of 4; record the gap.
3. **cargo-vet imports surface unaudited transitive deps.**
   Mitigation: per the milestone narrative line 128, the
   baseline accepts a documented threshold of audit-this-later
   rows; do not chase zero. M06.P2.T4 chases 50-100 rows down,
   not all 891.
4. **SBOM signing keys conflict with release-signing keys.**
   Mitigation: M06.P3.T4 reuses the existing cosign keyless
   identity; no new signing key introduced. If the OIDC token
   provenance drifts, M06.P3.T1 wires SBOM signing inside the
   same release-binaries job.
5. **CVE-alert pipeline overflows with low-severity advisories.**
   Mitigation: M06.P4.T1 filters to severity >= medium for
   issue auto-file; lower severities go to a digest issue
   weekly. Avoids alert fatigue while keeping the synchronous
   gate.
6. **Apalache spec bounds prove too small to surface
   counterexamples.** Mitigation: P5 contractor memo records
   the bound choices and the SMT timeouts; raises bounds
   incrementally if the SMT solver is fast.
7. **Reproducible-build hash drift between SBOM emissions on
   builders A and B.** Mitigation: P3 wires the SBOM into the
   M03 reproducible-build job (single builder per artifact),
   plus the third-party rebuilder verifies the SBOM hash as
   part of the M03 P4 hash-equal handoff.
8. **M09 HITRUST assessor rejects the SBOM format.**
   Mitigation: P3.T5 handshake doc confirms format
   acceptability BEFORE the M09 audit window opens; if the
   assessor demands SPDX, syft emits both with one extra
   `-o` flag.

## Recommended ticket scaffold

The tickets above are PRELIMINARY (the IMPLEMENT-phase agent
can re-cut them). The shape:

- P0: 4 tickets (audit baseline, invariant shortlist, contractor
  scoping, audit-doc P0 fill).
- P1: 6 tickets (Apalache scaffold + 4 invariant specs + CI
  lane).
- P2: 5 tickets (top-50 vet seed, regenerate imports, standalone
  workflow, exemption chase-down, sign-off).
- P3: 5 tickets (sbom workflow, syft config extension,
  publication path, cosign signing, M09 receipt handshake).
- P4: 5 tickets (cve-monitor workflow, osv lane, issue routing,
  deny.toml refresh, sign-off).
- P5: 3 tickets (contractor memo, audit doc closure, M06 close).

Total: 28 tickets. Reasonable for a 7-10 week milestone at
fractional contractor + 1 FTE eng.

## Open questions for IMPLEMENT phase

1. **Apalache vendor selection**: confirm Informal Systems is
   reachable for a fixed-fee contract; if not, fall through to
   Runtime Verification.
2. **SPDX-or-CycloneDX for HITRUST**: the recommendation is
   CycloneDX, but the M09 HITRUST assessor's exact ask is not
   yet on file. Confirm in M06.P3.T5.
3. **osv-scanner version pin**: nothing currently pins
   osv-scanner; recommend pinning to the latest tagged release
   at the time of P4 ticket merge.
4. **Top-50 vet candidate list**: requires `cargo tree` plus a
   centrality computation; the IMPLEMENT-phase agent generates
   the actual list at P0.
5. **Apalache nightly bound choices**: the 3-bound, 6-cap,
   4-epoch shape recommended above is a starting point; the
   contractor calibrates against SMT-solver speed in P0.
6. **Two-builder verification for SBOM**: M03 owns the
   third-party rebuild; M06 must confirm syft-on-source is
   deterministic enough that two independent builders produce
   byte-equal SBOMs. The IMPLEMENT-phase agent runs a
   determinism probe in P3.T1.
7. **Existing 9-row deny.toml ignore list**: each ignore is a
   pending upstream bump. M06.P4.T4 must decide
   close-vs-re-justify per row.
8. **Lean theorem-inventory drift**: the inventory.json
   carries 1 axiom plus N theorems; not edited by M06, but the
   IMPLEMENT-phase agent should confirm no Lean edits sneak
   in via cross-milestone PRs during the freeze window.
