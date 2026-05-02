# Milestone 06: Focused Formal Invariants + Supply-Chain Hygiene v2

## Lens

Dual lens: formal verification and supply-chain hygiene. M06 is the
deepen-the-substrate milestone inside the trajectory-3 50/30/20 blend.
On the formal side it adds 3-4 highest-leverage Apalache invariants on
top of the trajectory-2 Lean / TLA+ / Kani / Aeneas lattice (per D04,
NOT a full FSM). On the supply-chain side it closes the cargo-vet,
SBOM, and CVE-monitoring gaps left by trajectory-2 (per D05, NOT a
crate consolidation). Both halves serve the same purpose: produce
evidence that the M09 HITRUST i1 assessor and the M08 protocol
reviewer can consume. Release-gate anchor is dual: QUALIFICATION (the
formal half) plus RELEASE_AUDIT (the supply-chain half), and every
M06 verdict claim names which half closes which gate.

Trust-boundary: yes.

## Why this is on the trajectory

**Release-gate anchor:** QUALIFICATION + RELEASE_AUDIT (dual).

Trajectory-2 closed with a substantial formal stack and a substantial
supply-chain pipeline, but neither half is closed. The M09 HITRUST i1
control map demands an SBOM published at every release with a signed
provenance chain; the M08 protocol reviewer needs a named, mechanized
invariant set that covers the protocol semantics (delegation,
revocation, receipt ordering) without forward-referencing Lean
theorems the reviewer is not trained to read. M06 picks up exactly
those load-bearing pieces.

The trajectory-2 substrate that creates the precondition:

- Lean 4 stack at `formal/lean4/Chio/`: 83 closed theorems across 14
  root modules, 0 `sorry` markers, 1 audited axiom
  (`assumption.crypto.verify_capability_signature`). M06 does NOT
  edit Lean.
- TLA+ specs at `formal/tla/RevocationPropagation.tla` and
  `formal/tla/DelegationDepthBound.tla`: 8 named TLA+ safety/liveness
  invariants; the lane is TLC-shaped (no Apalache annotations). M06
  ports a subset to Apalache.
- Kani harnesses at
  `crates/chio-kernel-core/src/kani_public_harnesses.rs` and
  `kani_harnesses.rs`: 30 `#[kani::proof]` attributes, 18 of which
  are public (registered in `formal/MAPPING.md`). M06 does NOT edit
  Kani.
- Aeneas extraction at `formal/aeneas/`: pilot active; 6 verified
  Rust symbols. Out of M06 scope.
- 10 active assumptions in `formal/assumptions.toml`
  (`required_assumption_ids`); 1 retired assumption discharged
  jointly by `MonotoneLog` and the per-row budget invariant. M06
  closes the gap by lifting that joint discharge to a single
  Apalache invariant (`ReceiptBeforeAllow`).
- Supply-chain skeleton: `supply-chain/audits.toml` carries 26
  first-party `safe-to-deploy` certifications signed by
  `@bb-connor`; `supply-chain/config.toml` carries 891 exemption
  rows (the audit-this-later baseline) and 4 import feeds
  (`bytecode-alliance`, `google`, `mozilla`, `zcash`).
  `supply-chain/imports.lock` is present.
- `deny.toml` (533 lines) with an explicit advisory-ignore list
  (10 rows; each a pending upstream bump).
- `.github/workflows/ci.yml` already runs cargo-vet 0.10.2 and
  cargo-deny 0.19.4 on every PR.
- `.github/workflows/release-binaries.yml` already emits a
  CycloneDX 1.6 binary SBOM via syft 1.18.1 and signs every
  release archive with cosign keyless.
- `infra/sbom/syft.yaml` pins the syft output shape and exclude
  paths.

What the M09 HITRUST control map and the M08 reviewer still need:

- A named Apalache invariant set covering kernel-state semantics
  the Lean stack does not directly speak to (state-machine cross-step
  interleaving, multi-authority epoch propagation, transition
  cancellation safety).
- An SBOM published per release at a stable, content-addressed path
  (`supply-chain/sbom/v{tag}.cdx.json`), with both source-tree and
  per-target-binary outputs, cosign-signed by the same identity that
  signs the binaries.
- A standalone CVE-monitor workflow with cargo-audit (Rust) plus
  osv-scanner (Python, JS) lanes, scheduled nightly plus on every PR,
  routing alerts to GitHub Issues for `@bb-connor`.
- A standalone cargo-vet workflow (today vet runs only inside the
  monolithic `ci.yml`).
- An audited reduction in the 891-row exemption baseline (50-100
  rows down per the milestone narrative; not all 891).
- Apalache contractor sign-off memo confirming the model checks
  pass and the bounded model sizes are documented.

D04 caps the formal scope to focused invariants on a kernel-state
subset; the full delegation FSM is deferred to trajectory-4. D05 caps
the supply-chain scope to API-tier hygiene; the 88->70 crate
consolidation is deferred to trajectory-4. M06 lives inside both
caps.

## Prior-art reckoning

Trajectory-2 shipped (preserved verbatim by M06):

- Lean 4 theorem stack at `formal/lean4/Chio/` (83 theorems,
  0 sorries, 1 audited axiom). M06 does NOT touch Lean.
- TLA+ specs `RevocationPropagation.tla` (5 named invariants,
  1 liveness property) and `DelegationDepthBound.tla` (3 named
  invariants). M06 adds Apalache annotation comments to a subset
  but does not delete any TLC-shaped definitions.
- Kani harness set (30 proofs, 18 public). M06 does NOT touch Kani.
- Aeneas pilot (6 verified Rust symbols). M06 does NOT touch
  Aeneas.
- `formal/MAPPING.md` and `formal/assumptions.toml`. M06 edits
  the mapping file to add the 4 new Apalache rows and updates
  `assumptions.toml` to reflect that `RETIRED-SQLITE-CROSS-ROW` is
  now closed by a single Apalache invariant rather than a joint
  discharge.
- `supply-chain/audits.toml` (26 first-party rows). M06 ADDS
  certifications, does not delete or re-sign existing ones.
- `supply-chain/imports.lock` (cached upstream feeds). M06
  refreshes via `cargo vet regenerate imports`; the diff is committed.
- `deny.toml` (533 lines, 10 advisory ignores). M06 audits each
  ignore and either upstream-bumps it shut or re-justifies it with
  a refreshed CVE-status line.
- `.github/workflows/ci.yml` cargo-vet and cargo-deny jobs (lines
  302 and 318). M06 ADDS standalone workflows alongside; the
  in-CI jobs remain.
- `.github/workflows/release-binaries.yml` (cargo-auditable, syft,
  cosign). M06 extends it with a source-tree SBOM step; the
  binary SBOM emission is preserved.
- `infra/sbom/syft.yaml`. M06 EXTENDS to support source-tree
  scanning; binary scanning preserved.

What trajectory-2 left exposed (closed by M06):

- `formal/apalache/` does not exist. M06 P1 creates it with type
  annotations, 4 invariant specs, and a CI lane.
- Standalone `.github/workflows/sbom.yml` does not exist (SBOM
  emission today is folded into `release-binaries.yml`). M06 P3
  creates it as a tag-triggered + scheduled workflow producing
  source plus binary SBOMs at `supply-chain/sbom/v{tag}/`.
- Standalone `.github/workflows/cargo-vet.yml` does not exist
  (vet runs inside `ci.yml` only). M06 P2 creates it.
- `.github/workflows/cve-monitor.yml` does not exist. M06 P4
  creates it (cargo-audit + osv-scanner lanes; nightly + on-PR;
  GitHub Issues auto-file routing to `@bb-connor`).
- Apalache contractor not yet engaged. M06 P0 starts contractor
  scoping (Informal Systems primary, Runtime Verification fallback;
  D07 budget posture ~$40-60k); P5 records the sign-off memo.
- 891-row cargo-vet exemption baseline. M06 P2 chases 50-100 rows
  down; the milestone narrative explicitly says "do not chase zero".
- Top-50 most-central transitive deps not yet audited (the 26
  first-party rows cover proc-macro infra; the async runtime,
  serde, crypto, and tracing families are not yet certified). M06
  P2 seeds those.
- HITRUST-formatted SBOM provenance receipt (M09 P0 / P1 evidence
  row). M06 P3 produces it via a handshake doc with the assessor.

The 88-crate workspace shape baseline cited in the trajectory-3
README is approximate. The measured count today is **90** (two
extra crates landed during trajectory-2 close, likely
`crates/chio-formal-diff-tests` plus one more). D05 says
consolidation is deferred regardless; M06 treats the 90-crate shape
as fixed and the supply-chain pipeline is crate-shape-agnostic.

## Hard counts (measured 2026-04-30)

Reproduce with the commands in parentheses; the M06.P0.T1 audit doc
ticket re-runs every command and pins exact numbers.

- Lean: **83** theorems, 0 sorries, 1 audited axiom
  (`assumption.crypto.verify_capability_signature`).
  Source: `formal/proof-manifest.toml` plus `theorem-inventory.json`.
  M06 does NOT touch Lean.
- TLA+: **8** named invariants (5 in `RevocationPropagation.tla`,
  3 in `DelegationDepthBound.tla`); 1 liveness property
  (`RevocationEventuallySeen`). Source:
  `grep '^[A-Z][A-Za-z]+ ==' formal/tla/*.tla` plus
  `formal/MAPPING.md`.
- Apalache invariants today: **0**. `formal/apalache/` does not
  exist (`test -d formal/apalache && echo PRESENT || echo MISSING`).
- Kani: **30** `#[kani::proof]` attributes (18 public in
  `kani_public_harnesses.rs`, 12 internal in `kani_harnesses.rs`).
  Source: `grep -rn '#\[kani::proof\]' crates/chio-kernel-core/src/`.
- Active assumptions: **10** in `formal/assumptions.toml`
  `required_assumption_ids`; 1 retired (`RETIRED-SQLITE-CROSS-ROW`).
- Workspace crates: **90** (baseline 88; drift +2). Source:
  `awk '/^members = \[/,/^\]/' Cargo.toml | grep -c '^  "'`.
- Cargo.lock package records: **1147**.
  Source: `grep -c '^name = ' Cargo.lock`.
- cargo-vet first-party certifications: **26** rows
  (`supply-chain/audits.toml`, signed `who = "@bb-connor"`,
  `safe-to-deploy`).
- cargo-vet exemption rows (audit-this-later baseline): **891**
  in `supply-chain/config.toml`. cargo-vet import feeds: **4**
  (`bytecode-alliance`, `google`, `mozilla`, `zcash`).
- deny.toml advisory-ignore rows: **10** (lines 28-43). IDs:
  `RUSTSEC-2026-{0049,0098,0099,0104}`,
  `RUSTSEC-2025-{0141,0134,0068,0097}`, `RUSTSEC-2024-0436`,
  `RUSTSEC-2023-0071`. M06.P0.T4 re-runs `cargo audit` to
  confirm.
- Existing supply-chain workflows: **2**
  (`ci.yml` lines 302/318 for cargo-vet/cargo-deny;
  `release-binaries.yml` for syft + cosign). M06 ADDS 3 standalone
  workflows (`sbom.yml`, `cargo-vet.yml`, `cve-monitor.yml`).
- Apalache invariants chosen for M06 (per `research/m06/RESEARCH.md`
  and D04): **4** (`MonotoneLogApalache`, `RevocationCutCompleteness`,
  `ReceiptBeforeAllow`, `KernelTransitionCancelSafe`).
- Top-50 transitive deps not yet certified: **TBD** (M06.P0.T2
  generates via `cargo tree` plus reverse-edge centrality).
  Candidate families: async-runtime (tokio, futures, tower, hyper,
  rustls), serde, ed25519 / sha2 / subtle / zeroize, tracing.

## Workspace dependency state

M06 introduces two third-party version pins; the rest of the work
reuses trajectory-2 pins.

- `apalache-mc = 0.51.0` is pinned via the CI workflow
  (`.github/workflows/apalache-nightly.yml`) as a SHA-pinned
  tarball download. No crate dep needed; Apalache is a JVM-side
  tool invoked from CI. Pin source: latest tagged release on the
  Apalache GitHub repo at the time M06.P0 opens.
- `osv-scanner` is pinned via the CI workflow
  (`.github/workflows/cve-monitor.yml`) as a SHA-pinned download.
  No crate dep needed. Pin source: latest tagged release at the
  time M06.P4.T2 opens.

Reused trajectory-2 pins (no re-pin):
`cargo-vet = "0.10.2"` and `cargo-deny = "0.19.4"` (both in
`.github/workflows/ci.yml`); `cargo-auditable = "0.7.4"`,
`syft = "1.18.1"`, and `cosign` keyless (all in
`release-binaries.yml`; M06.P3 SBOM signing uses the same cosign
identity).

Apalache contractor engagement (D07 budget posture
~$40-60k):

- Primary: Informal Systems (Apalache origin org; candidates
  Igor Konnov, Jure Kukovec).
- Fallback: Runtime Verification Inc. (commercial formal-methods
  consultancy with Apalache + TLA+ engagement record).
- Backup independent: Andrey Kuprianov.
- Engagement model: fixed-fee per-invariant ($10k-$15k each, 4
  invariants, total $40-60k), 7-10 weeks calendar. Pre-contract
  scoping call in M06.P0.T3 confirms feasibility of the kernel-
  state subset before the contract is signed.

## Scope

### In

- 4 named Apalache invariants on a kernel-state subset:
  `MonotoneLogApalache`, `RevocationCutCompleteness`,
  `ReceiptBeforeAllow`, `KernelTransitionCancelSafe`. Each lives
  under `formal/apalache/` with its own `.tla` plus `MC*.cfg`
  pair; each is checked by `apalache-mc check` in
  `.github/workflows/apalache-nightly.yml`.
- Type annotations on the kernel-state subset of variables shared
  with `RevocationPropagation.tla` (Apalache requires
  `@type:` annotations; TLC ignores them).
- Bounded model parameters tuned for SMT tractability
  (`Authorities = 1..3`, `CapSet = 1..6`, `EpochMax = 4`).
- `formal/MAPPING.md` updated to add 4 new Apalache rows; cross-
  references to the 4 invariants from the existing TLA+ rows.
- `formal/assumptions.toml` updated to reflect
  `RETIRED-SQLITE-CROSS-ROW` is now discharged by a single Apalache
  invariant (`ReceiptBeforeAllow`).
- Apalache contractor sign-off memo (M06.P5.T1) at
  `.planning/trajectory-3/audits/M06-formal-supply-chain.md`
  section 3, naming the invariants checked, the Apalache version,
  the SMT solver invocation parameters, and the bounded model
  sizes.
- Standalone `.github/workflows/cargo-vet.yml` running
  `cargo vet --locked` on every PR; pinned to cargo-vet 0.10.2.
- Top-50 most-central transitive dep certifications added to
  `supply-chain/audits.toml` (the async-runtime, serde, crypto,
  tracing families); existing 26 first-party rows preserved.
- `cargo vet regenerate imports` refresh of
  `supply-chain/imports.lock`; commit the diff.
- 50-100 row chase-down on the 891-row exemption baseline (do not
  chase zero per the narrative).
- Standalone `.github/workflows/sbom.yml` emitting both source-
  tree and per-target binary SBOMs at
  `supply-chain/sbom/v{tag}/source.cdx.json` and
  `supply-chain/sbom/v{tag}/{target}.binary.cdx.json`. Both
  CycloneDX 1.6 JSON; cosign-signed via the existing keyless
  identity.
- `infra/sbom/syft.yaml` extended to support source-tree scanning
  (today it scans the binary only).
- M09 HITRUST assessor handshake doc confirming the SBOM format
  is consumable in the assessor portal (M06.P3.T5; cross-ref to
  M09 P0 evidence row).
- Standalone `.github/workflows/cve-monitor.yml` with
  cargo-audit (Rust primary) and osv-scanner (Python, JS
  secondary) lanes; nightly cron plus on-PR triggers; GitHub
  Issues auto-file routing to `@bb-connor` on advisory-db hit;
  severity filter at >= medium for issue creation, lower
  severities go to a weekly digest issue.
- `deny.toml` advisory-ignore audit: each of the 10 rows either
  closed by upstream bump (preferred) or re-justified with a
  refreshed CVE-status line and a date stamp.
- M06 audit doc closure (sections 2 + 3 + 4 populated; HITRUST
  receipt cross-linked).

### Out (and why)

- Full delegation FSM Apalache model. D04 defers to trajectory-4
  because it is a 16-20 week effort under 0.5 SR; the highest-
  value invariants are 7-10 weeks and capture most of the formal
  value.
- New Lean 4 theorems. The Lean stack is sealed (83 theorems,
  0 sorries). Adding theorems for the same properties M06 ships
  in Apalache duplicates work without closing a verdict gap.
  Trajectory-4 may extend Lean if a new property surfaces.
- New Kani harnesses. The 30 existing harnesses cover the
  single-step kernel surface; the 4 Apalache invariants cover the
  cross-step interleaving Kani cannot model. Adding more Kani
  harnesses chases coverage that the SMT-side Apalache work
  already produces.
- Crate consolidation 88 -> <=70. D05 defers to trajectory-4
  because moving public symbols across crate boundaries forces
  a breaking-change cascade across every downstream consumer;
  trajectory-3 cannot afford the churn.
- SPDX SBOM emission. The repository already emits CycloneDX 1.6
  via syft, and the M09 HITRUST control map consumes CycloneDX.
  syft can emit both formats with one extra `-o` flag if a
  downstream consumer demands SPDX; currently no consumer does.
- A second SBOM-signing identity. Reuses the existing cosign
  keyless identity used by `release-binaries.yml`; introducing a
  second identity would create an OIDC-token-provenance drift
  risk during the M03 reproducible-build verification.
- Reproducible-build pipeline. M03 owns
  `.github/workflows/reproducible-build.yml`; M06 SUPPLIES the
  SBOM that flows through it. Two-builder hash-equal verification
  is M03 P4 territory.
- Anchor-chain integrity Apalache invariant. TLA+/Apalache cannot
  reason about hash collisions; this property stays in Kani
  (`verify_oracle_inclusion_soundness`) modulo `ASSUME-SHA256`.
- AttenuationPreserving Apalache port. Already covered in TLA+
  AND Lean AND Kani; adding Apalache duplicates work for no
  verdict-evidence gain.
- RevocationEventuallySeen liveness Apalache check. Liveness;
  `formal/MAPPING.md` says the nightly Apalache lane "checks via
  `--temporal=`", so it lands in the same workflow file as the
  4 safety invariants but is bookkept separately (not counted
  against the 3-4 cap).

## Phases

### P0: Audit baseline + invariant shortlist + Apalache contractor scoping

Tickets:

- M06.P0.T1: Open M06 audit doc with hard counts (90 crates, 891
  exemption rows, 10 deny.toml advisory ignores, 30 Kani proofs,
  83 Lean theorems, 8 TLA+ invariants), reference-runner contract
  for the Apalache CI lane, and the 4 named Apalache invariants
  (`MonotoneLogApalache`, `RevocationCutCompleteness`,
  `ReceiptBeforeAllow`, `KernelTransitionCancelSafe`).
- M06.P0.T2: Generate the top-50 most-central transitive dep list
  via `cargo tree` plus reverse-edge centrality and pin into the
  audit doc as the M06.P2 cargo-vet certification target.
- M06.P0.T3: Apalache contractor pre-contract scoping call;
  confirm Informal Systems availability for the 4-invariant
  fixed-fee engagement; record outcome (signed / fallback /
  declined) in the audit doc. If declined, escalate to Runtime
  Verification.
- M06.P0.T4: Re-run `cargo audit` and pin the actual deny.toml
  advisory-ignore status (which of the 10 rows still hit, which
  closed via upstream bump since the trajectory-2 baseline). The
  output goes into the M06 audit doc as the P4 starting line.

### P1: Apalache spec for kernel-state subset (4 invariants)

Tickets:

- M06.P1.T1: Scaffold `formal/apalache/` with a `README.md`
  pointing to `formal/MAPPING.md`, plus `formal/apalache/Common.tla`
  carrying the type annotations and bounded sets shared across
  the 4 invariants.
- M06.P1.T2: Port `MonotoneLog` from
  `formal/tla/RevocationPropagation.tla` to Apalache annotation
  form at `formal/apalache/MonotoneLogApalache.tla`; ship
  `formal/apalache/MCMonotoneLogApalache.cfg`.
- M06.P1.T3: New invariant
  `formal/apalache/RevocationCutCompleteness.tla` plus
  `MCRevocationCutCompleteness.cfg`. Lifts the Lean
  `revocation_is_cut` theorem to a state-machine invariant under
  concurrent epoch updates.
- M06.P1.T4: New invariant
  `formal/apalache/ReceiptBeforeAllow.tla` plus
  `MCReceiptBeforeAllow.cfg`. Names the joint discharge of
  `RETIRED-SQLITE-CROSS-ROW` (today shared by `MonotoneLog` plus
  `budget_per_row_invariant`) as a single Apalache invariant.
- M06.P1.T5: New invariant
  `formal/apalache/KernelTransitionCancelSafe.tla` plus
  `MCKernelTransitionCancelSafe.cfg`. Covers cross-step
  interleaving Kani cannot model.
- M06.P1.T6: Wire CI lane
  `.github/workflows/apalache-nightly.yml` running
  `apalache-mc check` against each `MC*.cfg` file with the
  bounded sets pinned in M06.P1.T1 (`Authorities = 1..3`,
  `CapSet = 1..6`, `EpochMax = 4`); also runs the
  `RevocationEventuallySeen` liveness lane via `--temporal=`.

### P2: cargo-vet config + workspace import audit

Tickets:

- M06.P2.T1: Seed cargo-vet certifications for the top-50
  transitive deps from M06.P0.T2 in
  `supply-chain/audits.toml` (async-runtime, serde, crypto,
  tracing families). All certifications signed
  `who = "@bb-connor"`, criteria `safe-to-deploy`. Existing 26
  rows preserved.
- M06.P2.T2: Refresh upstream imports
  (`cargo vet regenerate imports`); commit the diff to
  `supply-chain/imports.lock`.
- M06.P2.T3: Add standalone `.github/workflows/cargo-vet.yml`
  running `cargo vet --locked` on every PR; cargo-vet 0.10.2
  pinned. The job is a duplicate of the in-`ci.yml` job
  (preserved); duplication is intentional so the cargo-vet
  signal does not vanish if `ci.yml` drift removes its lane.
- M06.P2.T4: Chase the 891-row exemption baseline DOWN by 50-100
  rows (target: 791-841 remaining). Each row removed is either
  certified in M06.P2.T1 or upgraded to a violation that
  surfaces in CI; do not chase zero.
- M06.P2.T5: Cargo-vet end-of-freeze sign-off; the
  m06-supply-chain-pivot freeze closes on this ticket plus
  M06.P3.T5 plus M06.P4.T5.

### P3: SBOM generation pipeline + per-release publication

Tickets:

- M06.P3.T1: Add `.github/workflows/sbom.yml` as a standalone
  tag-triggered + scheduled (weekly cron) workflow emitting
  source-tree and binary SBOMs. Source SBOM:
  `supply-chain/sbom/v{tag}/source.cdx.json`. Binary SBOMs:
  `supply-chain/sbom/v{tag}/{target}.binary.cdx.json` per
  release target. CycloneDX 1.6 JSON validated against the
  CycloneDX schema. Includes a determinism probe (run syft twice
  on the same source tree; assert byte-equal output) so M03's
  third-party rebuilder can verify the SBOM hash without a
  separate builder.
- M06.P3.T2: Extend `infra/sbom/syft.yaml` to support source-tree
  scanning (today binary-only). Adds the `dir:` scanner config
  with the same exclude paths (`./target/**`, `./node_modules/**`,
  `./.git/**`, `./.worktrees/**`).
- M06.P3.T3: Pin the SBOM publication path
  `supply-chain/sbom/v{tag}/` per the M06 audit doc template
  (section 4); update `.gitignore` to exempt this path so
  release SBOMs are committed to the tree.
- M06.P3.T4: Cosign-sign each SBOM file using the existing
  keyless identity from `release-binaries.yml`. Wire the SBOM
  signing inside the same release-binaries job so the OIDC
  token provenance chain is unified (do NOT introduce a
  separate signing key per the risk register).
- M06.P3.T5: M09 HITRUST assessor receipt: handshake doc at
  `.planning/trajectory-3/audits/M06-formal-supply-chain.md`
  section 4 confirming the SBOM is consumable in the assessor
  portal; cross-ref to M09 P0 evidence row. If the assessor
  demands SPDX, M06.P3.T1 adds an `-o spdx-json` flag at low
  cost.

### P4: CVE-alert workflow

Tickets:

- M06.P4.T1: Add `.github/workflows/cve-monitor.yml` running
  `cargo-audit` on every PR plus a nightly cron. Block-on-new-
  advisory; severity filter is informational (every hit is
  surfaced; the issue-creation filter in T3 is what limits
  noise). cargo-audit pinned to the latest tagged release at
  the time the workflow lands.
- M06.P4.T2: Add the osv-scanner secondary lane to the same
  workflow. Covers the Python (`crates/chio-conformance/
  verdict_matrix/drivers/python/`) and JS / TypeScript packages
  that cargo-audit does not. osv-scanner pinned to the latest
  tagged release.
- M06.P4.T3: GitHub Issues auto-file step on advisory-db hit;
  routes to `@bb-connor`. Severity filter at >= medium for
  per-advisory issues; severities below medium go into a
  weekly digest issue (avoids alert fatigue while preserving
  the synchronous gate per the M09 HITRUST control).
- M06.P4.T4: Refresh `deny.toml` ignore list. Each of the 10
  rows is either closed by an upstream bump (preferred,
  remove the ignore) or re-justified with a refreshed
  CVE-status line plus a `last-checked = 2026-MM-DD` date
  stamp.
- M06.P4.T5: CVE-monitor end-of-freeze sign-off; the
  m06-supply-chain-pivot freeze closes on M06.P2.T5 +
  M06.P3.T5 + M06.P4.T5.

### P5: Apalache contractor sign-off + audit doc closure

Tickets:

- M06.P5.T1: Apalache contractor produces a sign-off memo
  naming the 4 invariants checked, the Apalache version, the
  SMT solver invocations, the bounded model sizes
  (`Authorities`, `CapSet`, `EpochMax`), and any counterexamples
  surfaced (with the resolution per counterexample: spec fix,
  implementation fix, or out-of-bound). Memo lives in
  `formal/apalache/CONTRACTOR-SIGNOFF.md`.
- M06.P5.T2: Paste the contractor memo into
  `.planning/trajectory-3/audits/M06-formal-supply-chain.md`
  section 3; cross-ref the memo content from the Apalache
  workflow run URL.
- M06.P5.T3: M06 audit doc closure: sections 2 (hard counts
  refreshed), 3 (contractor record final), and 4 (closure
  attestations all green). HITRUST assessor receipt
  cross-linked from M06.P3.T5.

## Cross-milestone interactions

Hard dependencies (other trajectory-3 tickets):

- M06.P0.T1 must land before any other M06 ticket.
- M06.P1.T1 must land before M06.P1.T2..T6 (Common.tla provides
  the type annotations the 4 invariant specs reference).
- M06.P1.T6 should land after M06.P1.T2..T5 so the CI lane has
  all 4 `MC*.cfg` files to check.
- M06.P2.T1 must land before M06.P2.T4 (cannot remove an exemption
  row without first having a certification or violation).
- M06.P3.T1 must land before M06.P3.T3..T5 (publication path,
  cosign signing, and assessor handshake all bind to the
  workflow shape).
- M06.P3.T1 has a HARD dep on M03.P2.T* (the M03 reproducible-
  build workflow must exist before M06 wires its SBOM into it).
  The exact M03 ticket id resolves at M03 IMPLEMENT time;
  M06.P3.T1's gate_check tolerates absence of the M03 workflow
  (M06 SBOM still publishes; reproducible-build handshake waits
  on M03).
- M06.P4.T4 (deny.toml refresh) should land after M06.P4.T1+T2
  (workflow exists) but does not strictly depend on them; can
  parallel.
- M06.P5.T1 must land after M06.P1.T6 (contractor needs the CI
  lane green to certify the bounds).

Soft dependencies (cross-trajectory or sentence references):

- "trajectory-2 Lean 4 stack at `formal/lean4/Chio/` (83
  theorems, 0 sorries) is preserved verbatim by M06."
- "trajectory-2 TLA+ specs at `formal/tla/` (8 named invariants)
  are extended with Apalache annotation comments by M06.P1; no
  TLC-shaped definitions are deleted."
- "trajectory-2 Kani harness set
  (`crates/chio-kernel-core/src/kani_public_harnesses.rs`,
  30 proofs) is preserved verbatim by M06."
- "trajectory-2 `supply-chain/audits.toml` 26 first-party rows
  are preserved; M06.P2.T1 ADDS rows."
- "trajectory-2 `.github/workflows/release-binaries.yml`
  cargo-auditable + syft + cosign pipeline is preserved; M06.P3
  extends it with a source-tree SBOM step and reuses the cosign
  identity."
- "trajectory-2 `infra/sbom/syft.yaml` is extended for source-tree
  scanning by M06.P3.T2; binary-scanning config preserved."
- "M03 hosted CI restoration owns
  `.github/workflows/reproducible-build.yml`; M06 publishes the
  SBOM that flows through it. M06.P3.T1 has a soft_dep on
  M03.P2.T* (workflow scaffold)."
- "M08 protocol reviewer consumes the Apalache invariant set as
  formal-evidence input; M06.P5.T2 audit doc section 3 is the
  M08 input artifact."
- "M09 HITRUST assessor consumes the SBOM published at
  `supply-chain/sbom/v{tag}/source.cdx.json`; M06.P3.T5 is the
  M09 P0 / P1 evidence handshake."
- "freezes.yml `m06-revocation-oracle-pivot` covers
  `crates/chio-revocation-oracle/**`, `formal/tla/**`,
  `formal/apalache/**` during P1-P2; opens at M06.P1.T1, closes
  at M06.P2.T5."
- "freezes.yml `m06-supply-chain-pivot` covers `supply-chain/**`
  and the three new workflow files during P2-P4; opens at
  M06.P2.T1, closes at M06.P4.T5."

## Risks and mitigations

1. **Apalache contractor unavailable / withdraws mid-engagement.**
   Mitigation: M06.P0.T3 scoping call confirms availability;
   the audit doc names the fallback (Runtime Verification) and
   the backup independent (Andrey Kuprianov). If both primary
   and fallback withdraw, halt trigger 13 (vendor lane decline)
   fires; the orchestrator routes to the user for substitute or
   descope. Floor fallback: ship 3 invariants instead of 4; the
   M06 audit doc records the gap. Hard fallback: TLA+ TLC-only
   checking on the 4 specs (no Apalache symbolic check); record
   the degradation and accept the M08 reviewer caveat.
2. **Chosen invariants prove non-mechanizable in Apalache.**
   Mitigation: M06.P0.T3 ticket lets the contractor downgrade
   any invariant to "modeled in TLC, sketched in Apalache" and
   substitute another candidate from the top-6 list in
   `research/m06/RESEARCH.md`. The 4 chosen are the highest-
   leverage; the alternates are AttenuationPreserving (already
   in Lean, low gain) and RevocationEventuallySeen (liveness,
   not safety; lands as a sidecar lane regardless).
3. **cargo-vet imports surface unaudited transitive deps that
   block CI.**
   Mitigation: per the milestone narrative, the baseline accepts
   a documented threshold of audit-this-later rows; M06.P2.T4
   chases 50-100 rows down, not all 891. The standalone workflow
   in M06.P2.T3 is configured with `--locked` (does not
   regenerate); regeneration is a separate explicit ticket
   (M06.P2.T2).
4. **SBOM signing keys conflict with release-signing keys.**
   Mitigation: M06.P3.T4 reuses the existing cosign keyless
   identity; no new signing key introduced. M06.P3.T1 wires SBOM
   signing inside the same release-binaries job so OIDC token
   provenance is unified. If OIDC drift occurs, the audit doc
   captures it as a known risk and the M03 reproducible-build
   verifier confirms the signed-blob hash chain.
5. **CVE-alert pipeline overflows with low-severity advisories,
   producing alert fatigue.**
   Mitigation: M06.P4.T3 filters to severity >= medium for
   issue auto-file; lower severities go to a weekly digest
   issue. The synchronous block-on-new-advisory gate in M06.P4.T1
   still fires regardless of severity; only the issue-creation
   path is severity-filtered.
6. **Apalache spec bounds prove too small to surface
   counterexamples (false-green risk).**
   Mitigation: M06.P5.T1 contractor memo records the bound
   choices and the SMT timeouts; the contractor MAY raise
   bounds incrementally if the SMT solver is fast (the
   `MCRevocationPropagation.cfg` TLC bounds of `PROCS=4,
   CAPS=8, DEPTH_MAX=4` set the upper aspiration; Apalache
   starts at the smaller `1..3 / 1..6 / 4` envelope). The
   audit doc records both attempted-bound and final-bound.
7. **Reproducible-build hash drift between SBOM emissions on
   builders A and B (M03 third-party verifier).**
   Mitigation: M06.P3.T1 includes a determinism probe (run
   syft twice on the same source tree; assert byte-equal). The
   M03 reproducible-build job is the single builder per
   artifact; the third-party rebuilder verifies the SBOM hash
   as part of M03 P4 hash-equal handoff. syft determinism is
   high but timestamp emission is the known exception; the
   `infra/sbom/syft.yaml` excludes already suppress it.
8. **M09 HITRUST assessor rejects the CycloneDX SBOM format,
   demands SPDX or a different schema version.**
   Mitigation: M06.P3.T5 handshake doc confirms format
   acceptability BEFORE the M09 audit window opens; if the
   assessor demands SPDX, M06.P3.T1 adds `-o spdx-json` to the
   syft invocation at low cost (one workflow line). If the
   assessor demands a non-syft tool entirely, halt trigger 14
   (HITRUST assessor rejection) fires and the orchestrator
   routes to substitute tooling or M09 descope.
9. **Lean theorem-inventory drift during the M06 freeze window
   (cross-milestone PR sneaks a Lean edit into trajectory-3).**
   Mitigation: M06 narrative says NO Lean edits; the Lean stack
   is sealed verbatim. The M06 audit doc closure check in
   M06.P5.T3 verifies `formal/proof-manifest.toml` and
   `theorem-inventory.json` are byte-identical to the P0
   baseline; any drift fails the gate and the orchestrator
   surfaces the offending PR.

## Success criteria

- 4 named Apalache invariants (`MonotoneLogApalache`,
  `RevocationCutCompleteness`, `ReceiptBeforeAllow`,
  `KernelTransitionCancelSafe`) checked under
  `formal/apalache/`; each spec validates with `apalache-mc
  check` and the corresponding `MC*.cfg`.
- `.github/workflows/apalache-nightly.yml` runs the 4 safety
  checks plus the `RevocationEventuallySeen` liveness check; CI
  green for 7 consecutive nightly runs before M06 closes.
- `formal/MAPPING.md` carries 4 new Apalache rows cross-
  referenced from the existing TLA+ rows.
- `formal/assumptions.toml` records `RETIRED-SQLITE-CROSS-ROW`
  as discharged by `ReceiptBeforeAllow` (single Apalache
  invariant; replaces the joint discharge).
- Apalache contractor sign-off memo committed at
  `formal/apalache/CONTRACTOR-SIGNOFF.md` and pasted into the
  M06 audit doc section 3, naming Apalache version, bounds,
  and SMT solver invocations.
- `supply-chain/audits.toml` carries 26 + N first-party rows
  where N is the count of newly-certified top-50 transitive
  deps; existing 26 rows preserved.
- `supply-chain/imports.lock` refreshed via `cargo vet
  regenerate imports`; diff committed.
- `supply-chain/config.toml` exemption row count reduced by
  50-100 (target: 791-841 remaining; do not chase zero).
- Standalone `.github/workflows/cargo-vet.yml` live; CI green.
- Standalone `.github/workflows/sbom.yml` live; tag-triggered
  emission produces both source-tree and binary SBOMs at
  `supply-chain/sbom/v{tag}/`; both files cosign-signed by the
  release-binaries identity.
- M09 HITRUST assessor handshake doc confirms SBOM
  consumability; cross-ref recorded in M06 audit doc section 4.
- Standalone `.github/workflows/cve-monitor.yml` live;
  cargo-audit (Rust) and osv-scanner (Python, JS) lanes both
  green on baseline; GitHub Issues auto-file routing to
  `@bb-connor` verified end-to-end with a synthetic advisory
  hit.
- `deny.toml` advisory-ignore list reviewed: each of 10 rows
  either closed by upstream bump or re-justified with a
  `last-checked = 2026-MM-DD` date stamp.
- M06 audit doc final pass complete: hard counts refreshed
  (sections 2), contractor record final (section 3), closure
  attestations all green (section 4).
- m06-supply-chain-pivot freeze closes on M06.P2.T5 +
  M06.P3.T5 + M06.P4.T5; m06-revocation-oracle-pivot freeze
  closes on M06.P2.T5.
- Lean theorem inventory byte-identical to the P0 baseline
  (no drift during the freeze window).
