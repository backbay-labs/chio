# Trajectory 5.1 Tickets

Each ticket has one owner-class, one acceptance gate, and an explicit close
condition. The order below is the execution order unless a ticket says it can
run in parallel.

## Baseline

### T5.1-BL-001: Fix merged conformance build break

Owner-class: release integrator.

Scope: remove stale `?Send` async-trait impl annotations from conformance test
`ToolServerConnection` impls after the merged trait became `Send`.

Acceptance:

- `rg 'async_trait::async_trait\\(\\?Send\\)' crates/chio-conformance` returns no matches.
- `cargo check -p chio-kernel -p chio-anchor -p chio-federation -p chio-conformance --tests` passes.

### T5.1-BL-002: Stale PR closeout map

Owner-class: release integrator.

Scope: close, supersede, or restack remaining Trajectory 5 PRs against merged
`main`.

Acceptance:

- PRs already represented on `main` are closed or labeled superseded.
- #618 remains parked or closed without merging.
- #628 and #629 are either closed as superseded or restacked into small,
  main-based deltas.

## Lane B Runtime

### T5.1-B-001: Cancellation-safe post-admission dispatch

Owner-class: runtime owner.

Scope: make public async tool evaluation unwind budget, payment, and receipt
state when a future is dropped after admission and before terminal receipt
recording.

Acceptance:

- A timeout/drop test proves admitted budget and payment state are released or
  finalized.
- A terminal cancellation or interrupted receipt is recorded, or a documented
  denial path proves no admission occurred.
- The test fails if the post-admission await is reverted to the current shape.

### T5.1-B-002: Explicit receipt context instead of thread-local scope

Owner-class: runtime owner.

Scope: replace tenant and governed receipt scope thread-local dependence with
request-keyed or task-local context that survives async runtime migration.

Acceptance:

- A multi-thread Tokio test yields across dispatch and still persists tenant
  and governed metadata.
- Receipt-building code has a non-thread-local fallback for tenant scope, as it
  already does for federation admission snapshots.

### T5.1-B-003: Federated dispatch requires durable local receipt storage

Owner-class: runtime owner.

Scope: deny federated v1 and v2 dispatch before tool invocation when no durable
local receipt store is configured.

Acceptance:

- A fresh v1 peer with no receipt store denies before tool invocation.
- Cosigner is not called.
- No dual receipt or DSSE artifact is produced.

### T5.1-B-004: DSSE cosigner protocol for Org A signing

Owner-class: federation owner.

Scope: route Org A DSSE PAE signing through a cosigner protocol instead of
requiring Org A private key material in the tool-host path.

Acceptance:

- Kernel federation path can emit and verify `DsseEnvelope`.
- `DualSignedReceipt` is documented and tested as compatibility-only.
- Missing, malicious, or key-mismatched cosigner denies without persistence.

### T5.1-B-005: Strict CHIODOS bilateral invocation profile

Owner-class: federation owner.

Scope: replace the current signature-slice-only conformance with a strict
`chio.bilateral-cosign-invocation.v1` predicate profile.

Acceptance:

- Full schema validation exists for required predicate fields.
- Negative tests reject signature-slice artifacts as strict CHIODOS
  conformance.
- `scripts/check-bounded-ship-bar.sh --diagnostic` no longer reports B4 as
  interim-only.

## Lane A Evidence

### T5.1-A-001: Full hosted-nightly mutation rebaseline

Owner-class: assurance owner.

Scope: replace partial or below-target mutation rows with complete evidence or
explicitly accepted sampling contracts.

Acceptance:

- All target crates have complete cargo-mutants JSON or approved sampling
  contract.
- `chio-attest-verify` meets 80 percent or records honest non-closure.
- Other target crates meet 65 percent or record honest non-closure.
- README banner and `releases.toml` use observed values, not targets.

### T5.1-A-002: Strict threat-mutants evidence closure

Owner-class: assurance owner.

Scope: make threat coverage match `scripts/check-threat-coverage-mutants.sh`.

Acceptance:

- `bash scripts/check-threat-coverage-mutants.sh` exits 0.
- No covered or partial row uses bootstrap placeholder or generated metadata as
  mutants evidence.
- `docs/security/threat-coverage.md` matches strict script output.

### T5.1-A-003: Kani claim alignment

Owner-class: assurance owner.

Scope: align manifest entries with claimed invariants, or demote claims to
model-only.

Acceptance:

- Planned direct production-entry invariants either exist or the ticket text is
  revised to match actual model-only evidence.
- Run transcripts exist for all manifest entries.

### T5.1-A-004: Formal evidence closure

Owner-class: formal methods owner.

Scope: reconcile Apalache bounds, Lean theorem names, theorem inventory, and
CI/qualification integration.

Acceptance:

- Apalache bound decision is documented and reflected in evidence.
- Lean theorem inventory matches proven theorem names.
- A local or CI command runs `lake build` for the claimed proof set.

### T5.1-A-005: Bounded assurance manifest

Owner-class: assurance owner.

Scope: add `audits/evidence/bounded-assurance-manifest.json` generated from
merged `main`.

Acceptance:

- Manifest hashes Lane A, B, and C evidence artifacts.
- Stale and missing manifests fail `scripts/tests/check-bounded-ship-bar.test.sh`.
- Current manifest passes the manifest block of `scripts/check-bounded-ship-bar.sh`.

## Lane C Canary

### T5.1-C-001: Kernel-backed Chiodome canary

Owner-class: demo owner.

Scope: regenerate canary artifacts from production hot paths rather than
synthetic receipts.

Acceptance:

- Deterministic run writes `receipt.json`, `envelope.json`, and
  `checkpoint.json` under `examples/chiodome-bilateral/fixtures/v0.1.0-bounded-chiodome/`.
- At least two transcripts and golden inspect output are committed.
- Rerun is diff-stable.

### T5.1-C-002: KB MCP policy and replay alignment

Owner-class: demo owner.

Scope: align the demo policy with the replayed KB MCP tools, or make the replay
use only policy-declared tool names.

Acceptance:

- Allowed KB call produces the expected mediated artifact or receipt.
- Destructive or undeclared call denies.
- The default script passes the intended policy into the wrap path.

### T5.1-C-003: Receipt explain verification mode

Owner-class: federation owner.

Scope: separate structural inspection from verification and add a pinned-key,
store-backed verification mode.

Acceptance:

- CLI output contains `verification_performed=true` only when keys and stores
  were actually checked.
- Bad signature, missing store, bad lease, and policy mismatch cases fail.

### T5.1-C-004: Selective-disclosure boundary cleanup

Owner-class: federation owner.

Scope: keep `bbs-stub` clearly non-cryptographic until real BBS+ or zk proof
support lands.

Acceptance:

- Release and planning docs cannot claim BBS+, zk, or privacy-preserving
  selective disclosure from the stub.
- Strict checks fail if an evidence-complete marker is set without real proof
  fixtures.

## Packaging

### T5.1-P-001: Deferred bounded package restart

Owner-class: release owner.

Scope: restart #618 only after strict A/B/C gates pass.

Acceptance:

- Root `releases.toml [v0_1_0_bounded_chiodome]` records concrete
  `release_status` and 40-hex `integrated_merge_sha`.
- Versioned fixtures, tarball notes, and CI evidence are regenerated from
  merged `main`.

## 2026-05-09 Execution Status

| Ticket | Status | Evidence |
| --- | --- | --- |
| T5.1-BL-001 | Done | `cargo check -p chio-kernel -p chio-anchor -p chio-federation -p chio-conformance --tests` passed. |
| T5.1-BL-002 | Done | PRs #609, #610, #611, #614, #615, #616, #617, #618, #620, #628, and #629 closed after #627 landed. |
| T5.1-B-001 | Done | `cargo test -p chio-kernel monetary_ -- --nocapture` passed with the post-admission drop test. |
| T5.1-B-002 | Done | `cargo test -p chio-kernel tenant -- --nocapture` passed with request-keyed tenant receipt context. |
| T5.1-B-003 | Done | `cargo test -p chio-conformance --test b2_receipt_v2_failclosed_pre_dispatch` passed. |
| T5.1-B-004 | Done | `cargo test -p chio-kernel federated_request -- --nocapture` and `cargo test -p chio-federation --test bilateral_signing -- --nocapture` passed. |
| T5.1-B-005 | Done | `cargo test -p chio-conformance --test b4_bilateral_dsse_pae_conformance` passed and the ship-bar no longer reports B4 interim-only. |
| T5.1-A-001 | Honest partial | README, `releases.toml`, and `audits/evidence/mutants/banner.json` now record observed partial/below-target values instead of targets. |
| T5.1-A-002 | Done | `bash scripts/check-threat-coverage.sh` and `bash scripts/check-threat-coverage-mutants.sh` passed with 20 pending rows and zero false-covered rows. |
| T5.1-A-003 | Done | `cargo-kani 0.67.0` is installed and `bash scripts/run-kani-manifest.sh --lane pr` passed all 30 manifest harnesses. |
| T5.1-A-004 | Done | `python3 scripts/check-apalache-formal-slice.py`, all four bounded Apalache checks, and `lake build` under `formal/lean4/Chio` passed. |
| T5.1-A-005 | Done | `audits/evidence/bounded-assurance-manifest.json` verifies under `bash scripts/check-bounded-ship-bar.sh --diagnostic`. |
| T5.1-C-001 | Done | Versioned receipt, envelope, checkpoint, transcripts, and golden output are present under `examples/chiodome-bilateral/`. |
| T5.1-C-002 | Partial | Replay policy/tool naming is aligned for read-only fixture tools, but the default `mcp wrap --e2e-fixture` path is still manifest-scaffold based rather than full policy-backed `mcp serve`. |
| T5.1-C-003 | Partial | CLI output honestly reports inspection-only behavior; pinned-key/store-backed verification remains a future release blocker. |
| T5.1-C-004 | Done | C5 remains explicitly deferred with `release_claim_allowed = "no"` and ship-bar checks reject false completion. |
| T5.1-P-001 | Blocked | `releases.toml` records `blocked_pending_full_assurance_gate` and the integrated merge SHA. Packaging restarts only after strict gate partials are zero. |
