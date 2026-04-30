# M08 Chio Arena Audit

Snapshot date: 2026-04-30

Ticket: M08.P0.T1

Source of truth:

- `.planning/trajectory-2/08-chio-arena-replay-coliseum.md`
- `.planning/trajectory-2/tickets/M08/P0.yml`
- `.planning/trajectory-2/tickets/manifest.yml`
- `.planning/trajectory-2/EXECUTION-BOARD.md`
- `.planning/trajectory-2/freezes.yml`

## Gate Phrases

This audit intentionally records the exact prerequisite names required by
the M08.P0.T1 gate:

- trajectory-1 M04
- trajectory-1 M05
- trajectory-1 M07.P4.T6

## Scope

M08 builds `chio-arena`, a deterministic replay coliseum that generates
multi-agent scenarios, drives real Chio kernel instances, and emits receipt
bundles that the existing replay machinery can verify. The milestone does
not invent a new replay format, a new kernel execution model, or a new
verdict comparator. It composes earlier trajectory surfaces and feeds later
trajectory-2 gates.

M08 is not a trust-boundary milestone in `freezes.yml`, and M08.P0.T1 owns
only this audit file. Later M08 tickets must still respect active freezes in
M03, M04, M05, and M10 when their outputs or dependencies touch those
surfaces.

## Prerequisite Snapshot

### trajectory-1 M04 deterministic replay

State: present and load-bearing.

Observed artifacts:

- `crates/chio-replay-corpus/src/m04_writer.rs` defines
  `M04Scenario`, `write_m04_fixture`, `M04ByteSizes`, and the stable file
  constants `receipts.ndjson`, `checkpoint.json`, and `root.hex`.
- `tests/replay/fixtures/` currently has 10 top-level fixture families and
  50 fixture files.
- The fixture families are `allow_metered`, `allow_simple`,
  `allow_with_delegation`, `deny_expired`, `deny_revoked`,
  `deny_scope_mismatch`, `guard_rewrite`, `replay_attack`,
  `tampered_canonical_json`, and `tampered_signature`.

M08 dependency contract:

- Arena receipt bundles must reuse the M04 writer surface instead of
  reimplementing bundle serialization.
- Arena outputs must keep the M04 three-file bundle layout:
  `receipts.ndjson`, `checkpoint.json`, and `root.hex`.
- Auto-promoted arena cases must live under the arena namespace described
  by the M08 narrative and pass through the existing CHIO_BLESS discipline.

### trajectory-1 M05 async kernel

State: present and load-bearing.

Observed artifacts:

- `crates/chio-kernel/src/kernel/mod.rs` exposes
  `pub async fn evaluate_tool_call(&self, request: &ToolCallRequest)`.
- The public async entrypoint takes `&self`, not `&mut self`, which is the
  substrate M08 needs for shared kernel access in one process.
- The current async body routes through the `ToolEvaluator` abstraction and
  the default `BlockingToolEvaluator`, preserving the existing sync pipeline
  semantics while keeping the call site async.
- Kernel setup methods remain mutable setup surfaces. M08 runtime code
  should configure kernels before sharing them with arena agents.

M08 dependency contract:

- Arena runtime should drive existing `ChioKernel` instances through the
  async entrypoint.
- Arena runtime should use shared ownership or per-agent kernels as called
  out in the narrative, without adding a new `*_blocking` shim or restoring
  an exclusive dispatch bottleneck.
- Any future M08 concurrency tests should prove deterministic scheduling on
  top of this substrate rather than relying on wall-clock timing.

### trajectory-1 M07.P4.T6 verdict equality oracle

State: present as the provider conformance equality surface, and extended
by the trajectory-2 M02 matrix.

Observed artifacts:

- `crates/chio-provider-conformance/src/assertions.rs` exposes exact
  canonical-byte and verdict equality helpers, including
  `assert_verdict_eq`.
- `crates/chio-provider-conformance/tests/cross_provider_equality.rs`
  exercises cross-provider normalized receipt and verdict equality.
- `crates/chio-conformance/verdict_matrix/src/diff_oracle.rs` now provides
  the trajectory-2 matrix oracle that compares verdict tuples.

M08 dependency contract:

- Arena ranking and fitness functions should compare verdict tuples through
  the existing equality semantics, not a new arena-local comparator.
- M08 may widen the witness set from provider verdicts to kernel-instance
  verdicts, but the equality contract remains verdict plus reason code plus
  scope set where the M02 oracle is in play.

### trajectory-2 M02 verdict_matrix

State: present on this branch snapshot.

Observed artifacts:

- `crates/chio-conformance/verdict_matrix/SCENARIOS.md` exists.
- `crates/chio-conformance/verdict_matrix/manifest.toml` exists and reports
  `status = "active"`, `scenario_count = 48`, and required driver
  `rust-kernel`.
- Scenario families are present for `capability_subset`,
  `revocation_propagation`, `replay_verdict`, and
  `redaction_determinism`, with 12 JSON scenarios each.
- `crates/chio-conformance/verdict_matrix/src/diff_oracle.rs` validates the
  manifest, scenario schema, corpus hash, driver reports, and reason-code
  registry linkage.
- The oracle manifest names tuple fields `verdict`, `reason_code`, and
  `scope_set`, with reason registry `spec/errors/registry.yaml`.

M08 dependency contract:

- Arena outputs that graduate into cross-SDK comparison must feed the M02
  manifest and bless path rather than creating a parallel scenario registry.
- Arena leaderboard output should treat the M02 tuple fields as the stable
  comparison boundary.
- Later M08 tickets should re-check the M02 matrix state before wiring P4
  and P5, since M02 is actively evolving in Wave 1.

## Handoff Constraints For Later M08 Tickets

- Do not edit `crates/chio-kernel/src/kernel/mod.rs` for arena runtime
  convenience. The M08 narrative explicitly says the arena is a thin layer
  above the M05 kernel surface.
- Do not edit the existing M04 fixture families in place. Arena-promoted
  material belongs under the arena namespace.
- Do not add provider SDK dependencies to `chio-arena`. The arena remains
  provider-agnostic and consumes provider fabric through trait surfaces.
- Do not reinterpret the existing `crates/chio-link/` oracle crate as the
  arena in-process link. The narrative places the arena channel link under
  `crates/chio-arena/src/link/`.
- Do not change receipt schemas for M08. Receipt bundle compatibility is a
  hard dependency on the M04 replay corpus and replay engine.

## Verification Notes

Commands used while creating this snapshot:

- `find tests/replay/fixtures -mindepth 1 -maxdepth 1 -type d | wc -l`
- `find tests/replay/fixtures -type f | wc -l`
- `find crates/chio-conformance/verdict_matrix/scenarios -mindepth 2 -maxdepth 2 -name '*.json' | wc -l`
- `sed -n '1,140p' crates/chio-conformance/verdict_matrix/manifest.toml`
- `rg -n "M04Scenario|write_m04_fixture|RECEIPTS_FILENAME|CHECKPOINT_FILENAME|ROOT_FILENAME|M04ByteSizes" crates/chio-replay-corpus/src/m04_writer.rs tests/replay`
- `rg -n "Arc<ChioKernel>|evaluate_tool_call|async fn evaluate_tool_call|&mut self|ChioKernel" crates/chio-kernel/src/kernel/mod.rs crates/chio-kernel/src/lib.rs`

P1 walking-skeleton evidence:

- `cargo test -p chio-arena --test walking_skeleton -- --nocapture` loads
  `arena/scenarios/walking_skeleton.toml`, drives one `ChioKernel`, and
  writes an M04-shaped bundle with `receipts.ndjson`, `checkpoint.json`,
  `root.hex`, and sibling `arena.json`.
- The P1 test recomputes the M04 root from the exact `receipts.ndjson` and
  `checkpoint.json` bytes and checks it against `root.hex`, proving
  bit-exact replay-bundle compatibility with the M04 root derivation.
- The P1 test intentionally does not invoke the `chio replay` CLI directly.
  CLI wiring is scoped to M08.P5, so P1 keeps replay-engine ownership in
  `chio-replay-corpus` and `chio-cli` while still proving the M04 byte
  contract.

This file is prose-only and does not modify ticket state, execution state,
the generated manifest, Cargo files, or code.
