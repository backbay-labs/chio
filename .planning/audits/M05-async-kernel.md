# M05 Async-Kernel Pivot: Audit Baseline

This doc captures the starting state of the kernel surface before the M05
async-kernel pivot. Subsequent phases (P1-P4) will move methods off
`&mut self`, replace `std::sync` primitives with async-aware equivalents
or lock-free containers, and convert the public evaluate-tool-call surface
to a real async body. This file tracks the targets to retire.

Source-of-truth: `.planning/trajectory/05-async-kernel-real.md`. The hard
counts in that document were measured 2026-04-25; the snapshot below was
taken 2026-04-26 and matches the trajectory exactly (no drift).

## Starting counts (snapshot 2026-04-26)

The three gate-tracked numbers:

- **1133** fn signatures under `crates/chio-kernel/src/`. Of these, only
  3 are `async fn` and the kernel crate has 3 `.await` sites total
  (0.26 percent async coverage).
- **27** `&mut self` methods on `Session` in `crates/chio-kernel/src/session.rs`
  (1186 lines). Every state transition demands exclusive access today.
- **10** sync primitives held inside the `ChioKernel` struct at
  `crates/chio-kernel/src/kernel/mod.rs` (definition starts at line 875).
  All `std::sync`, none `tokio::sync`.

### Sync-primitive inventory (the 10 fields)

| # | Field | Type |
|---|-------|------|
| 1 | `budget_store` | `Mutex<Box<dyn BudgetStore>>` |
| 2 | `revocation_store` | `Mutex<Box<dyn RevocationStore>>` |
| 3 | `sessions` | `RwLock<HashMap<SessionId, Session>>` |
| 4 | `receipt_log` | `Mutex<ReceiptLog>` |
| 5 | `child_receipt_log` | `Mutex<ChildReceiptLog>` |
| 6 | `receipt_store` | `Option<Mutex<Box<dyn ReceiptStore>>>` |
| 7 | `emergency_stop_reason` | `Mutex<Option<String>>` |
| 8 | `federation_peers` | `RwLock<HashMap<String, FederationPeer>>` |
| 9 | `federation_dual_receipts` | `Mutex<HashMap<String, DualSignedReceipt>>` |
| 10 | `federation_local_kernel_id` | `Mutex<Option<String>>` |

### Reproduction commands

```bash
# 1133 fn signatures in the kernel crate
grep -rE '^\s*(pub\s+)?(async\s+)?fn\s+' crates/chio-kernel/src/ | wc -l

# 3 async fn signatures
grep -rE '^\s*(pub\s+)?async\s+fn\s+' crates/chio-kernel/src/ | wc -l

# 27 &mut self methods on Session
grep -c '&mut self' crates/chio-kernel/src/session.rs

# 10 sync primitives: read the ChioKernel struct definition
sed -n '875,961p' crates/chio-kernel/src/kernel/mod.rs
```

The trajectory cites a workspace-wide `&mut self` and `Mutex|RwLock` count
when measured by `rg -c` across `crates/chio-kernel/src/`; those wider
scans return larger figures (141 `&mut self` lines, 49 `Mutex|RwLock`
mentions) because they include every method body, doc comment, and
generic-parameter use, not just the targets the pivot retires. The
canonical baselines are the three above (1133, 27, 10), which are what
the gate-check enforces.

## Target end state (M05 exit)

- 0 `&mut self` methods on `Session`. Per-session state moves behind
  `Arc<SessionState>` with internal `tokio::sync::RwLock` and
  `AtomicU64` counters.
- 0 `std::sync::Mutex` / `std::sync::RwLock` fields in `ChioKernel`.
  Async-aware replacements are `tokio::sync::*`, lock-free
  `dashmap::DashMap`, and `arc-swap::ArcSwap` where copy-on-write is
  acceptable.
- `evaluate_tool_call` and `dispatch_tool_call_with_cost` become real
  `async fn` bodies that `.await` guard evaluation, store reads, receipt
  signing, and tool dispatch (today they delegate one-line through to a
  sync method).

## Mega-file inventory

The largest concurrency hotspots and bench-attribution targets (re-checked
on 2026-04-26, all under the 304 file-size gate of 3000 lines):

| File | LOC |
|------|----:|
| `crates/chio-kernel/src/kernel/mod.rs` | 5800 |
| `crates/chio-kernel/src/operator_report.rs` | 1759 |
| `crates/chio-kernel/src/budget_store.rs` | 1711 |
| `crates/chio-kernel/src/kernel/responses.rs` | 1526 |
| `crates/chio-kernel/src/receipt_support.rs` | 1494 |
| `crates/chio-kernel/src/checkpoint.rs` | 1481 |
| `crates/chio-kernel/src/approval.rs` | 1404 |
| `crates/chio-kernel/src/session.rs` | 1186 |

Note: `kernel/mod.rs` exceeds the 3000-line gate because the gate excludes
this file by allowlist (it is the kernel definition itself); the M05 pivot
plan is to leave the file structure alone and change types, not to split.

## Phase tracking

- [x] P0.T1: bench scaffold (12 criterion harnesses) - LANDED PR #166
- [x] P0.T2: workspace dep pins (dashmap, arc-swap, loom, parking_lot,
  tower) - LANDED PR #173
- [x] P0.T3: this audit doc - LANDED PR #<pending>
- [x] P0.T4: kernel-paths freeze (CODEOWNERS + ruleset + announcement)
- [x] P0.T5: cargo-mutants baseline kill rate on chio-kernel

## Freeze announcement

- **Date**: 2026-04-27
- **Freeze id**: `m05-kernel-async-pivot`
  (.planning/trajectory/freezes.yml)
- **Frozen paths**:
  - `crates/chio-kernel/src/kernel/mod.rs`
  - `crates/chio-kernel/src/session.rs`
  - `crates/chio-kernel/src/kernel/session_ops.rs` (sibling under same
    freeze id; tracks the contended Session-on-Kernel call surface)
- **Duration**: M05 P1 through M05 P3. Released by M05.P4.T3
  (`feat(m05): release kernel/session freeze` flips
  `state: active` -> `state: released` and removes the principal-engineer
  CODEOWNERS overrides).
- **Review routing**:
  CODEOWNERS routes the frozen paths to `@bb-connor` (single-owner
  trajectory; the `M05_FREEZE` slug in `OWNERS.toml` resolves to the
  same handle). The root `CODEOWNERS` file is generated from
  `OWNERS.toml` via `scripts/regen-codeowners.sh`; `.github/CODEOWNERS`
  is a symlink to the root file so server-side gates and the
  `m05-freeze-guard` workflow read identical content.
- **Server-side gate**: `.github/workflows/m05-freeze-guard.yml`
  computes the changed-file set against the merge base, intersects with
  the `paths:` list of `m05-kernel-async-pivot` in `freezes.yml`, and
  fails the required check if any frozen path is touched and the PR
  title does not begin with the bypass label.
- **Bypass**: hotfix PRs land via a tagged `hotfix/` branch with the
  PR title prefixed `[M05-bypass]`. The bypass path requires explicit
  `@bb-connor` review and a documented justification appended to this
  audit doc under a "Bypass log" section. The same workflow accepts
  the standard `[M05]` prefix for in-milestone work.
- **Activation phase**: M05.P0.T4 (`start_phase` in `freezes.yml`).
  M05.P0.T5 (cargo-mutants baseline) is the only ticket that may
  re-touch `kernel/mod.rs` or `session.rs` indirectly via a tooling
  script, and it does not modify those source files.

## Re-audit cadence

The audit re-runs at the start of each P{N} phase (P1, P2, P3, P4) and at
M05 exit. Each re-audit appends a dated snapshot section below this one;
the `&mut self` and sync-primitive counts should monotonically decrease
toward zero. Total fn-signature count (1133) is informational and may
grow as new async machinery is added.

## Snapshots

### 2026-04-26 (P0 baseline)

| Metric | Count | Target |
|--------|------:|------:|
| fn signatures (kernel crate) | 1133 | n/a (informational) |
| `async fn` signatures | 3 | grow |
| `.await` sites | 3 | grow |
| `&mut self` on `Session` | 27 | 0 |
| sync primitives in `ChioKernel` | 10 | 0 |

### 2026-04-27 (P1.T6 caller migration and pub-use freeze)

Scope: M05.P1.T6 owned paths only:

- `crates/chio-kernel/src/lib.rs`
- `crates/chio-cli/**`
- `crates/chio-mcp-edge/**`
- `crates/chio-mcp-adapter/**`
- `crates/chio-a2a-edge/**`
- `crates/chio-acp-edge/**`
- `crates/chio-acp-proxy/**`
- `crates/chio-control-plane/**`

Caller survey:

| Surface | Result |
|---------|--------|
| `crates/chio-cli/**` | Test callers now use `ChioKernel::evaluate_tool_call(...).await`; no owned `evaluate_tool_call_blocking(...)` references remain. |
| `crates/chio-mcp-edge/**` | No deprecated `evaluate_tool_call_blocking(...)` references. One metadata-preserving bridge remains on `evaluate_tool_call_blocking_with_metadata(...)` because the owned public async surface has no metadata-bearing counterpart yet. |
| `crates/chio-mcp-adapter/**` | No direct deprecated kernel sync evaluator references. |
| `crates/chio-a2a-edge/**` | No direct deprecated kernel sync evaluator references. |
| `crates/chio-acp-edge/**` | No direct deprecated kernel sync evaluator references. |
| `crates/chio-acp-proxy/**` | No direct deprecated kernel sync evaluator references. |
| `crates/chio-control-plane/**` | No direct deprecated kernel sync evaluator references. |

Reproduction:

```bash
rg -n "evaluate_tool_call_blocking\(" \
  crates/chio-cli crates/chio-mcp-edge crates/chio-mcp-adapter \
  crates/chio-a2a-edge crates/chio-acp-edge crates/chio-acp-proxy \
  crates/chio-control-plane crates/chio-kernel/src/lib.rs
# no matches

rg -n "evaluate_tool_call_blocking_with_metadata" \
  crates/chio-cli crates/chio-mcp-edge crates/chio-mcp-adapter \
  crates/chio-a2a-edge crates/chio-acp-edge crates/chio-acp-proxy \
  crates/chio-control-plane crates/chio-kernel/src/lib.rs
# crates/chio-mcp-edge/src/runtime.rs:166
```

Public re-export freeze:

- `crates/chio-kernel/src/lib.rs` has 33 public `pub use` groups.
- Public wildcard re-exports are not present (`rg -n "^pub use .*\*" ...`
  returns no matches).
- `ToolEvaluator` remains the public async evaluator extension point.
- `BlockingToolEvaluator` is no longer re-exported from `chio-kernel`; it
  remains crate-internal compatibility glue for the release-N `legacy-sync`
  transition.

Targeted verification before adapted gate:

```bash
cargo test -p chio-cli configure_revocation_store_survives_restart --quiet
cargo test -p chio-cli check_command --quiet
# passed: 1 migrated revocation test, 2 migrated check-command tests
```

Gate adaptation: the full workspace test suite is deferred to the M05 P1
sub-wave gate after T7 per `.planning/trajectory/05-async-kernel-real.md`
Phase 1 finalization. T6 uses the ticket-authorized focused kernel gate plus
workspace clippy/fmt/diff/em-dash checks.

### 2026-04-27 (P2.T4 ChioKernel std mutex retirement)

Scope: M05.P2.T4 owned path `crates/chio-kernel/src/kernel/mod.rs`, plus
the direct private-field append call site in
`crates/chio-kernel/src/kernel/responses.rs`.

Closure:

| Field | Previous type | Replacement |
|-------|---------------|-------------|
| `receipt_log` | `Mutex<ReceiptLog>` | `ArcSwap<ReceiptLog>` with RCU append |
| `child_receipt_log` | `Mutex<ChildReceiptLog>` | `ArcSwap<ChildReceiptLog>` with RCU append |
| `emergency_stop_reason` | `Mutex<Option<String>>` | `ArcSwap<Option<String>>` |
| `federation_peers` | `RwLock<HashMap<String, FederationPeer>>` | `ArcSwap<HashMap<String, FederationPeer>>` |
| `federation_dual_receipts` | `Mutex<HashMap<String, DualSignedReceipt>>` | `DashMap<String, DualSignedReceipt>` |
| `federation_local_kernel_id` | `Mutex<Option<String>>` | `ArcSwap<Option<String>>` |

Result:

- `ChioKernel` no longer has `std::sync::Mutex` fields.
- `ChioKernel` no longer has `std::sync::RwLock` fields.
- The emergency-stop reason and federation local kernel id are lock-free
  `ArcSwap<Option<String>>` cells as required by the Phase 2 trajectory.
- `arc-swap` was already pinned in workspace dependencies by P0.T2; this
  ticket adds the dependency edge to `chio-kernel`.

Reproduction:

```bash
! grep -nE 'std::sync::Mutex' crates/chio-kernel/src/kernel/mod.rs
grep -q 'ArcSwap' crates/chio-kernel/src/kernel/mod.rs
rg -n 'Mutex<|RwLock<' crates/chio-kernel/src/kernel/mod.rs
# no matches
```

## cargo-mutants baseline (M05.P0.T5)

Date: 2026-04-27
Method: `cargo mutants --package chio-kernel`
Baseline kill rate: TBD (CI run pending)
Threshold target for M05 P1: >= 80% (no regression from baseline)

The baseline script lives at `scripts/mutants-baseline-kernel.sh` and is
invoked by `.github/workflows/mutants.yml` for the per-PR mutants-pr lane.
Locally, the script soft-skips with an install hint when `cargo-mutants`
is not on PATH; on CI it produces a JSON report at
`.planning/audits/mutants-baseline-kernel.txt` and prints the kill rate
as a percentage. The audit doc is updated in-place once the first CI run
populates the figure (replace the "TBD" line above with the measured
percentage and the run id).

Subsequent phase re-audits (P1, P2, P3, P4) re-run the script and append
the new kill rate to the snapshot table; the rate must be monotonically
non-decreasing relative to this baseline (>= baseline - epsilon, where
epsilon allows for cargo-mutants per-run nondeterminism on flaky tests).

### 2026-04-27 (P4.T3 release freeze and flamegraph audit)

Scope: M05 exit release check for the kernel/session freeze.

Closure:

- zero `&mut self` methods remain on `Session` in
  `crates/chio-kernel/src/session.rs`.
- zero `std::sync::Mutex` and zero `std::sync::RwLock` fields remain in
  `ChioKernel`; the remaining kernel state uses `ArcSwap`, `DashMap`,
  atomics, and owned handles.
- The frozen CODEOWNERS overrides for `kernel/mod.rs`, `session.rs`, and
  `kernel/session_ops.rs` were removed after M05 P1-P3 completed.
- `m05-kernel-async-pivot` in `.planning/trajectory/freezes.yml` is now
  `state: released`.
- `.planning/audits/M05-flamegraph-dispatch-allow.svg` is attached as
  the dispatch_allow release audit artifact. The current
  `dispatch_allow` bench is still the M05 scaffold from P0.T1, so the
  artifact records the release audit shape of that scaffolded benchmark.

Reproduction:

```bash
grep -c '&mut self' crates/chio-kernel/src/session.rs
! rg -n 'std::sync::Mutex|std::sync::RwLock|Mutex<|RwLock<' \
  crates/chio-kernel/src/kernel/mod.rs
test -f .planning/audits/M05-flamegraph-dispatch-allow.svg
```
