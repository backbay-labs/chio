# Trj5 B0 - Async Kernel Migration (architectural prerequisite)

**Status**: cross-lane prerequisite. This is the SMALLEST decomposition cut
the synthesis sanctioned. It is owned cross-lane because Lane B (protocol
realization) cannot wire new primitives without it; Lane C (forcing demo)
cannot run two kernels in one process without it.

**Concession (explicit)**: this is NOT trust-control extraction; NOT
`chio-core` gravity-well surgery; NOT reqwest 0.12/0.13 unification; NOT
`serde_yaml`/`serde_yml` retirement; NOT the 36 `&mut self` -> builder
conversion in full. Those are deferred to trj6. This document carves out
the minimum that unblocks Lane B.

**Origin**: `.planning/trajectory-5/debate/03-architecture-decomposition.md`
section 1.2 (smoking gun) and section 5 (smallest viable slice) plus the
synthesis at `.planning/trajectory-5/debate/00-SYNTHESIS.md` Lane B
"Architectural prerequisite".

---

## 1. Current State

### 1.1 The dispatch sync-helper hop

`crates/chio-kernel/src/kernel/mod.rs:6402-6442` (verified 2026-05-07):

```rust
pub(crate) async fn dispatch_tool_call_with_cost(
    &self, request: &ToolCallRequest, has_monetary_grant: bool,
) -> Result<(ToolServerOutput, Option<ToolInvocationCost>), KernelError> {
    self.dispatch_tool_call_with_cost_sync(request, has_monetary_grant)
}
```

The async wrapper exists for caller ergonomics. It immediately delegates to
a sync helper because the underlying tool-server connection trait is sync.
The doc comment admits this: "Delegates to the sync helper while the
tool-server trait remains sync-only, preserving the exact dispatch and
cost-accounting semantics."

### 1.2 The trait that forces the hop

`crates/chio-kernel/src/runtime.rs:254` defines `ToolServerConnection`:

```rust
pub trait ToolServerConnection: Send + Sync {
    fn server_id(&self) -> &str;
    fn tool_names(&self) -> Vec<String>;
    fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError>;
    // ... `invoke_with_cost`, `invoke_stream`, etc., all sync.
}
```

Every method is sync. The kernel's `async fn dispatch_tool_call_with_cost`
cannot await any tool-server call because the trait does not return a
`Future`. The async signature is decorative.

### 1.3 Inventory at workspace head

| Metric | Count | Source |
|---|---|---|
| Lines in `chio-kernel/src/kernel/mod.rs` | 6,757 | `wc -l` |
| `&mut self` occurrences in same file | 36 (24 are method definitions; the remaining 12 are call sites or method bodies) | `grep -c '&mut self' kernel/mod.rs` vs `grep -nP 'fn \w+.*\(\s*&mut self' kernel/mod.rs \| wc -l` |
| `async fn` in same file | 6 | `grep -c 'async fn' kernel/mod.rs` |
| `ToolServerConnection` impl SITES in workspace | 47 (across 31 files; several files contain multiple impls) | `grep -rn 'impl ToolServerConnection for\|impl .* ToolServerConnection for' crates/ \| wc -l` |
| `ToolServerConnection` impl FILES in workspace | 31 | `grep -rl 'impl ToolServerConnection for' crates/ \| wc -l` |
| `ToolEvaluator` trait | sync | `crates/chio-kernel/src/kernel/evaluator.rs:26` |

The 36 `&mut self` setters are NOT in scope for this migration; the builder
pattern is a trj6 concern. This document only converts the trait
async-ness.

---

## 2. Target State

### 2.1 `ToolServerConnection` becomes async

Annotate the trait with `#[async_trait::async_trait]`. The `invoke` family
of methods returns `Future` instead of `Result` directly:

```rust
#[async_trait::async_trait]
pub trait ToolServerConnection: Send + Sync {
    fn server_id(&self) -> &str;
    fn tool_names(&self) -> Vec<String>;

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError>;

    async fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let value = self.invoke(tool_name, arguments, nested_flow_bridge).await?;
        Ok((value, None))
    }

    // invoke_stream, drain_async_events: similar.
}
```

The non-async methods (`server_id`, `tool_names`) stay sync; they are pure
accessors.

### 2.2 Dispatch path becomes single-step async

`Kernel::dispatch_tool_call_with_cost` no longer delegates to a sync helper.
It awaits the tool-server `invoke` directly:

```rust
pub(crate) async fn dispatch_tool_call_with_cost(
    &self, request: &ToolCallRequest, has_monetary_grant: bool,
) -> Result<(ToolServerOutput, Option<ToolInvocationCost>), KernelError> {
    // ... the body of the former _sync helper, with `self.tool_server.invoke(...)`
    // calls becoming `.await`.
}
```

The `dispatch_tool_call_with_cost_sync` method is retired (or kept under
`#[cfg(test)]` only, with a `block_on` shim for in-process unit tests).

### 2.3 `async_trait` is the chosen mechanism

`async_trait` 0.1.x is already a workspace dependency (TBD-from-W1: confirm
in `Cargo.toml`). Using it is the lowest-risk path: it desugars to
`Box<Pin<dyn Future>>`, has zero impact on caller signatures except the
`.await`, and is well-understood by Rust review.

The alternative ("native async-fn-in-trait" in stable Rust) is rejected for
release work because the dyn-compatibility story is not yet stable for our MSRV. We
revisit in trj6.

---

## 3. Migration Sequence

The sequence is ordered so each step is a green CI commit; nothing
half-migrates.

### Step 0: prerequisite check (XS, A0.00)

- Confirm `async_trait = "0.1"` is in `[workspace.dependencies]`.
- Confirm `tokio` features in `chio-kernel` `[dependencies]` include
  `rt-multi-thread`, `macros`.
- Land `scripts/check-async-trait-uniform.sh` (Wave 0 deliverable) that
  asserts every implementer of `ToolServerConnection` either uses
  `#[async_trait]` or pre-dates the migration (initially empty allow-list).

### Step 1: trait conversion (S, A0.01)

- Add `#[async_trait]` attribute to the trait definition at
  `crates/chio-kernel/src/runtime.rs:254`.
- Make `invoke`, `invoke_with_cost`, `invoke_stream`,
  `drain_async_events` async.
- `cargo build --workspace` passes; this is allowed to break implementers
  for one PR cycle (they catch up in step 2).

### Step 2: implementer catch-up (M, A0.02 .. A0.0N)

For each `impl ToolServerConnection for <T>` in the workspace, add
`#[async_trait]` and convert method bodies. Implementers are typically:

- `crates/chio-mcp-edge/src/...` (TBD-from-W1: enumerate exactly).
- `crates/chio-acp-edge/src/...`.
- `crates/chio-a2a-edge/src/...`.
- `crates/chio-tower/src/...`.
- The `chio-cpp-kernel-ffi` shim (this one MAY require a `block_on` adapter
  for the C++ side; flagged as risk R1 in `RISK-REGISTER.md`).
- Any in-tree test/example implementers.

Each implementer is its own ticket so the catch-up is parallelizable.

### Step 3: dispatch hot-path collapse (M, A0.10)

- Remove `dispatch_tool_call_with_cost_sync` (or move to `#[cfg(test)]`).
- Inline the body into `dispatch_tool_call_with_cost`, with `.await` on
  every tool-server call.
- Re-run all conformance tests to confirm semantics are preserved.

### Step 4: CI gates (S, A0.11)

- Promote `scripts/check-async-trait-uniform.sh` from advisory to required
  in `.github/workflows/ci.yml`.
- Add a regression test that asserts `dispatch_tool_call_with_cost` does
  NOT contain a sync delegation (grep-based, brittle but cheap).

### Step 5: Lane B unblock (no ticket; gating-only)

- release work-B1, B2, B3 may now proceed; their wiring no longer has to thread
  through the sync helper.

---

## 4. Risk: Mobile and Browser Impact

### 4.1 `chio-kernel-mobile`

`crates/chio-kernel-mobile/` is a thin FFI layer over the in-process
kernel. It currently exposes synchronous bindings via `block_on` from the
mobile side. The migration impacts it as follows:

- The mobile-side FFI continues to expose a sync surface; the migration
  moves the `block_on` boundary inward (one layer closer to the kernel).
- No spec change; no protocol change.
- Risk: the existing Apple App Attest / Play Integrity verifier paths use
  blocking syscalls in `cbor` parsing and JWS verification; these stay
  sync and are not affected by the trait change.

### 4.2 `chio-kernel-browser`

`crates/chio-kernel-browser/` is the wasm-bindgen target. JS-side callers
are inherently async (Promise-based). The migration is favorable here: the
wasm boundary stops needing a sync-to-async adapter for the dispatch path.

- Tokio is not available in wasm. The wasm build uses `wasm-bindgen-futures`
  to drive Rust async to JS Promises; `async_trait` is wasm-compatible.
- Risk: `async_trait`'s `Box<Pin<dyn Future>>` allocates per invocation;
  wasm bundle size impact (TBD-from-W1: measure with `twiggy`).

### 4.3 `chio-cpp-kernel-ffi`

C++ side is sync. The shim must adapt. Two options:

- **Option A**: keep a sync-facing FFI that internally `block_on`s a
  per-call tokio runtime. Simple; per-call runtime overhead.
- **Option B**: expose an async-callback FFI that takes a continuation. More
  invasive on the C++ side.

For release work, Option A is the default. Option B is trj6.

---

## 5. Diff Size Estimate

Rough estimate (will be tightened in Wave 1 after the implementer
enumeration):

| Component | Files | LOC | Confidence |
|---|---|---|---|
| Trait definition (`runtime.rs`) | 1 | ~30 | high |
| Dispatch hot path (`kernel/mod.rs`) | 1 | ~200 (rewrite of the sync helper) | medium |
| Edge implementers (mcp/acp/a2a/tower) | 4-6 | ~150 each, ~600-900 total | medium |
| FFI shim (`cpp-kernel-ffi`) | 2-4 | ~200 | low |
| Tests adjusted (`#[tokio::test]` instead of `#[test]`) | 20-40 | small per-test, ~400 total | medium |
| New CI script + workflow integration | 2 | ~80 | high |
| **Total** | **~30-55 files (47 impl sites in 31 files)** | **~1,500-2,000 LOC net diff** | medium |

Note: per R3 BLOCKER on impl count, the 31 number is FILES with at least one impl. The actual impl-site count is 47 because several files contain multiple impls (notably `chio-kernel/src/kernel/tests/all.rs` with 8 impls and `chio-mcp-edge/src/runtime/runtime_tests.rs` with 5). The release work-B0.3 and B0.4 ticket descriptions (in `lane-b-wiring/planning docs`) count files; the impl-site count is the more accurate diff-sizing measure. Concretely: `chio-kernel/src/kernel/tests/all.rs` (8 impls), `chio-mcp-edge/src/runtime/runtime_tests.rs` (5), `chio-acp-edge/src/lib.rs` (2), `chio-a2a-edge/src/lib.rs` (3), `chio-openai/src/lib.rs` (2), `chio-openapi-mcp-bridge/src/lib.rs` (2). The `chio-mcp-remote/src/remote_mcp/session_core.rs` impl was previously cited at lines 2682 and 2860; the current head shows only 1838 (line numbers shift; resolved by audit at B0.1 PR-time).

This is meaningfully smaller than the trust-control extraction (~18K LOC)
or the gravity-well surgery on `chio-core` (~80K LOC). Trj5 sticks to this
slice. If Wave 1 measurement shows >3,000 LOC, see Risk R1 in
`RISK-REGISTER.md`.

---

## 6. Rollback Plan

If Wave 1 measurement shows the migration is more invasive than 3,000 LOC,
or if the FFI shim work in `chio-cpp-kernel-ffi` proves to need Option B,
rollback proceeds as follows:

### 6.1 Trigger criteria (any one)

- Step 2 implementer catch-up exceeds 1,500 LOC across more than 8 crates.
- C++ FFI Option A measured per-call overhead exceeds 5% of dispatch_allow
  bench baseline.
- A non-trivial wasm bundle-size regression (>5% on `chio-kernel-browser`)
  appears in `.github/workflows/browser-kernel-twiggy.yml`.
- Any implementer requires architectural changes that violate the "smallest
  cut" concession (e.g. a setter-to-builder conversion in
  `crates/chio-kernel/src/kernel/mod.rs`).

### 6.2 Rollback procedure

- Revert the trait change (`runtime.rs`).
- Revert the dispatch-collapse change.
- Restore `dispatch_tool_call_with_cost_sync` as the production path.
- Lane B receipts the rollback in its plan: B1, B2, B3 wiring proceeds
  through the sync path with explicit ticket notes that the async migration
  is deferred to trj6.
- Update `.planning/trajectory-5/architecture/RISK-REGISTER.md` R1 to
  reflect that the migration was attempted and rolled back.

### 6.3 What does NOT roll back

- The CI scripts (`check-async-trait-uniform.sh`,
  `check-conformance-imports.sh`) stay; they are independently useful.
- The Lane B/C work proceeds without B0; the conformance fixtures still
  exercise the production call path, just through the sync helper.

---

## 7. Out-of-Scope (explicit, do not let this expand)

- `&mut self` setter -> builder conversion. **Out**: trj6.
- `chio-cli/src/trust_control/` extraction (~18K LOC). **Out**: trj6.
- `kernel/mod.rs` 6,757-LOC split into `assembly.rs`, `dispatch.rs`,
  `responses.rs`, `state.rs`, `negotiation.rs`. **Out**: trj6. The
  Decomposition Advocate's case for this is correct, but the synthesis
  sanctioned only the async-trait cut.
- `reqwest 0.12 / 0.13` unification. **Out**: trj6.
- `serde_yaml` / `serde_yml` deduplication. **Out**: trj6.
- `too_many_arguments` burndown beyond what the async migration touches.
  **Out**: trj6.

If Wave 1 review wants to expand any of these into release work, that is a
synthesis-level change requiring the synthesis doc to be re-opened. Do not
expand silently.

---

## 8. References

- Smoking gun: `.planning/trajectory-5/debate/03-architecture-decomposition.md`
  section 1.2.
- Synthesis sanction: `.planning/trajectory-5/debate/00-SYNTHESIS.md`
  Lane B "Architectural prerequisite".
- Trait location: `crates/chio-kernel/src/runtime.rs:254`.
- Dispatch hop: `crates/chio-kernel/src/kernel/mod.rs:6402-6442`.
- Risk: `.planning/trajectory-5/architecture/RISK-REGISTER.md` R1.
