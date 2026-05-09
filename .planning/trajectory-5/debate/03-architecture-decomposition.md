# Trajectory 5 Position Paper: Decomposition First

**Author:** Architecture & Decomposition Advocate
**Date:** 2026-05-07
**Recommendation:** Trj5 must be the decomposition trajectory. Every alternative trajectory will inherit the same failure mode that reopened trj4: structural framing without runtime wiring, because the architecture is too tangled to wire correctly.

---

## 1. Hard Inventory of the Debt

### 1.1 Gravity wells (file / LOC)

Top non-test source files in the workspace right now:

- `crates/chio-core-types/src/_generated/chio_wire_v1.rs` -- **37,258 LOC** (auto-generated wire types from JSON schemas; not refactor-by-splitting, but it does dominate compile time and triggers the dual `wasmparser`/`wasm-encoder` situation downstream).
- `crates/chio-kernel/src/kernel/mod.rs` -- **6,757 LOC** (the kernel god-module; 95 `pub fn`, 36 `&mut self` setters, only 6 `async fn`).
- `crates/chio-core-types/src/capability.rs` -- **5,497 LOC**.
- `crates/chio-cli/src/trust_control/cluster_and_reports.rs` -- **5,185 LOC**.
- `crates/chio-cli/src/trust_control/service_runtime.rs` -- **5,131 LOC** (149 `pub fn`).
- `crates/chio-cli/src/trust_control/capital_and_liability.rs` -- **2,954 LOC**.
- `crates/chio-cli/src/cli/types.rs` -- **3,593 LOC**; `cli/dispatch.rs` -- **2,660 LOC**; `cli/trust_commands.rs` -- **2,826 LOC**.

`chio-cli/src/` totals **72,010 LOC**. The "five files >6K lines" framing in the v2.80-v2.83 review remains directionally accurate; the gravity has migrated from `chio-core` proper into `chio-core-types` (capability.rs, receipt.rs, session.rs) and into `chio-cli/src/trust_control/` and `chio-cli/src/cli/`.

### 1.2 Kernel concurrency blocking points (smoking gun)

`crates/chio-kernel/src/kernel/mod.rs:6402-6442`:

```rust
pub(crate) async fn dispatch_tool_call_with_cost(
    &self, request: &ToolCallRequest, has_monetary_grant: bool,
) -> Result<(ToolServerOutput, Option<ToolInvocationCost>), KernelError> {
    self.dispatch_tool_call_with_cost_sync(request, has_monetary_grant)
}
```

The async wrapper exists for caller ergonomics, then immediately delegates to a sync helper because the `ToolServer` trait is sync-only. The doc comment admits it: "Delegates to the sync helper while the tool-server trait remains sync-only, preserving the exact dispatch and cost-accounting semantics." This is the dual API model that the v2.80-v2.83 review flagged. It is still here.

The kernel additionally exposes 36 `&mut self` mutators (setters for stores, hooks, oracles, federation, capabilities). Every adapter that wires a new dependency in must take a `&mut Kernel` exclusive borrow; concurrent assembly is impossible.

### 1.3 Dependency duplication (Cargo.lock)

- **`reqwest`**: both `0.12.28` and `0.13.2` resolved. The workspace pin is `0.13.2` (Cargo.toml:238) but a transitive path still drags `0.12.28`.
- **`serde_yaml 0.9.34+deprecated`** AND **`serde_yml 0.0.12`** both resolved. The workspace declares both (Cargo.toml:211-212) and crates pick whichever they see first.
- **`wasmparser`** resolved 5 times, **`wasm-encoder`** 4 times, **`hashbrown`** 5 times, **`windows-sys`** 6 times, **`schemars`** 3 times, **`toml`** 3 times, **`rand`** 3 times.
- **128 distinct crate names** appear in Cargo.lock with more than one resolved version.

### 1.4 Crates with zero `tests/` directory (20)

`chio-a2a-edge`, `chio-acp-edge`, `chio-acp-proxy`, `chio-ag-ui-proxy`, `chio-api-protect`, `chio-bindings-ffi`, `chio-config`, `chio-cpp-kernel-ffi`, `chio-cross-protocol`, `chio-egress-contract`, `chio-guard-sdk`, `chio-guard-sdk-macros`, `chio-http-session`, `chio-log-redact`, `chio-mcp-remote`, `chio-metrics-spec`, `chio-openapi`, `chio-openapi-mcp-bridge`, `chio-provider-adapter-core`, `chio-workflow`.

That's 20 of 94 crates -- **21% of the workspace** -- with no integration coverage. The v2.80-v2.83 review counted 12; the number has grown, not shrunk. Among them are surfaces trj4 was supposed to harden: `chio-cross-protocol` (the v3.13 shared runtime home), `chio-mcp-remote` (3,399 LOC, 1 file >3K LOC, no integration tests), `chio-egress-contract` (the W2.2 wire surface that trj4 just landed in PR #597), and `chio-acp-edge`/`chio-a2a-edge` (3,224 + 3,295 LOC).

### 1.5 `too_many_arguments` offenders

46 occurrences total across the workspace (down from the review's 82, but still significant). Top offender files:

1. `crates/chio-kernel/src/budget_store.rs` -- 9
2. `crates/chio-store-sqlite/src/receipt_store/support.rs` -- 5
3. `crates/chio-store-sqlite/src/receipt_store/tests.rs` -- 3
4. `crates/chio-store-sqlite/src/budget_store.rs` -- 3
5. `crates/chio-kernel/src/receipt_store.rs` -- 2
6. `crates/chio-kernel/src/kernel/responses.rs` -- 2
7. `crates/chio-cross-protocol/src/lib.rs` -- 2
8. `crates/chio-cli/tests/receipt_query.rs` -- 2
9. `crates/chio-tee-frame/src/frame.rs`, `chio-settle/src/hook.rs`, `chio-mercury-core/src/proof_package.rs`, `chio-kernel/src/kernel/mod.rs`, `chio-kernel/src/checkpoint.rs`, `chio-http-core/src/authority.rs` -- 1 each (top 10).

The cluster is the kernel/store seam: every persistence call grew positional parameters until clippy gave up. Each suppression is a place a future caller has to copy-paste an 8-arg invocation correctly.

---

## 2. Why This Matters For Trj5 Specifically

The trj4 closeout erratum (`.planning/trajectory-4/TRAJECTORY-4-CLOSEOUT-ERRATUM.md`, 2026-05-05) is the definitive evidence:

> "structural framing landed (types, schemas, registry entries, doc generators) but runtime wiring did not (kernel/verifier hot paths, separate-file negative conformance tests, real proof artifacts behind theorem-inventory rows). Approximately 30 P0/P1 issues were filed against artifacts that the prior closeout summary lists under 'Closed' or 'Validation'."

That is not a process failure. That is an architecture failure. Trj4 PR #597 ("wire HttpEgressContract into 16 production callers") landed only after a parallel `chio-egress-contract` crate was carved out -- but the crate has zero tests directory, and the wiring touched 16 callers because the abstraction crossed 16 different `&mut self` setters and dual-version `reqwest` dependencies. That is the structural cost the kernel signature imposes on every new hot-path wiring task.

Every trj4 wave that "stalled at structural framing" did so for the same reason: to wire a new responsibility into the kernel hot path you have to (a) take `&mut Kernel`, which conflicts with the async-spawn world that downstream callers assume, (b) thread the dependency through a tool-server trait that is sync-only so the async wrapper is a lie, and (c) extend a function that is already on the `too_many_arguments` exemption list. The path of least resistance is "land the type, defer the wire" -- and that is exactly the trj4 closeout failure pattern.

If release work takes any focus other than decomposition, it inherits the same surface. The W2.x continuation effort, the AnchorWitnessClient integration, the chain-binding/negotiation/sibling-sum work -- they will each accrete one more `&mut self` setter, one more positional arg, one more crate without integration tests. Trj4 was nominally "closed" with 95% of its 126 brainstorm ideas not actually wired. That is the steady-state failure mode unless we change the substrate.

---

## 3. The Decomposition Lane (proposed release work structure)

**Wave 0 -- Inventory and pin (1 phase).** Freeze the close-bar: every "decomposed" surface ships with (a) integration tests or it does not count, (b) zero new `too_many_arguments` exemptions, (c) zero new dual-version dependencies in Cargo.lock.

**Wave 1 -- Kernel concurrency model (3 phases).**
1.1 Convert `ToolServer` trait to `async_trait` + `Arc<Self>`. Eliminate the `dispatch_tool_call_with_cost` lie at line 6402.
1.2 Replace the 36 `&mut self` setters on `Kernel` with a builder-finalize pattern (`KernelBuilder` accumulates, `KernelBuilder::build()` returns `Arc<Kernel>`).
1.3 Extract `kernel/mod.rs` (6,757 LOC) into modules along the natural boundaries already visible in the file: `assembly.rs`, `dispatch.rs`, `responses.rs`, `state.rs`, `negotiation.rs`. Target: no module >1,500 LOC.

**Wave 2 -- Trust-control surface decomposition (2 phases).** `chio-cli/src/trust_control/` is 18K LOC across 5 files >2.5K. Split into `chio-trust-control` crate (or split files at the natural HTTP-handler / cluster-replication / capital-liability seams). Outcome: `chio-cli` becomes a thin command-dispatch shell.

**Wave 3 -- Dependency unification (1 phase).** Eliminate the `reqwest 0.12 / 0.13` split (find the transitive holdout, force a workspace patch). Replace `serde_yaml 0.9.34+deprecated` with `serde_yml` everywhere or vice versa -- one wins. Cargo.lock duplicate count target: <40 (from 128).

**Wave 4 -- Integration test floor (2 phases).** All 20 zero-tests crates get at least one integration test exercising one real failure path. Priority: `chio-cross-protocol`, `chio-mcp-remote`, `chio-egress-contract`, `chio-a2a-edge`, `chio-acp-edge`. CI gate: zero is no longer acceptable for any crate.

**baseline -- `too_many_arguments` burn-down (1 phase).** The kernel/store seam (top 8 files) gets parameter-object structs. Suppression count target: <10 from 46.

---

## 4. Counterargument rebuttals

**(a) "This is just refactoring, no new value."** False. The concurrency model fix unlocks user-facing demos that are currently impossible: a single Chio kernel handling concurrent A2A and MCP sessions in one process (today blocked by `&mut self`). The duplicate-deps cleanup cuts cold-build time measurably (rough estimate: 90s+ on the secondary `reqwest 0.12` tree). The integration-test floor is what makes the next trajectory's "wire X into the hot path" actually verifiable instead of "structural framing only."

**(b) "Trj4 closeout first."** Trj4 closeout IS decomposition for the surfaces it touches. The wave plan at `local trajectory-4 closeout plan` is already closing-by-decomposing for 16 hot-path call sites. Trj5-as-decomposition formalizes the substrate so the *next* trj4-shaped effort doesn't repeat the failure. Decomposition first is also a *prevention* lane: every wave-NN-summary doc that lands in trj4 closeout will land faster against a kernel that doesn't require `&mut self` plumbing.

**(c) "Boring, do shippable user features."** Name three. (i) Concurrent multi-session hosted runtime is blocked by sync `&mut self`. (ii) Comptroller-capable second-customer demo needs `chio-trust-control` to be a library, not a 18K-LOC CLI annex. (iii) The bounded Chio operational profile (the v3.18 ship boundary) requires the integration-test floor to be enforceable as a CI gate; right now 21% of crates are exempt by absence.

---

## 5. Smallest viable decomposition slice (if release work is mostly trj4 closeout)

If the consensus is that trj4 closeout consumes most of release work, accept it -- but carve out exactly one decomposition phase that cannot wait:

**Minimum slice: Wave 1.1 + Wave 4 priority crates.** Convert `ToolServer` to async-trait, and add a *single* integration test to each of `chio-cross-protocol`, `chio-mcp-remote`, `chio-egress-contract`. That removes the async-wrapper-lie at the kernel hot path AND establishes that the 2026-04-13 zero-tests count cannot increase. Everything else can defer to trj6.

Without even this slice, release work will conclude with a longer Cargo.lock, more `&mut self` setters, more zero-test crates, and another erratum.

---

**Bottom line:** the v2.80-v2.83 five-agent review identified the debt 13 months ago. Some numbers improved (82 -> 46 `too_many_arguments`). Some got worse (12 -> 20 zero-test crates). The kernel concurrency model is unchanged. Trj4 reopened because the substrate it built on is too tangled for the wiring it promised. Trj5 either fixes that substrate or it ships a fourth instance of the same failure pattern.
