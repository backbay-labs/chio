# Trajectory 5 - Lane B: Wire the Spec Hot Path

**Status**: planned. **Owner-class**: Protocol-realization eng + kernel eng + federation eng. **Window**: ~7 weeks, parallelizable with Lane A. **Lane B internal dependency**: B0 async-trait migration gates B1, B2, B3, B4 (B0 has no upstream dependency). **B4 added Wave 3 per R4 BLOCKER 1** (DSSE-conformant bilateral signing was promoted from Lane C "Option A two-signature" to Lane B fourth primitive).

## What this lane is

Lane B closes the spec-vs-runtime gap. The trj4 closeout erratum diagnosed the failure mode: "structural framing landed (types, schemas, registry entries, doc generators) but runtime wiring did not (kernel/verifier hot paths, separate-file negative conformance tests, real proof artifacts behind theorem-inventory rows)." Lane B finishes the wiring for three normative MUSTs that are still partial on the kernel hot path, plus the smallest architectural cut that unblocks them.

The release work synthesis is explicit (`.planning/trajectory-5/debate/00-SYNTHESIS.md` lines 90-113):

> "Architectural prerequisite: convert `ToolServer` trait to `async_trait`, collapse the dispatch sync-helper hop in `chio-kernel/src/kernel/mod.rs:6402`. This is the smallest decomposition cut that unblocks hot-path wiring; everything else (chio-cli trust-control extraction, gravity-well surgery) stays out of release work."

(Synthesis-quote correction: the trait's actual name in the codebase is `ToolServerConnection`, defined at `crates/chio-kernel/src/runtime.rs:254-306`. The dispatch hop spans `mod.rs:6402-6442`. The synthesis text is left verbatim above; the corrected references propagate through PLAN.md, planning docs, and `async-trait-migration.md`.)
>
> "Each primitive closes with: enforced call site + spec MUST citation + signed negative conformance test that fails when wiring is removed. No Evidence Gate row closes without all three."

## Trj5 ship-bar items Lane B owns

Lane B is wholly responsible for ship-bar item 2 (synthesis lines 152-155, expanded to FOUR primitives per R4 BLOCKER 1):

> "The four Lane B primitives (capability v2, receipt v2, anchor-batch async, DSSE-conformant bilateral signing) are each protected by a signed negative conformance fixture in `crates/chio-conformance/tests/` that exercises the production call site and fails when the enforcement is removed."

## Sub-lane summary

| Sub-lane | Title | Source synthesis lines | Effort | Depends on |
|---|---|---|---|---|
| B0 | Async-trait migration: `ToolServerConnection` + dispatch hop | 95-99 | L | - |
| B1 | Single-entry verifier: `verify_capability_full` is the only production path | 100-103 | M | B0 |
| B2 | Receipt v2 fail-closed under negotiated v2 | 104-106 | M | B0 |
| B3 | Anchor-batch async-only when `require_public_witness=true` | 107-110 | M | B0 |
| B4 | **DSSE-conformant bilateral signing** (NEW per R4 BLOCKER 1) | promoted from Lane C "Option A two-signature" framing | L | B0 (hard), B1 (soft) |

Detailed per-sub-lane scope, acceptance, and evidence in [`PLAN.md`](./PLAN.md). Concrete tickets in [planning docs](./planning docs). Sub-lane deep dives in [`async-trait-migration.md`](./async-trait-migration.md), [`single-entry-verifier.md`](./single-entry-verifier.md), [`receipt-v2-failclosed.md`](./receipt-v2-failclosed.md), [`anchor-batch-async-only.md`](./anchor-batch-async-only.md), [`dsse-bilateral-signing.md`](./dsse-bilateral-signing.md). The pattern every Lane B ticket follows is in [`conformance-fixture-spec.md`](./conformance-fixture-spec.md).

## Why B0 is the architectural prerequisite

`crates/chio-kernel/src/kernel/mod.rs:6402-6408`:

```rust
pub(crate) async fn dispatch_tool_call_with_cost(
    &self, request: &ToolCallRequest, has_monetary_grant: bool,
) -> Result<(ToolServerOutput, Option<ToolInvocationCost>), KernelError> {
    self.dispatch_tool_call_with_cost_sync(request, has_monetary_grant)
}
```

The async wrapper exists for caller ergonomics, then immediately delegates to `dispatch_tool_call_with_cost_sync` because the `ToolServerConnection` trait at `crates/chio-kernel/src/runtime.rs:254-306` is sync-only. Until that trait migrates to `async_trait`, every Lane B wiring change is forced to take `&Kernel` through a sync helper, conflicting with the `Arc<Kernel>` shape the public-witness lane in B3 needs (the `AnchorWitnessClient::verify_inclusion` path is `async`). B0 is the smallest decomposition that unblocks B1-B3; anything broader (chio-cli trust-control, gravity-well surgery) stays out of release work per synthesis lines 136-138.

## Week-by-week timeline (7 weeks; B4 added per R4 BLOCKER 1)

| Week | Sub-lane(s) | Milestone |
|---|---|---|
| 1 | B0 | `ToolServerConnection` trait at `crates/chio-kernel/src/runtime.rs:254-306` switched to `async_trait`. 47 impl SITES (across 31 files) compile. CI green. |
| 2 | B0 | `dispatch_tool_call_with_cost_sync` collapsed; `dispatch_tool_call_with_cost` is the only entry. `&mut self` setter audit on `ChioKernel` published (24 method definitions, 36 occurrences; no removals required this lane; documentation only). |
| 3 | B1 | `verify_capability_signature` and `verify_capability_full_without_budget_admit` removed. All hosted callers route through `verify_capability_full`. Spec PROTOCOL.md line 408 SHOULD -> MUST. |
| 4 | B1 + B2 | B1 negative conformance fixture and lint script land. B2 fail-closed downgrade replaces warn-and-continue at `mod.rs:1574-1591`. Spec PROTOCOL.md lines 737-741 introduce a NEW normative MUST (tightening, not promotion). |
| 5 | B2 + B3 + B4 | B2 conformance fixture lands. B3 sync-path gating + `scripts/check-anchor-batch-async-witness.sh` (best-effort) + spec PROTOCOL.md §6.4.1 normative promotion. **B4 starts**: `crates/chio-federation/src/bilateral_dsse.rs` module skeleton; PAE encoding implementation. |
| 6 | B3 + B4 | B3 conformance fixture lands. **B4 lands**: DSSE envelope sign/verify path; spec citation `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §6 lines 338-353; B4 negative conformance fixture asserts §6 conformance is the DSSE envelope only. |
| 7 | B1.E + B2.E + B3.E + B4.E | Per-primitive Evidence Gate close: each of B1, B2, B3, B4 has enforced call site + spec MUST citation + signed negative conformance test that fails when wiring is removed. |

## Out of scope for Lane B

Per synthesis lines 134-144:

- `chio-cli` trust-control extraction (~18K LOC). Defer to trj6.
- Gravity-well surgery on `chio-core` / `chio-kernel` mod.rs (6,757 LOC).
- The remaining `&mut self` setter -> builder-finalize migration on `ChioKernel`. B0 only collapses the async-wrapper lie. Setter migration is a trj6 ask.
- Hybrid PQ wiring (R4 in `02-protocol-realization-engineer.md`). Synthesis explicitly chose only three primitives; PQ is not in the release work ship bar.
- Metered-billing post-execution gate (R5 in `02-...`). Same reason.
- Reqwest 0.12/0.13 unification (synthesis line 140).

## Assumptions

1. **`chio-kernel-mobile` is unaffected**. The crate at `crates/chio-kernel-mobile/Cargo.toml:30` depends on `chio-kernel-core`, NOT `chio-kernel`. The async-trait migration touches `crates/chio-kernel/src/runtime.rs::ToolServerConnection`, which `chio-kernel-mobile` does not import (verified by `grep -r "ToolServerConnection" crates/chio-kernel-mobile/`). Mobile builds remain on `chio-kernel-core`'s pure-compute entry points.
2. **`async-trait` crate is acceptable**. The workspace already depends on it transitively (the `chio-anchor` async path uses an `async fn` in trait via direct `async fn` in trait support on stable Rust 1.75+). The B0 ticket pins to native `async fn in trait` to avoid the `async-trait` macro dependency where the trait is not object-safe-required; falls back to `#[async_trait]` for trait-object call sites (the `Box<dyn ToolServerConnection>` registrations at e.g. `crates/chio-mcp-remote/src/remote_mcp/session_core.rs:2682`).
3. **Trj4 wave plan independence**. The trj4 wave plan continues in parallel; Lane B does not block on it. The W1.5 hot-path wire (commit `05fd0c56e`) and W2.3 anchor-witness wire (commit `7ee1ddbcc`) are the prerequisite landings; both already merged before release work kickoff.

## Evidence Gate close bar (every Lane B ticket)

Per synthesis line 111-113: "Each primitive closes with: enforced call site + spec MUST citation + signed negative conformance test that fails when wiring is removed."

Operationally, every Lane B ticket's PR description must link:

1. **Enforced call site**: file + line range where the wiring lives (e.g. `crates/chio-kernel/src/kernel/mod.rs:2898-2911`).
2. **Spec MUST citation**: PROTOCOL.md (or WIRE_PROTOCOL.md / GUARDS.md) section + line range, quoted verbatim.
3. **Signed negative conformance test**: a separate file under `crates/chio-conformance/tests/<name>.rs` that exercises the production code path (NOT a mock, not a near-copy) and FAILS when the wiring is removed. The pattern is in [`conformance-fixture-spec.md`](./conformance-fixture-spec.md).

A ticket with two of three is not closeable. The trj4 closeout erratum's failure mode (synthesis lines 9-13) is precisely a ticket that closed with structural framing but no negative test exercising the production hot path.
