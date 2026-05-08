# B0: Async-trait Migration

This document is the deep dive for sub-lane B0. PLAN.md "Sub-lane B0" gives the scope; this document fills in the migration order, blast radius, breaking-change handling, and CI strategy.

## What B0 actually changes

Two changes, both in `chio-kernel`:

1. The `ToolServerConnection` trait at `crates/chio-kernel/src/runtime.rs:254-306` becomes async. Specifically:
   - `fn invoke(...) -> Result<serde_json::Value, KernelError>` becomes `async fn invoke(...) -> Result<serde_json::Value, KernelError>`.
   - `fn invoke_with_cost(...) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError>` becomes `async fn invoke_with_cost(...)` with the same signature.
   - `fn invoke_stream(...) -> Result<Option<ToolServerStreamResult>, KernelError>` becomes `async fn invoke_stream(...)`.
   - `fn drain_events(...) -> Result<Vec<ToolServerEvent>, KernelError>` becomes `async fn drain_events(...)`.
2. The async-wrapper hop at `crates/chio-kernel/src/kernel/mod.rs:6402-6408` is collapsed:
   - `pub(crate) async fn dispatch_tool_call_with_cost(&self, ...)` was forwarding to `dispatch_tool_call_with_cost_sync` at `crates/chio-kernel/src/kernel/mod.rs:6415-6442`.
   - After B0, `dispatch_tool_call_with_cost` is itself the dispatch logic. `dispatch_tool_call_with_cost_sync` is removed.

The `nested_flow_bridge: Option<&mut dyn NestedFlowBridge>` parameter on the trait methods stays. The `NestedFlowBridge` trait at `crates/chio-kernel/src/runtime.rs:156` and `NestedFlowClient` at `crates/chio-kernel/src/runtime.rs:186` are not changed by this lane.

## Implementation choice: native `async fn` in trait vs `#[async_trait]`

Rust 1.75+ supports native `async fn` in trait. The catch is that traits with native `async fn` are not `dyn`-compatible by default; methods with implicit `Send` / `'static` bounds may need `Box<dyn Future ...>` workarounds.

The kernel registers tool servers as `Box<dyn ToolServerConnection>` (see `crates/chio-mcp-remote/src/remote_mcp/session_core.rs:2682` and `:2860`, `crates/chio-acp-proxy/src/kernel_checker.rs:138`, `crates/chio-conformance/verdict_matrix/src/driver.rs:345`, etc). This means `ToolServerConnection` MUST remain `dyn`-compatible.

**Decision**: use the `async-trait` crate (`#[async_trait]`) for `ToolServerConnection`. The performance overhead (one `Box<dyn Future>` allocation per dispatch) is acceptable on the hot path; the alternative requires reshaping every registrar to `Arc<dyn ToolServerConnection + Send + Sync>` with `trait_variant`, which is a larger blast radius than B0 wants.

The `async-trait` crate is already an indirect dependency in the workspace through other crates (verifiable in `Cargo.lock`); B0 promotes it to a direct dependency in `crates/chio-kernel/Cargo.toml`.

## Production-path implementor inventory (must convert in B0.3)

Verified by `grep -rl "impl ToolServerConnection for" crates/`. Production (non-test) implementations:

1. `crates/chio-mcp-adapter/src/native.rs` - native MCP server adapter.
2. `crates/chio-mcp-adapter/src/lib.rs` - the adapter root (re-exports).
3. `crates/chio-mcp-remote/src/remote_mcp/session_core.rs` - the SharedUpstreamToolServer at line 2682 + 2860.
4. `crates/chio-acp-edge/src/lib.rs` - ACP edge adapter.
5. `crates/chio-a2a-edge/src/lib.rs` - A2A edge adapter.
6. `crates/chio-acp-proxy/src/kernel_checker.rs` - ACP authority tool server (line 138).
7. `crates/chio-openapi-mcp-bridge/src/lib.rs` - OpenAPI -> MCP bridge (lines 734, 752 register impls).
8. `crates/chio-cross-protocol/src/lib.rs` - cross-protocol shim.
9. `crates/chio-tower/src/kernel_service.rs` - Tower service wrapper.
10. `crates/chio-http-core/src/authority.rs` - HTTP authority.
11. `crates/chio-a2a-adapter/src/invoke.rs` - A2A invocation impl.
12. `crates/chio-openai/src/lib.rs` - OpenAI adapter.

All twelve must convert in B0.3 (single PR or coordinated stack).

## Test-path implementor inventory (B0.4)

Verified by the same `grep`. Test-only implementations:

1. `crates/chio-http-core/tests/emergency_endpoints.rs`
2. `crates/chio-http-core/tests/evaluate_plan_endpoint.rs`
3. `crates/chio-http-core/tests/execution_nonce.rs`
4. `crates/chio-mcp-adapter/tests/integration_smoke.rs`
5. `crates/chio-arena/tests/single_agent_runtime.rs`
6. `crates/chio-arena/tests/determinism_gate.rs`
7. `crates/chio-arena/tests/multi_kernel_routing.rs`
8. `crates/chio-arena/tests/multi_agent_reference.rs`
9. `crates/chio-arena/tests/walking_skeleton.rs`
10. `crates/chio-mcp-edge/tests/integration_smoke.rs`
11. `crates/chio-mcp-edge/src/runtime/runtime_tests.rs`
12. `crates/chio-conformance/tests/wave1_hot_path_enforcement.rs`
13. `crates/chio-conformance/tests/v2_receipt_kernel_round_trip.rs` (the `EchoToolServer` at lines 58-77)
14. `crates/chio-conformance/verdict_matrix/src/driver.rs`
15. `crates/chio-kernel/tests/provenance_otel.rs`
16. `crates/chio-kernel/benches/dispatch_request_fixture.rs`
17. `crates/chio-kernel/src/kernel/tests/all.rs`
18. `crates/chio-kernel/src/kernel/tests/formal_closure.rs`

(There are 31 total impl sites by file, but several files contain more than one impl. The 12 production + 18 test list above totals to 30 distinct files; the 31st is a doc-test in `runtime.rs` itself, which becomes part of the trait change in B0.2.)

## Blast-radius numbers

**R3 BLOCKER #3 fix**: prior numbers undercount impl SITES. The 31 number counts FILES with at least one impl. The actual impl-site count is **47** (verified via `grep -rn "impl ToolServerConnection for\|impl .* ToolServerConnection for" crates/`). Several files contain multiple impls:

- `crates/chio-kernel/src/kernel/tests/all.rs` (lines 1298, 1318, 1409, 1430, 5266, 5299, 5328, 9664) - 8 impls.
- `crates/chio-mcp-edge/src/runtime/runtime_tests.rs` (lines 41, 73, 128, 155, 183) - 5 impls.
- `crates/chio-acp-edge/src/lib.rs` (1541, 1562) - 2 impls.
- `crates/chio-a2a-edge/src/lib.rs` (1634, 1655, 1676) - 3 impls.
- `crates/chio-openai/src/lib.rs` (561, 582) - 2 impls.
- `crates/chio-openapi-mcp-bridge/src/lib.rs` (329, 423) - 2 impls.
- `crates/chio-mcp-remote/src/remote_mcp/session_core.rs` - earlier doc cited lines 2682 + 2860; current head shows 1838 only. The line-number shift is resolved by the audit at B0.1 PR time.

For the synthesis-quoted "diff size" requirement:

- Lines in trait definition body changing from sync to async: ~50 (the four method bodies + the doc-comments referencing sync semantics).
- Lines in the dispatch sync-helper body being deleted: 28 (`crates/chio-kernel/src/kernel/mod.rs:6415-6442`).
- Lines in the async wrapper being expanded with the inlined body: ~28 added back (the body moves up, not deletes).
- Net production-implementor changes: each of the 12 production impl FILES contains an impl SITE (12 sites; mechanical `async fn` insertion + `.await` on inner async calls if any). Total ~150 lines touched.
- Net test-implementor changes: ~35 test impl sites (file count is 18; the impl-site count is higher due to the test-suite files with multiple impls listed above). Total ~250-350 lines (mostly mechanical).
- **Total Lane B0 PR diff estimate**: ~500-600 lines added/removed across ~31 files (47 impl SITES). Per-impl-site sequencing in the catch-up cycle is per `architecture/RISK-REGISTER.md` R1 mitigation.

The `&mut self` count (synthesis line 38: "36 `&mut self` setters") is NOT touched. **Correction per R3**: the 36 number counts OCCURRENCES of `&mut self` in `mod.rs`, of which only 24 are method definitions (the remaining 12 are method bodies and call sites). The async-wrapper collapse does not require setter migration. A documentation note records the corrected count for trj6:

> As of Lane B0 close: `crates/chio-kernel/src/kernel/mod.rs` contains 36 `&mut self` occurrences in source, of which 24 are method definitions (`pub fn ... &mut self`). Builder-finalize migration is deferred to trj6 per synthesis lines 136-138.

## Breaking-change handling

The `ToolServerConnection` trait is **public** (`pub trait ToolServerConnection`). Changing its method signatures from sync to async is a public-API breaking change for any external consumer.

**External-consumer audit**:

- The repo has no published crates yet; `chio-kernel` is workspace-internal. The only public exposure is via FFI bindings in `crates/chio-bindings-ffi/`, `crates/chio-cpp-kernel-ffi/`, and `crates/chio-kernel-mobile/bindings/`. The FFI surfaces do NOT export `ToolServerConnection` as a foreign trait; they expose `ChioKernel` operations through C ABI shims that do not require trait virtualization.
- Verified: `grep -rln "ToolServerConnection" crates/chio-bindings-ffi/ crates/chio-cpp-kernel-ffi/ crates/chio-kernel-mobile/` returns no results.

Conclusion: **no feature flag transition required**. The migration is workspace-atomic. CI is the change boundary.

## CI strategy

B0 PR strategy is one **stacked review** with logical commits in this order:

1. (release work-B0.2) Trait change in `crates/chio-kernel/src/runtime.rs`. CI is RED at this point - all 31 impls fail to compile. This commit ships in the same PR.
2. (release work-B0.3) Production impls converted. CI for production builds becomes green; tests are red because test-impls have not been converted.
3. (release work-B0.4) Test impls converted. CI fully green.
4. (release work-B0.5) Inline `dispatch_tool_call_with_cost_sync` into `dispatch_tool_call_with_cost`; delete the sync helper.
5. (release work-B0.6) Add the new `scripts/check-tool-server-async.sh`; CI gate update.

Reviewers see the layered diff but final CI is one green run. No mid-PR red CI lands on `main`; the merge is an atomic squash that goes from sync trait to async trait in one move.

## What B0 does NOT unblock

B0 unblocks B1, B2, B3 by removing the async-wrapper-lie at `mod.rs:6402-6408` and giving every Lane B sub-lane a real async dispatch path to wire into. B0 explicitly does NOT:

- Remove any `&mut self` setter (the 36 setters remain).
- Change the registration pattern (`kernel.register_tool_server(Box::new(...))` is unchanged).
- Touch `chio-cli/src/trust_control/`.
- Touch `chio-core-types/src/_generated/chio_wire_v1.rs` (37,258 LOC, untouched).
- Convert `NestedFlowBridge` or `NestedFlowClient` to async (those are already shaped to allow caller-side async; their bodies are sync).
- Change `chio-kernel-mobile`. Verified: that crate depends only on `chio-kernel-core`, not `chio-kernel`, per `crates/chio-kernel-mobile/Cargo.toml:30`.

## Open question for the reviewer

**Q**: Does any third-party consumer outside this monorepo embed `chio-kernel` directly with a sync `ToolServerConnection` impl?

**A** (best evidence available in the codebase): no such consumer is documented or traceable. The workspace `RELEASE_AUDIT.md` and the v3.18 `BOUNDED_OPERATIONAL_PROFILE.md` both name FFI shims (C, C++, Go, TypeScript, JVM) as the external surface; none of those embed `ToolServerConnection` as a trait. If a consumer is later identified, they receive the same async-trait API and adapt; no compatibility shim is provided.
