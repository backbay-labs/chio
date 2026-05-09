# Lane B Plan: Wire the Spec Hot Path

**Window**: 7 weeks (extended +1 for B4 per R4 BLOCKER 1). **Inter-lane dependency**: B0 -> {B1, B2, B3, B4}; B1 (soft) -> B4. **Owner-class**: protocol-realization eng + kernel eng + federation eng.

This document fills out per-sub-lane scope, spec citations, affected call sites, acceptance criteria, evidence required, and week range. Companion deep dives in [`async-trait-migration.md`](./async-trait-migration.md), [`single-entry-verifier.md`](./single-entry-verifier.md), [`receipt-v2-failclosed.md`](./receipt-v2-failclosed.md), [`anchor-batch-async-only.md`](./anchor-batch-async-only.md), [`conformance-fixture-spec.md`](./conformance-fixture-spec.md).

---

## Sub-lane B0: Async-trait migration (architectural prerequisite)

**Window**: weeks 1-2. **Owner-class**: kernel eng. **Effort**: L.

### Scope

Convert the `ToolServerConnection` trait at `crates/chio-kernel/src/runtime.rs:254-306` from sync-only to `async fn` in trait. Collapse the async-wrapper lie at `crates/chio-kernel/src/kernel/mod.rs:6402-6408` so `dispatch_tool_call_with_cost` is itself the dispatch path, not a forwarder to `dispatch_tool_call_with_cost_sync` at `crates/chio-kernel/src/kernel/mod.rs:6415-6442`.

### Spec citation

This sub-lane has no normative spec MUST of its own. It is the architectural prerequisite that lets B1, B2, B3 wire the spec MUSTs they DO own. The synthesis (line 95-99) names it: "smallest decomposition cut that unblocks hot-path wiring; everything else stays out of release work."

### Affected call sites

- Trait definition: `crates/chio-kernel/src/runtime.rs:254-306` (`ToolServerConnection`).
- Async wrapper hop: `crates/chio-kernel/src/kernel/mod.rs:6402-6408` (`dispatch_tool_call_with_cost`).
- Sync helper: `crates/chio-kernel/src/kernel/mod.rs:6415-6442` (`dispatch_tool_call_with_cost_sync`) - to be inlined and deleted.
- Trait implementations: 31 total across the workspace (full list in [`async-trait-migration.md`](./async-trait-migration.md) section "Migration order"). Production-path implementors that must convert simultaneously: `chio-mcp-adapter/src/native.rs`, `chio-mcp-remote/src/remote_mcp/session_core.rs`, `chio-acp-edge/src/lib.rs`, `chio-a2a-edge/src/lib.rs`, `chio-acp-proxy/src/kernel_checker.rs`, `chio-openapi-mcp-bridge/src/lib.rs`, `chio-cross-protocol/src/lib.rs`, `chio-tower/src/kernel_service.rs`, `chio-http-core/src/authority.rs`, `chio-a2a-adapter/src/invoke.rs`, `chio-openai/src/lib.rs`. Test-path implementors (~20) follow the production change.

### Acceptance criteria

1. `ToolServerConnection::invoke`, `::invoke_with_cost`, `::invoke_stream`, `::drain_events` are `async fn` (using either native `async fn in trait` or `#[async_trait]`; choice rationale in deep dive).
2. `dispatch_tool_call_with_cost_sync` is removed. `dispatch_tool_call_with_cost` becomes `async` and contains the actual dispatch logic at `crates/chio-kernel/src/kernel/mod.rs:6402` (the line range is now the body, not the forwarder).
3. The `&mut self` setter count on `ChioKernel` (currently 36, per synthesis line 38) is documented in `async-trait-migration.md` but not changed. Setter migration is a trj6 ask; this lane only collapses the async wrapper.
4. `cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check` is green.

### Evidence required

- The PR description includes the diff statistic: lines deleted in `dispatch_tool_call_with_cost_sync` body, lines added to `dispatch_tool_call_with_cost`, count of trait implementor crates touched.
- A new gate script `scripts/check-tool-server-async.sh` (added in B0) that fails if any production module still implements a sync `fn invoke` for `ToolServerConnection` (greps for the old trait signature).
- The existing `crates/chio-conformance/tests/v2_receipt_kernel_round_trip.rs` (lines 58-77, the `EchoToolServer` impl) is updated to use the async trait without behavior change. This proves the conformance suite compiles against the migrated trait.

### Out of scope for B0

- Changing the `ChioKernel::register_tool_server(&mut self, ...)` setter signature. Still `&mut self`. Builder-finalize is trj6.
- Removing any of the other 35 `&mut self` setters.
- Touching `chio-kernel-mobile` (not affected; depends only on `chio-kernel-core`, see README assumption 1).

---

## Sub-lane B1: Single-entry verifier

**Window**: weeks 3-4. **Owner-class**: protocol-realization eng. **Effort**: M. **Depends on**: B0.

### Scope

`chio_kernel_core::verify_capability_full` becomes the only production verifier entry point. The internal kernel helpers `verify_capability_signature` (`crates/chio-kernel/src/kernel/mod.rs:4005-4033`) and `verify_capability_full_without_budget_admit` (`crates/chio-kernel/src/kernel/mod.rs:4035-4058`) are deleted. The four hosted call sites - `mod.rs:2452`, `mod.rs:2706`, `mod.rs:2898`, `mod.rs:3403` - migrate to call `verify_capability_full` directly through a single thin wrapper that supplies kernel-owned dependencies (`trusted_issuers`, `clock`, `crypto_floor`, `peer`, `trust_root`, `budget_registry`).

### Spec citation

PROTOCOL.md lines 405-418 (capability negotiation, hot-path verifier preference):

> "The portable verifier entrypoint `chio_kernel_core::verify_capability_with_floor_and_trust_root(token, trusted_issuers, clock, crypto_floor, trust_root_scope_hash)` enforces the rule in isolation. Production kernels SHOULD prefer the Wave 1.5 composite entrypoint `chio_kernel_core::verify_capability_full(token, trusted_issuers, clock, crypto_floor, peer, trust_root, budgets)`."

This SHOULD becomes MUST. The spec edit changes "Production kernels SHOULD prefer the Wave 1.5 composite entrypoint" to "Production kernels MUST route every governed-decision verification through `chio_kernel_core::verify_capability_full`. Partial entry points (`_with_floor`, `_with_negotiated_floor`, `_with_floor_and_trust_root`, `_with_floor_and_resolver`) are non-production helpers retained only for auditor-facing isolation tests."

### Affected call sites

- `crates/chio-kernel/src/kernel/mod.rs:2452` - `validate_capability_for_resource_or_prompt` calls `verify_capability_signature` (legacy entry; signature + chain-binding only, no W1.2 budget admit, no W1.3 schema ceiling). Migrate to `verify_capability_full` via the new thin kernel wrapper.
- `crates/chio-kernel/src/kernel/mod.rs:2706` - `evaluate_planner_step_*` calls `verify_capability_signature`. Same migration.
- `crates/chio-kernel/src/kernel/mod.rs:2898-2911` - hosted dispatch calls `verify_capability_full_without_budget_admit`. Migrate to `verify_capability_full` (with the actual budget registry, not `NoopBudgetRegistry` from `mod.rs:4045`).
- `crates/chio-kernel/src/kernel/mod.rs:3403-3416` - nested-flow dispatch, same as above.
- The two helpers themselves: `mod.rs:4005-4033` (`verify_capability_signature`) and `mod.rs:4035-4058` (`verify_capability_full_without_budget_admit`) are deleted.

### Acceptance criteria

1. `verify_capability_full` is the only production-callable verifier from `crates/chio-kernel/src/kernel/mod.rs`. The two helpers are removed.
2. All four hosted call sites pass the actual `BudgetRegistry` (the kernel's `budget_registry` field), not `NoopBudgetRegistry`. This closes the Round-3 codex P2 gap noted in `mod.rs:4080-4087` ("the actual `admit_capability_budget` call is deferred until all subsequent checks have passed").
3. PROTOCOL.md line 408 changes SHOULD -> MUST as quoted above.
4. A new gate script `scripts/check-verify-capability-full.sh` greps every file under `crates/chio-kernel/src/` and `crates/chio-cli/src/` for the partial-entry symbols (`verify_capability_with_floor`, `verify_capability_with_negotiated_floor`, `verify_capability_with_floor_and_trust_root`, `verify_capability_with_floor_and_resolver`, `verify_capability_signature`, `verify_capability_full_without_budget_admit`) and exits 1 if any production caller (i.e. anything not under `tests/` and not behind `#[cfg(test)]`) is found. The script is wired into `scripts/check-release work-lane-b.sh` and the workspace CI.

### Evidence required

- The negative conformance fixture at `crates/chio-conformance/tests/verify_full_is_only_production_entry.rs` (the path is named in `02-protocol-realization-engineer.md` line 57 with the same intent). The fixture asserts (a) the two helper symbols are NOT visible from `chio_kernel`'s public API via `chio_kernel::*` glob; (b) the kernel hosted-dispatch path actually invokes `verify_capability_full` by routing through `evaluate_tool_call_blocking` and counting `BudgetRegistry::try_admit_share` calls (the real registry, not a noop, must be hit). Pattern detail in [`single-entry-verifier.md`](./single-entry-verifier.md).
- PR description quotes PROTOCOL.md line 408 before/after.
- `scripts/check-verify-capability-full.sh` returns exit 0 on the merged branch, and exit 1 if any of the deleted symbols is reintroduced.

---

## Sub-lane B2: Receipt v2 fail-closed under negotiated v2

**Window**: weeks 4-5. **Owner-class**: protocol-realization eng. **Effort**: M. **Depends on**: B0.

### Scope

When the federation peer is named on the request and the named peer is NOT pinned fresh, the kernel currently emits a tracing warning and falls back to v1-only minting (`crates/chio-kernel/src/kernel/mod.rs:1574-1591`, `kernel_receipt_version_for_remote`). When the named peer IS pinned fresh and the negotiated peer profile sets `ACCEPTS_RECEIPT_V2`, the kernel correctly mints v2; when negotiation says v1 only, the kernel correctly mints v1. The defect is the third case: a request that names a remote, the remote is not pinned fresh, but a negotiation-time agreement said v2. The current code drops to v1 with only a warning; spec language "falls back" hides the runtime behavior. B2 replaces this with a hard reject that surfaces a typed `KernelError::ReceiptNegotiationDowngrade { expected: V2BodyHash, actual: V1Legacy, reason: NotPinnedFresh }`.

### Spec citation

PROTOCOL.md lines 714-741 ("Receipt v2 body_hash addressing (W2.1)"). Specifically lines 737-741, which today contain DESCRIPTIVE PROSE with neither `MUST` nor `SHOULD`:

> "Negotiation downgrade. When the peer profile is v1-only or when no federation peer is pinned fresh for the request, the kernel falls back to minting only the v1 UUIDv7 receipt. The downgrade emits a structured warning so operators can see receipt-version regressions in observability."

B2 is therefore introducing a **NEW normative MUST** (a tightening), not promoting an existing SHOULD to MUST. The spec edit rewrites lines 737-741 to read: "When the peer profile is v1-only, the kernel mints only the v1 UUIDv7 receipt. When the peer profile is v2-capable but no federation peer is pinned fresh for the request (whether stale or never-pinned), the kernel MUST reject the dispatch with `KernelError::ReceiptNegotiationDowngrade`; v2 negotiation cannot be silently downgraded to v1." (See R3 BLOCKER #1 fix in `receipt-v2-failclosed.md`.)

### Affected call sites

- `crates/chio-kernel/src/kernel/mod.rs:1574-1591` - `kernel_receipt_version_for_remote`. Replace the `tracing::warn!` + `return KernelReceiptVersion::V1Legacy` block with a `Result<KernelReceiptVersion, KernelError>` return that produces the new typed error in the not-pinned-fresh case when the kernel-level `receipt_v2_default()` is true OR the call site otherwise expected v2.
- `crates/chio-kernel/src/kernel/responses.rs:1405-1427` - `record_chio_receipt_with_federation`. Update the call to surface the typed error rather than swallowing it.
- The signature change ripples to the dispatch caller (`evaluate_tool_call_blocking` and friends). Acceptance criterion 2 below pins this.

### Acceptance criteria

1. `kernel_receipt_version_for_remote` returns `Result<KernelReceiptVersion, KernelError>`. The error variant `ReceiptNegotiationDowngrade { expected, actual, reason }` is added to `KernelError`.
2. The dispatch path (the chain from `evaluate_tool_call_blocking` -> `record_chio_receipt_with_federation` -> `kernel_receipt_version_for_remote`) surfaces the typed error and returns a Deny verdict with the structured reason. The kernel does NOT mint a v1 receipt for a v2-negotiated request whose peer dropped out of pin freshness.
3. The advisory case (no federation peer named, kernel-level `receipt_v2_default()=false`) still mints v1; this is the spec-conformant v1-only profile and is unchanged.
4. PROTOCOL.md lines 737-741 are rewritten to introduce a NEW normative MUST per Patch 1 of R3 review. The audit-doc evidence section marks the change as **tightening** (fresh introduction of a normative rule), not **promotion** (SHOULD->MUST). The new MUST explicitly enumerates BOTH the "stale" and "never-pinned" cases.

### Evidence required

- The negative conformance fixture at `crates/chio-conformance/tests/receipt_v2_required_under_v2_negotiation.rs`. The fixture exercises the production mint path (the same `evaluate_tool_call_blocking` entry that `crates/chio-conformance/tests/v2_receipt_kernel_round_trip.rs:107-115` uses) and asserts: (a) when the peer is pinned fresh and v2-capable, v2 receipt is minted; (b) when the peer is named but pin freshness has expired, the dispatch fails with `KernelError::ReceiptNegotiationDowngrade`; (c) when the peer is not named and the kernel default is v1, v1 is minted normally. The fixture must FAIL if `kernel_receipt_version_for_remote` is patched back to the warn-and-downgrade form. Pattern detail in [`receipt-v2-failclosed.md`](./receipt-v2-failclosed.md).
- PR description quotes PROTOCOL.md lines 737-741 before/after.

---

## Sub-lane B3: Anchor-batch async-only when `require_public_witness=true`

**Window**: weeks 5-6. **Owner-class**: protocol-realization eng. **Effort**: M. **Depends on**: B0.

### Scope

When the witness policy declares `require_public_witness=true`, every producer-and-consumer call to anchor-batch verification MUST route through `verify_anchor_batch_with_witness_policy_async` at `crates/chio-anchor/src/batch.rs:251-269`. The sync wrapper at `crates/chio-anchor/src/batch.rs:227-235` (`verify_anchor_batch_with_witness_policy`) MUST reject any policy whose `require_public_witness=true`. This is already the spec rule (PROTOCOL.md lines 982-984) but is not enforced at the type system level today: the sync wrapper accepts any policy and routes through `evaluate_witness_policy`, which produces the right answer for `Pending` and `Stale` but NOT for `Witnessed` (the spec says `Witnessed on the sync path -> reject`). Today the sync wrapper does call `evaluate_witness_policy` which handles this rejection structurally, but there is no compile-time or lint-time guard preventing a producer from constructing a `WitnessPolicy { require_public_witness: true, ... }` and calling the sync function. B3 adds that guard.

### Spec citation

PROTOCOL.md lines 980-993 ("Anchor batch witness state, verifier rule"):

> "`require_public_witness: true`, `Pending` -> reject."
>
> "`require_public_witness: true`, `Witnessed` on the sync path -> reject; use the async verifier path so `AnchorWitnessClient::verify_inclusion` runs."
>
> "`require_public_witness: true`, `Stale` and no verifier-owned cache entry for the recomputed `batch_body_hash` -> reject."

These bullets are descriptive prose today. The spec edit promotes them to a normative MUST-list under a new "Anchor batch verifier-routing requirements" sub-section. The added MUST: "Producers and consumers MUST route through `verify_anchor_batch_with_witness_policy_async` whenever `require_public_witness=true`. The sync entry point `verify_anchor_batch_with_witness_policy` MUST reject any policy carrying `require_public_witness=true` at runtime, regardless of `WitnessState`."

### Affected call sites

- `crates/chio-anchor/src/batch.rs:227-235` - `verify_anchor_batch_with_witness_policy` (sync). Add an early-return that fails closed when `policy.require_public_witness == true` with a typed `AnchorError::SyncRouteRequiresAdvisoryPolicy` (or similar). Today the function silently delegates to `evaluate_witness_policy`, which only happens to reject witnessed/stale states by happenstance of the spec table.
- `crates/chio-anchor/src/batch.rs:208-215` - `verify_anchor_batch` (the bare sync form). This function does NOT take a policy; the gate for it is "do not invoke this from a producer that has a policy with `require_public_witness=true`". Add a doc-comment normative pointer + a CI lint script.
- Producer-side sync callers: per `02-protocol-realization-engineer.md` line 23 the issue exists at `batch.rs:208` and the unit-test path at `batch.rs:361-396`. The unit-test path is already test-only, but the production caller (the producer) must be located by the new gate script. The full caller graph is enumerated in [`anchor-batch-async-only.md`](./anchor-batch-async-only.md).

### Acceptance criteria

1. `verify_anchor_batch_with_witness_policy` fails closed at runtime when called with `require_public_witness=true`.
2. A new lint `scripts/check-anchor-batch-async-witness.sh` enumerates every Rust file in `crates/` outside `tests/` and exits 1 if it finds a call to `verify_anchor_batch_with_witness_policy` (sync) within 50 lines of a `WitnessPolicy` construction whose `require_public_witness` field is set to `true`. **Per R3 BLOCKER #2 fix, the lint's contract is reframed honestly**: false-positives are tolerated AND false-negatives are also tolerated, because the grep-window heuristic cannot soundly catch cross-file or builder-pattern policy construction. The runtime gate at `crates/chio-anchor/src/batch.rs:227-235` is the load-bearing defense; the lint exists ONLY to give developers fast feedback on the obvious literal-struct-init-same-file cases.
3. PROTOCOL.md gets the new normative paragraph in section 6.4.1 as quoted in "Spec citation" above.

### Evidence required

- The negative conformance fixture at `crates/chio-conformance/tests/anchor_batch_sync_path_rejected_under_public_witness.rs`. The fixture builds an `AnchorBatch` exactly as `crates/chio-conformance/tests/anchor_batch_forged_root_rejected.rs:32-45` does, constructs a `WitnessPolicy { require_public_witness: true, ... }`, calls `verify_anchor_batch_with_witness_policy` (the sync function) and asserts the runtime rejects with the new typed error. Then constructs the same scenario with `require_public_witness=false` and verifies the sync path still works (advisory mode preserved). Pattern detail in [`anchor-batch-async-only.md`](./anchor-batch-async-only.md).
- The script `scripts/check-anchor-batch-async-witness.sh` exits 0 on the merged branch. Its CI invocation is added to `.github/workflows/<workflow>.yml` (existing chio CI workflow, exact path determined at PR time).

---

## Sub-lane B4: DSSE-conformant bilateral signing (NEW per R4 BLOCKER 1)

**Window**: weeks 5-6. **Owner-class**: protocol-realization eng + federation eng. **Effort**: L. **Depends on**: B0 (hard); B1 (soft - reuses single-entry-verifier discipline).

### Scope

Wave-2 review R4 found that the existing `crates/chio-federation/src/bilateral.rs::CoSigningBody` (lines 41-77) signs canonical-JSON bytes that share **zero bytes** with the `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §6 DSSE PAE preimage. The spec §6 envelope shape is `Ed25519` over `"DSSEv1" SP LEN(payload-type) SP payload-type SP LEN(payload) SP payload`, where `payload` is the canonical-JSON in-toto Statement carrying the §5 predicate body. The legacy `DualSignedReceipt::verify` at `bilateral.rs:108` is therefore **structural-only** with respect to §6: it verifies the legacy preimage but is not a §6-conformant verifier.

The previously-proposed Lane C "Option A two-signature" (the same passport keypair signs BOTH preimages) was rejected by R4 because it is a structural-framing-without-wiring anti-pattern: it bolts a §6-conformant DSSE envelope alongside a non-conformant `DualSignedReceipt` rather than making §6 conformance load-bearing. R4 BLOCKER 1 promoted DSSE-conformant signing to a Lane B fourth primitive.

B4 introduces a new module `crates/chio-federation/src/bilateral_dsse.rs` exposing:

- `sign_dsse_envelope(receipt, kp_a, kp_b) -> DsseEnvelope`: produces the §6-conformant envelope.
- `verify_dsse_envelope(envelope, pubkey_a, pubkey_b) -> Result<(), Error>`: verifies the envelope per §7 step 11-12.
- `pae_bytes(payload_type, payload) -> Vec<u8>`: pure encoding helper (DSSE PAE).
- An in-toto Statement structure carrying the §5 predicate body.

The legacy `DualSignedReceipt::verify` at `bilateral.rs:108` is **NOT** changed in release work; it coexists with explicit non-§6 disclaimer (Lane C release notes record this). Lane C's bilateral demo consumes B4's DSSE envelope as the §6-conformant artifact.

### Spec citation

`spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §6 lines 338-353 (DSSE PAE encoding) and §7 step 11-12 (signature verification). The spec text is already in MUST shape (the §6 envelope is normatively defined; the open question is whether the runtime emits a §6-conformant artifact). B4 wires the runtime to the existing spec MUST.

### Affected call sites

- New module: `crates/chio-federation/src/bilateral_dsse.rs` (new file). Pure additive.
- Existing module: `crates/chio-federation/src/bilateral.rs` lines 41-77 (`CoSigningBody`) and line 108 (`DualSignedReceipt::verify`) - these stay as-is. Documentation is added noting the legacy artifact is NOT §6-conformant.
- Federation hot path: the dispatch path that produces a `DualSignedReceipt` is augmented to also produce a DSSE envelope when the §6-conformant artifact is requested. Exact integration point determined at PR time.

### Acceptance criteria

1. `crates/chio-federation/src/bilateral_dsse.rs` exists with `sign_dsse_envelope`, `verify_dsse_envelope`, `pae_bytes`, and the in-toto Statement carrier.
2. The DSSE PAE encoding follows §6 lines 338-353 byte-for-byte: `"DSSEv1" SP LEN(payload-type) SP payload-type SP LEN(payload) SP payload`.
3. The Ed25519 signature is computed over the PAE bytes; the public key id matches §7 step 8.
4. `verify_dsse_envelope` rejects: (a) tampered PAE bytes, (b) mismatched payload-type, (c) signatures over the legacy `CoSigningBody` preimage (proves the verifier is §6-shaped, not legacy-shaped).
5. The relationship to `DualSignedReceipt` is documented in `dsse-bilateral-signing.md`: cohabitation (both surfaces ship), not replacement; legacy verifier explicitly disclaims §6 conformance.

### Evidence required

- The negative conformance fixture at `crates/chio-conformance/tests/b4_bilateral_dsse_pae_only_is_conformant.rs` (per R4 finding 1, recommendation 1, ticket B4.2). The fixture: (a) builds a real `DualSignedReceipt` via the legacy path, (b) builds a real DSSE envelope via the new `sign_dsse_envelope`, (c) asserts the two preimages share ZERO bytes (the R4 finding), (d) the §6-conformant verifier accepts the DSSE envelope, (e) tampered PAE bytes are rejected. Pattern detail in [`dsse-bilateral-signing.md`](./dsse-bilateral-signing.md) and [`conformance-fixture-spec.md`](./conformance-fixture-spec.md) §8a.
- PR description quotes `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §6 lines 338-353 verbatim (the PAE encoding) and §7 step 11-12 (signature verification).
- Reverse-test: revert B4.2 on a draft branch; the fixture FAILS because the §6-conformant envelope is not produced and the demo's §6 conformance claim is contradicted.

---

## Inter-lane composition (Lane A x Lane B)

Lane B does not block on Lane A. Lane A's sub-lanes A1 (mutation kill), A2 (threat-evidence backfill), A3 (Kani harnesses) operate on the same crates Lane B touches but on the orthogonal axis of evidence-floor instead of call-site-wiring. The shared CI gate at lane convergence: every Lane B negative conformance fixture is included in the trj4 closeout `audits/evidence/threats/*.json` row that Lane A is replacing. Specifically the threat rows for "capability bypass via partial verifier", "receipt downgrade", and "anchor-batch sync routing under public witness" are populated by Lane B's fixture `caught: 1` runs (Lane A owns that the JSON is non-placeholder; Lane B owns that the fixture is real).

## Out-of-scope reminder

Lane B explicitly excludes (per synthesis lines 134-144):

- Hybrid PQ wiring (R4 in `02-...`).
- Metered-billing post-execution gate (R5 in `02-...`).
- `chio-cli` trust-control extraction.
- Gravity-well surgery on `chio-core` / `chio-kernel`.
- Mobile attestation production-hardening.
- New chiodos primitives.
- `&mut self` setter migration on `ChioKernel` (B0 only collapses the async-wrapper lie; setter migration defers to trj6).
