# Direction A - Authoritative Enforcement, Wired End-to-End

_Keystone research + implementation plan for Chio Desktop's spend control plane. Produced by a focused principal-engineer agent (the multi-wave workflow's A lane hit a structured-output cap and was re-run free-form). Status: DRAFT for maintainer approval._

Repo root: `/Users/connor/backbay/arc`. Paths are relative to that root; evidence is `file:line` from a read-only pass on branch `chio/autonomous-commerce-brainstorm`.

**Thesis (now proven):** a spend control plane whose enforcement can be satisfied by consuming an *advisory* receipt is not a control plane. The kernel already contains a fully authoritative, atomic, fail-closed spend pipeline. The hole is that the surface real agents actually use - the `chio-api-protect` sidecar's direct tool-call endpoint - deliberately routes around that pipeline and emits an advisory receipt that admits, in its own metadata, that it is not authorization. Direction A closes that hole and makes advisory-only enforcement a machine-visible failure.

## 1. Current state - how tool-call evaluation + budget enforcement flow today

### 1.1 Two evaluation surfaces in the sidecar
`crates/products/chio-api-protect/src/proxy/router.rs`:
- `/chio/evaluate` -> `sidecar_evaluate_handler` (`router.rs:23`, `sidecar.rs:3`) - **authoritative but HTTP-substrate-shaped.**
- `/v1/evaluate/advisory` -> `sidecar_evaluate_tool_call_handler` (`router.rs:58`, `sidecar.rs:1008`) - **advisory-only; this is the direct tool-call path SDKs use.**
- `/v1/evaluate` -> `sidecar_removed_evaluate_handler` (`router.rs:61`, `sidecar.rs:995`) returns **410 Gone**; the mediated direct-tool-call route was removed.

The `/chio/evaluate` path is genuinely kernel-mediated (`evaluate_chio_request` -> `HttpAuthority::evaluate` -> `kernel.evaluate_tool_call_blocking_with_metadata`, `authority.rs:658-659`), mints a real `execution_nonce`, signs `Mediated`/`MediatedDecision`/`Prevent` (`authority.rs:697,708`).

The direct tool-call handler (`sidecar.rs:1008`) signs a receipt with `receipt_kind: AdvisoryEvaluation` (`:1100`), `boundary_class: AdvisoryOnly` (`:1101`), `tool_origin: HostExecutedUnmediated` (`:1103`), `decision: None` (`:1099`), `trust_level: Advisory` (`:1117`), and metadata `execution_nonce: "not_minted"` with a self-declared limitation string (`:1114-1115`). No nonce, no budget hold, no guard pipeline, no kernel. **Every shipped Python SDK (chio-langchain/llamaindex/langgraph) posts to `/v1/evaluate/advisory`** (e.g. `sdks/python/chio-langchain/tests/test_tool.py:90`). `chio-api-protect` never opens a budget store (`ProxyState`, `proxy/state.rs:138`, holds no ledger handle).

### 1.2 Lead confirmation
- **Atomic ledger already exists (do not rebuild):** `chio-kernel/src/budget_store.rs`, `trait BudgetStore` (`:260`), `authorize_budget_hold` (`:507`) atomic check+increment+rollback (`:268-294`), plus `reverse/release/reconcile/capture`. Per-`hold_id` rows in `chio-store-sqlite/src/budget_store/store.rs:35-52`. A `BudgetGuaranteeLevel` taxonomy exists **in code only** (`:94`), absent from `spec/` and every ADR.
- **`chio-metering` BudgetEnforcer is a RED HERRING:** real TOCTOU (`check` `:110` read-only, `record` `:167` mutation) but only `chio-data-guards` depends on `chio-metering`, and only for `CostDimension`, never `BudgetEnforcer`. Kernel/control-plane/api-protect do not depend on it.
- **The real gap is the sidecar tool-call routing** (confirmed) with two sharpening corrections: (i) the sidecar's `L847-851` "non-authoritative rejection" is actually the *verify* side already correctly rejecting non-`Mediated` receipts - the *produce* side is what can't mint an authoritative direct-tool-call receipt; (ii) `TrustLevel::Mediated` is a **hardcoded stamp** (`receipt_persistence.rs:45,55`; every builder passes `TrustLevel::default()`), not a proof that budget was held + guards ran.
- **Split budget endpoints** (`/v1/budgets/authorize-exposure|release-exposure|reconcile-spend`, control-plane `service_runtime/router.rs:252-257`) exist but the sidecar does not call them; in `agent-commerce-network` only the provider edge (`chio mcp serve-http`) drives the atomic dance, and the buyer sidecar enforces budget in Python (`buyer/app.py:333-335`).

### 1.3 The kernel pipeline A must reuse
`evaluate_tool_call_async_with_session_context` (`kernel/evaluation/async_evaluation_core.rs`) is a 26-step pipeline: capability verify -> ... -> **authorize budget hold** (step 15, `validation.rs:750` `check_and_increment_budget` -> `authorize_budget_hold` `:785`, hold id `budget-hold:{request_id}:{cap}:{index}`) -> guard pipeline (`run_guards`) -> **consume presented execution nonce** (step 22, `require_presented_execution_nonce`, fail-closed) -> dispatch (step 24) -> **reconcile hold to realized cost** (step 26, `validation.rs:1000`) -> sign receipt + `mint_execution_nonce_for_allow` (`construction.rs:1026`, binding `subject/cap/server/tool/param_hash`). Strong kernel-path regression coverage already exists (`kernel/tests/budget_governed_call_chain.rs`, `kernel/tests/execution_nonce.rs`). **A is wiring the existing authoritative pipeline into the surface real agents use, not building new machinery.**

## 2. The real gap
Routing, not machinery. Four structural facts combine:
1. No authoritative direct-tool-call route exists (the mediated `/v1/evaluate` was removed; SDKs hit `/v1/evaluate/advisory`).
2. The advisory route can emit a receipt at all (governance by convention).
3. Even `/chio/evaluate` builds the kernel request under a cost-free `kernel_scope()` capability (`authority.rs:719`), so its budget hold is a no-op - a nonce + `Mediated` label do not imply a spend hold.
4. `Mediated` is a label, not a proof; `hold_id` (from `request_id+cap+index`) and `nonce_id` (UUIDv7) are orthogonal - a `Mediated` receipt can coexist with zero budget movement.

**"Authoritative" must be a structurally-checkable conjunction over the kernel signature:** (a) `MediatedDecision & Prevent & Mediated & observation_outcome==None & decision==Allow`; (b) budget-authority metadata naming a `hold_id` atomically committed against the *agent's* cost-bearing grant and reconciled; (c) a kernel-signed `execution_nonce` whose binding param_hash/cap match the receipt; (d) hold<->nonce cross-bound; (e) signer is an *admitted kernel key*; (f) fail-closed on any missing/invalid element. Today only (a) is checkable, and (a) is a stamp.

## 3. Implementation plan

**GOAL:** make kernel-mediated, atomic, fail-closed spend enforcement the only structurally-supported path through the sidecar tool-call surface, expressed as a frozen machine-checkable contract (execution_nonce + cross-bound atomic hold + `MediatedSpend` receipt profile) that B and C pin against, so any advisory-only consumption is a visible conformance failure.

### M0 - Freeze the enforcement contract (Phase 0; unblocks B and C; no behavior change)
- Write **ADR-0016** reconciling code-only reality with docs: declare `chio.execution_nonce.v1`, the hold lifecycle, and `BudgetGuaranteeLevel` normative; supersede ADR-0006's "monotonic, no-refund" text (which the code already contradicts); define the `MediatedSpend` predicate (§2 a-f).
- Add `spec/PROTOCOL.md` §6.x for execution_nonce + atomic hold + `MediatedSpend`, coherent with existing §6.1 (`spec/PROTOCOL.md:850-863`).
- Define the contract as code in a shared low-level crate: `MEDIATED_SPEND_PROFILE = "chio.mediated_spend.v1"`, `struct BudgetAuthorityReceiptRef { hold_id, authorize_event_id, reconcile_event_id, capability_id, grant_index, exposed_units, realized_units, execution_nonce_id, guarantee_level }`, and `fn is_authoritative_spend_receipt(receipt, admitted_kernel_keys, presented_nonce) -> Result<(), NotAuthoritativeReason>` (reuse `sidecar.rs:796-799,847-851` as the (a) fragment; extend to b-f).
- **Reserve linkage slots downstream now:** add `execution_nonce_ref`/`hold_ref` to B's `chio.comptroller.surface-report.v1` and to C's M5 settlement receipt, `Option::None` until Phase 2, to avoid a governance-gated schema v2.
- **Decide prepay authority (A's call):** authorize worst-case (`quote.quoted_cost` when present, else `max_cost_per_invocation`) and reconcile down to realized `cost_charged`. Thread the chosen authoritative number to B (projection) and C (gate).

Files: `docs/adr/ADR-0016-*.md` (new), `docs/adr/ADR-0006-*.md` (supersede), `spec/PROTOCOL.md`, `crates/core/chio-core-types/src/receipt/` (new module), `crates/sdk/chio-eval-receipt/` (re-export). Tests: golden round-trip/schema-stability for the nonce + `BudgetAuthorityReceiptRef`; a unit matrix flipping each of (a)-(f).

### M1 - Kernel-mediated direct-tool-call route in the sidecar
Add a `BudgetStore` handle to `ProxyState` (RemoteBudgetStore under `--control-url`, else local sqlite; fail-closed if none). Add `sidecar_evaluate_tool_call_mediated_handler` at a reinstated `POST /v1/evaluate` accepting the same `SidecarEvaluateToolCallRequest` (SDK needs only a URL change). Build the kernel `ToolCallRequest` from the **agent's presented (cost-bearing) capability**, route through the kernel path with a real budget store installed so `check_and_increment_budget` fires and `mint_execution_nonce_for_allow` runs; return `{verdict, receipt, execution_nonce}`; deny/error reverses the hold. Files: `proxy/state.rs`, `proxy/sidecar.rs`, `proxy/router.rs`, `evaluator.rs`/`authority.rs`. Tests: integration asserting the hold was authorized against the agent's cap, `committed_cost` moved, `Mediated`+`Allow`+signed nonce, `is_authoritative_spend_receipt == Ok`; deny leaves `committed_cost==0`.

### M2 - Cross-bind hold <-> nonce; make `Mediated` earned not stamped
Thread the minted `nonce_id` into the budget hold event and record `hold_id`/`authorize_event_id`/`reconcile_event_id` in the receipt's `BudgetAuthorityReceiptRef`; replace hardcoded `TrustLevel::default()` stamps with a derivation (label `Mediated` only if the receipt carries a reconciled `BudgetAuthorityReceiptRef` + guard evidence for cost-bearing grants); add a sign-site invariant. Files: `validation.rs`, `construction.rs`, `responses/receipt_persistence.rs`, `http-core/authority.rs`. Tests: nonce_id in receipt == returned nonce id; signing `Mediated` for a cost-bearing grant without a hold fails closed.

### M3 - Make advisory a visible failure (the enforcement lever)
Gate `/v1/evaluate/advisory` behind `--allow-advisory` (default off; when off, return non-authorizing status pointing to `/v1/evaluate`). Honor `require_nonce`/`minimum_trust_level` (strict mode denies below-`Mediated`). Point the Python SDKs at `/v1/evaluate` by default. Add a tool-server nonce middleware (Solution C from `STRUCTURAL-SECURITY-FIXES.md:423-469`) that refuses executions lacking a valid `X-Chio-Execution-Nonce`. Files: `proxy/router.rs`, `sidecar.rs`, CLI flag, `sdks/python/*`, tool-server middleware. Tests: advisory-off non-authorizing; strict mode denies nonce-less; SDK default target is `/v1/evaluate`.

### M4 - Crash-safety + truthful HA labeling
Add a hold TTL/expiry + a startup **reaper** over `budget_authorization_holds WHERE disposition='Open'` that reconciles/reverses orphaned holds using the ADR-0013 durable-before-allow WAL as arbiter; escalate `PostAdmissionDropGuard` reverse failures beyond `warn!` to a durable pending-reversal record; make `BudgetGuaranteeLevel` truthful (never claim `HaLinearizable` without a backing quorum store; carry the level in `BudgetAuthorityReceiptRef` and let operators set a minimum acceptable level). Files: `chio-store-sqlite/budget_store/store.rs`, `kernel_drop_guard.rs`, `budget_store.rs`, startup hook.

### M5 - Golden conformance + double-spend regression
The mandatory concurrency test runs against both paths: a capability with `max_total_cost=N` and two concurrent calls each `>N/2`. Stale/advisory path: both "authorized," ledger never moved -> asserted as a FAILURE (the visible-failure witness). Integrated path: atomic `authorize_budget_hold` serializes -> exactly one `Allow` (reconciled), one `Deny` (`committed_cost` unchanged), total `<= N`.

## 4. Acceptance criteria (machine-checkable)
1. Golden conformance test (new `crates/tooling/chio-conformance/tests/authoritative_spend_enforcement.rs`): mediated path -> `is_authoritative_spend_receipt == Ok` + hold authorized/reconciled + nonce single-use; advisory path -> `is_authoritative_spend_receipt == Err`, and consuming that receipt as authorization is rejected (**the golden gate**).
2. Double-spend regression present, passing on integrated path, asserting failure on stale path.
3. Predicate coverage matrix (flip each of a-f -> distinct rejection reason).
4. Structural greppable invariant: only the mediated handler can emit `decision: Some(Allow)` for a tool call; advisory is structurally constrained to `decision: None` (asserted).
5. Strict-mode: nonce-less/advisory denied end-to-end; tool-server middleware rejects unmediated calls.
6. Crash-recovery: authorize -> simulated crash before reconcile -> reaper -> orphaned hold reconciled/reversed, exposure consistent.
7. Contract stability: schema round-trip freezes `chio.execution_nonce.v1` + `chio.mediated_spend.v1`; a change fails CI (so B/C's pinned slots cannot silently break).

## 5. Dependencies + sequencing
Freezes first: the M0 contract + prepay-authority decision (single highest-leverage decision). B reuses the ledger read-only as its projection source and must add a nonce/hold slot to `surface-report.v1` now; A gates only B's *live* flagship. C charges the same ledger on the CLI/control-plane host (already kernel-routed), so C-M2..M4 are not blocked by A; A gates only C's *sidecar-hosted* rail, and resolves C's prepay open question. The out-of-repo Chio Desktop fork consumes the frozen contract (presents budgeted capabilities to the mediated route, verifies with `is_authoritative_spend_receipt`, rejects below `Mediated`) - it does not re-implement ledger/kernel/nonce. D is fully independent. **Rule: A passes its own adversarial review before B/C pin.** Reuse `load_behavioral_feed_signing_keypair` (one signing authority).

## 6. Out of scope / defer
Rebuilding the ledger (reuse it); the `chio-metering` refactor (red herring); custody (Year-2); the out-of-repo fork internals; the iroh mesh (no hard dep; `HaLinearizable` stays a labeled claim); full HA linearizable consensus (A ships truthful labeling + a reaper, not consensus); Envoy ext_authz (follow-on); the live B flagship + C sidecar rail themselves (A unblocks, does not build).

## 7. Adversarial self-review - top false-closure risks
- **R1 Relabeling bypass (deepest):** a trusted signer stamps advisory content as `Mediated`+`MediatedDecision`+`Prevent`, passing the label-only predicate with zero budget movement. Fix: `is_authoritative_spend_receipt` must reject a `Mediated` receipt lacking `BudgetAuthorityReceiptRef` + bound nonce + guard evidence AND require an *admitted kernel key* signer; negative conformance case constructs the forged-label receipt and asserts rejection.
- **R2 Nonce-without-hold (mediation theater):** route a call so it gets a nonce + `Mediated` label but the hold runs against a cost-free capability. Fix: conformance asserts the hold was against the *agent's* cost-bearing `capability_id` and `committed_cost` moved + reconciled, not just that a nonce/label exist.
- **R3 Crash leaks exposure (fail-closed but wrong):** no hold TTL/reaper; SIGKILL after authorize commits but before reconcile wedges the grant into `BudgetExhausted` forever; a naive "release Open on restart" fix would enable double-spend. Fix: crash-recovery test with the reaper arbitrated by the ADR-0013 durable receipt log.
- **R4 ADR-0006 HA overrun is doc, not mechanism:** LWW-merge allows `node_count * max_cost_per_invocation` overrun while receipts truthfully-but-misleadingly claim `single_node_atomic`; `HaLinearizable` is a pass-through header claim. Fix (A is not fixing consensus): predicate refuses a guarantee level above the backing store's real level + operator minimum-level; reconcile ADR-0006 in M0.
- **R5 Advisory stays reachable / SDKs keep using it:** even after M1, if advisory is default-on and SDK default unchanged, production keeps emitting advisory receipts and agents can skip the sidecar. Fix: advisory off by default (M3) + SDK default `/v1/evaluate` + tool-server nonce middleware, each tested.
- **R6 Contract shape drift breaks B/C after they pin:** a refactor renames a nonce field; B/C verifiers silently mis-parse while A's tests stay green. Fix: frozen schema golden tests (Acceptance #7) + review-before-pin gate.
