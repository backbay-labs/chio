# Chio Post-Roadmap Addendum

> **Date**: 2026-04-16
> **Scope**: Phases that should begin only after the current `docs/ROADMAP.md`
> execution is complete or explicitly re-scoped.
>
> **Relationship to `docs/ROADMAP.md`**: This document is an addendum, not a
> replacement. It is a candidate post-`v3.18` follow-on sketch for the
> remaining repo-solvable closure path after Phase 20.
>
> **Authority rule**: This document is subordinate to
> `docs/release/QUALIFICATION.md` and `docs/release/RELEASE_AUDIT.md`. It is
> not a replacement ship-boundary document.

---

## Why This Addendum Exists

The current roadmap captures Chio's breadth well, but the latest repo review and
multi-agent debate found that the next bottleneck is not new breadth. The next
bottleneck is tightening trust-critical semantics that are still:

- leader-local rather than quorum-safe
- partially wired rather than end-to-end
- widened by defaults or docs beyond what the runtime proves
- harder to qualify at the public entry points than in the kernel core

This addendum converts that conclusion into five immediate follow-on phases and
then extends the repo-solvable closure ladder through Phase 31.

---

## Ordering

The recommended execution order is:

1. Phase 21: Trust-Control Authority and Budget Truth
2. Phase 22: Guard and Runtime Correctness Closure
3. Phase 23: Economic Truth Separation
4. Phase 24: Release Truth and Front-Door Qualification
5. Phase 25: Adoption Parity and Distribution Hardening

Phase 21 should be treated as serial by default unless its shared trust-control
write sets are re-sliced more narrowly.
Phase 22 can overlap late Phase 21 only when write sets are actually disjoint.
Phase 23 should not widen claims before Phase 21 is green.
Phase 24 is the hard claim-boundary lock for Phases 21 through 23.
Phase 24.1 and 24.3 should begin together.
Phase 25 should ship only after the user-facing contract is stable.
Phases 26 through 31 are the remaining repo-solvable full-vision closure path.

---

## Phase 21: Trust-Control Authority and Budget Truth

> **Goal**: Replace leader-local authority custody and merged budget state with
> fenced, authoritative mutation semantics.
> **Depends on**: Completion of the current roadmap or an explicit decision to
> pause lower-priority roadmap breadth.
> **Refs**:
> - `docs/release/RELEASE_AUDIT.md`
> - `docs/release/QUALIFICATION.md`

**Current repo baseline**:
- [`crates/chio-kernel/src/authority.rs`](../../crates/chio-kernel/src/authority.rs),
  [`crates/chio-control-plane/src/trust_control/cluster_and_reports.rs`](../../crates/chio-control-plane/src/trust_control/cluster_and_reports.rs),
  and
  [`crates/chio-control-plane/src/trust_control/service_runtime.rs`](../../crates/chio-control-plane/src/trust_control/service_runtime.rs)
  already provide a real authority and clustered trust-control surface. The
  remaining gap is fenced custody and stale-leader rejection, not absence of an
  authority subsystem.
- [`crates/chio-kernel/src/budget_store.rs`](../../crates/chio-kernel/src/budget_store.rs),
  [`crates/chio-store-sqlite/src/budget_store.rs`](../../crates/chio-store-sqlite/src/budget_store.rs),
  and [`crates/chio-cli/tests/trust_cluster.rs`](../../crates/chio-cli/tests/trust_cluster.rs)
  already implement hold and mutation-event substrate plus clustered tests.
  Phase 21 is about making those holds and events authoritative across the HA
  path instead of leaving money truth partly leader-local or merge-shaped.

### 21.1 Fenced Authority Custody

**What**: Remove routine replication of authority seed material, replace shared
bearer internal authority APIs with node identity, and add term-based stale
leader fencing.

**Files**:
- `crates/chio-kernel/src/authority.rs`
- `crates/chio-control-plane/src/trust_control/cluster_and_reports.rs`
- `crates/chio-control-plane/src/trust_control/service_runtime.rs`
- `crates/chio-control-plane/src/trust_control/service_types.rs`
- `crates/chio-control-plane/src/trust_control/http_handlers_b.rs`

**Acceptance**:
- authority seed material is no longer serialized and replayed as ordinary
  cluster state on the authoritative path
- every authority mutation carries node identity plus term or lease metadata
- stale-leader writes are rejected by test, not just documented as bounded
- the internal trust-control API no longer relies on a shared bearer token for
  authority custody

### 21.2 Cluster Budget Truth and Replay Safety

**What**: Tighten the remaining cluster and HA spend semantics on top of the
local hold and event model that already exists, so the remote path cannot widen
bounded money truth into a stronger claim.

**Files**:
- `crates/chio-kernel/src/budget_store.rs`
- `crates/chio-store-sqlite/src/budget_store.rs`
- `crates/chio-control-plane/src/trust_control/service_runtime.rs`
- `crates/chio-control-plane/src/trust_control/service_types.rs`
- `crates/chio-cli/tests/trust_cluster.rs`

**Acceptance**:
- budget truth is derived from committed holds and events, not merged counters
- replay-safe idempotency exists for authorize, capture, release, and reconcile
- duplicate `event_id` and stale `lease_epoch` paths are rejected by test
- cluster tests prove no orphaned exposure on failed quorum or stale lease
- leader-visible or `ha_leader_visible` style status is never promoted into a
  stronger spend-truth claim
- the authoritative path no longer documents split-brain overrun as normal
  money truth

### 21.3 Authority and Budget Qualification Gate

**What**: Add a dedicated qualification lane for fenced authority custody and
authoritative budget semantics.

**Files**:
- `docs/release/QUALIFICATION.md`
- `docs/release/RELEASE_AUDIT.md`
- `scripts/qualify-release.sh`
- `scripts/qualify-bounded-chio.sh`

**Acceptance**:
- one qualification command proves authority fencing, stale-leader rejection,
  and authoritative budget mutation semantics
- release docs distinguish bounded compatibility paths from the new
  authoritative path
- no stronger HA or spend-truth language survives without the new gate

---

## Phase 22: Guard and Runtime Correctness Closure

> **Goal**: Close concrete enforcement bugs in the default runtime and guard
> pipeline before widening adoption.
> **Depends on**: Phase 21 can be in progress, but write sets should be kept
> disjoint from trust-control files.
> **Refs**:
> - `docs/protocols/STRUCTURAL-SECURITY-FIXES.md`
> - `docs/protocols/ADR-TYPE-EVOLUTION.md`
> - `docs/guards/10-DATA-LAYER-GUARDS.md`
> - `docs/guards/13-CODE-EXECUTION-GUARDS.md`

**Current repo baseline**:
- [`crates/chio-wasm-guards/src/wiring.rs`](../../crates/chio-wasm-guards/src/wiring.rs),
  [`crates/chio-wasm-guards/src/manifest.rs`](../../crates/chio-wasm-guards/src/manifest.rs),
  [`crates/chio-wasm-guards/src/runtime.rs`](../../crates/chio-wasm-guards/src/runtime.rs),
  and [`crates/chio-cli/src/guards/sign.rs`](../../crates/chio-cli/src/guards/sign.rs)
  already provide signed-guard machinery. The open issue is that the default
  loader path still needs mandatory signature enforcement.
- [`crates/chio-data-guards/src/sql_parser.rs`](../../crates/chio-data-guards/src/sql_parser.rs),
  [`crates/chio-data-guards/src/sql_guard.rs`](../../crates/chio-data-guards/src/sql_guard.rs),
  and [`crates/chio-policy/src/compiler.rs`](../../crates/chio-policy/src/compiler.rs)
  already implement real data-guard and policy-compiler paths. Phase 22 closes
  known bypass and coverage gaps in those existing paths rather than adding a
  brand-new guard stack.

### 22.1 Non-Bypassable WASM Guard Signing

**What**: Enforce signature verification on the default WASM loader path, not
just on helper or explicit signed-load APIs.

**Files**:
- `crates/chio-wasm-guards/src/wiring.rs`
- `crates/chio-wasm-guards/src/manifest.rs`
- `crates/chio-wasm-guards/src/runtime.rs`
- `crates/chio-cli/src/guards/sign.rs`
- `crates/chio-wasm-guards/tests/signing_roundtrip.rs`

**Acceptance**:
- the default runtime path rejects unsigned or invalidly signed guards
- there is no ordinary wiring path that instantiates a guard before signature
  verification
- tests cover valid, invalid, missing-signature, and explicit-opt-out cases

### 22.2 Multi-Statement SQL and Data Guard Safety

**What**: Reject or fully analyze multi-statement SQL payloads and remove the
first-statement-only bypass.

**Files**:
- `crates/chio-data-guards/src/sql_parser.rs`
- `crates/chio-data-guards/src/sql_guard.rs`
- `crates/chio-data-guards/tests/sql_guard.rs`

**Acceptance**:
- a query containing multiple statements cannot pass by validating only the
  first statement
- tests cover `SELECT ...; DROP ...`, mixed read/write sequences, and dialect
  edge cases
- the guard either fully analyzes all statements or fails closed

### 22.3 Fail-Closed Policy Compiler Coverage

**What**: Make the HushSpec-to-runtime compiler fail closed when a supported
policy block lacks a runtime guard mapping.

**Files**:
- `crates/chio-policy/src/compiler.rs`
- `crates/chio-wasm-guards/src/wiring.rs`
- `crates/chio-policy/tests/integration_smoke.rs`

**Acceptance**:
- compiler coverage exists for all supported guard families the schema accepts
- accepted `Rules` fields and `ToolAccessRule` subfields fail closed when they
  have no runtime mapping
- unsupported policy blocks fail compilation instead of being silently dropped
- CI includes a coverage test that enumerates accepted guard families against
  emitted runtime guards

---

## Phase 23: Economic Truth Separation

> **Goal**: Separate budget truth, meter truth, rail truth, and settlement
> truth so receipts and reports stop widening economic claims by default.
> **Depends on**: Phase 21.
> **Refs**:
> - `docs/AGENT_ECONOMY.md`
> - `docs/TOOL_PRICING_GUIDE.md`

**Current repo baseline**:
- [`crates/chio-kernel/src/payment.rs`](../../crates/chio-kernel/src/payment.rs)
  already defines both `not_applicable` and `settled`, while
  [`crates/chio-kernel/src/kernel/mod.rs`](../../crates/chio-kernel/src/kernel/mod.rs)
  and
  [`crates/chio-kernel/src/kernel/responses.rs`](../../crates/chio-kernel/src/kernel/responses.rs)
  still surface `settled` on some no-adapter paths. Phase 23 corrects that
  truth boundary rather than inventing settlement support from zero.
- [`crates/chio-kernel/src/operator_report.rs`](../../crates/chio-kernel/src/operator_report.rs),
  [`crates/chio-store-sqlite/src/receipt_store/reports.rs`](../../crates/chio-store-sqlite/src/receipt_store/reports.rs),
  and
  [`crates/chio-kernel/tests/property_budget_store.rs`](../../crates/chio-kernel/tests/property_budget_store.rs)
  already preserve hold lineage, guarantee level, and budget-authority context
  on several reporting paths. The remaining work is preventing later report and
  export layers from collapsing budget, meter, rail, and settlement truth into
  one synthetic outcome.

### 23.1 Canonical Economic Envelope

**What**: Bind governed approval to payer, merchant, payee destination, rail,
asset, amount ceiling, settlement mode, and quote or tariff identity, while
keeping economic-party truth distinct from authorization lineage alone.

**Files**:
- `crates/chio-core-types/src/capability.rs`
- `crates/chio-core-types/src/receipt.rs`
- `spec/PROTOCOL.md`

**Acceptance**:
- economic authorization hashes change when payer, merchant, payee, rail,
  asset, quote, or amount ceiling changes
- the canonical envelope is serialized, signed, and preserved on receipts
- roundtrip tests prove payer, merchant, payee, rail, asset, quote, and ceiling
  identity survive serialization and verification intact
- captures and releases require envelope-consistent authorization lineage

### 23.2 No-Adapter Settlement Truth Cleanup

**What**: Stop marking no-adapter or no-rail flows as settled.

**Files**:
- `crates/chio-kernel/src/payment.rs`
- `crates/chio-kernel/src/kernel/mod.rs`
- `crates/chio-kernel/src/kernel/responses.rs`
- `crates/chio-kernel/src/receipt_support.rs`

**Acceptance**:
- no-adapter paths emit `not_applicable` or an equivalent bounded truth,
  never settlement finality
- tests prove no adapter-free path can surface `settled` unless a real rail
  adapter and settlement evidence exist
- receipt, report, and summary surfaces cannot reintroduce settlement finality
  without real rail evidence
- release docs narrow any prior language that conflated no-rail and settled

### 23.3 Derived Reporting Truth Preservation

**What**: Preserve economic truth classes through reports, exports, and
reconciliation surfaces.

**Files**:
- `crates/chio-kernel/src/operator_report.rs`
- `crates/chio-kernel/src/cost_attribution.rs`
- `crates/chio-store-sqlite/src/receipt_store/reports.rs`
- `crates/chio-cli/tests/receipt_query.rs`

**Acceptance**:
- derived rows preserve hold lineage, guarantee level, and economic truth class
- operator, metered, behavioral, and settlement reports hydrate from signed
  receipt metadata rather than synthetic recomputation
- report and export gates prove budget, meter, rail, and settlement truth stay
  separated on operator, settlement, metered, behavioral, and cost-attribution
  paths
- report tests prove budget, meter, rail, and settlement truths are distinct

---

## Phase 24: Release Truth and Front-Door Qualification

> **Goal**: Make the release boundary, public docs, and front-door crates prove
> the same thing.
> **Depends on**: Phases 21 through 23.
> **Refs**:
> - `docs/release/RELEASE_AUDIT.md`
> - `docs/release/QUALIFICATION.md`

**Current repo baseline**:
- [`docs/release/QUALIFICATION.md`](../release/QUALIFICATION.md),
  [`docs/release/RELEASE_AUDIT.md`](../release/RELEASE_AUDIT.md),
  `scripts/qualify-bounded-chio.sh`, and
  [`scripts/qualify-release.sh`](../../scripts/qualify-release.sh) already define
  a real bounded-release qualification surface. Phase 24 is mainly about claim
  synchronization and gate enforcement.
- Public entry-point crates already exist at
  [`crates/chio-api-protect`](../../crates/chio-api-protect),
  [`crates/chio-http-core`](../../crates/chio-http-core),
  [`crates/chio-hosted-mcp`](../../crates/chio-hosted-mcp),
  [`crates/chio-openapi`](../../crates/chio-openapi),
  [`crates/chio-openapi-mcp-bridge`](../../crates/chio-openapi-mcp-bridge),
  [`crates/chio-workflow`](../../crates/chio-workflow), and
  [`crates/chio-http-session`](../../crates/chio-http-session). Existing public
  boundary docs such as
  [`spec/OPENAPI-INTEGRATION.md`](../../spec/OPENAPI-INTEGRATION.md) and
  [`docs/standards/CHIO_CROSS_PROTOCOL_QUALIFICATION_MATRIX.json`](../standards/CHIO_CROSS_PROTOCOL_QUALIFICATION_MATRIX.json)
  already reference parts of that surface.

### 24.1 Claim-Discipline Sync Gate

**What**: Add an automated gate that checks ship-facing docs and planning state
for milestone and claim drift against the existing bounded Chio release boundary.

**Files**:
- `spec/PROTOCOL.md`
- `README.md`
- `docs/COMPETITIVE_LANDSCAPE.md`
- `docs/release/RELEASE_AUDIT.md`
- `docs/release/QUALIFICATION.md`
- `docs/release/RELEASE_CANDIDATE.md`
- `docs/release/GA_CHECKLIST.md`
- `docs/release/OPERATIONS_RUNBOOK.md`
- `docs/release/OBSERVABILITY.md`
- `docs/release/RISK_REGISTER.md`
- new script under `scripts/`

**Acceptance**:
- a scripted gate fails if README, release docs, and planning state disagree on
  the current bounded claim boundary
- formal-proof, HA, spend-truth, and market-position language cannot silently
  outrun the qualified evidence set
- the chosen release-go documents are stated explicitly in one place

### 24.2 Front-Door Crate Qualification

**What**: Add direct tests for public boundary crates rather than relying only
on kernel and CLI integration coverage.

**Files**:
- `crates/chio-api-protect/`
- `crates/chio-http-core/`
- `crates/chio-hosted-mcp/`
- `crates/chio-openapi/`
- `crates/chio-openapi-mcp-bridge/`
- `crates/chio-workflow/`
- `crates/chio-http-session/`
- `crates/chio-config/`

**Acceptance**:
- each public boundary crate has direct regression coverage for its primary
  contract surface
- emergency routes, auth failures, config drift, and serialization boundaries
  are exercised through the public entry points
- release qualification includes these front-door tests

### 24.3 Qualification Execution Model

**What**: Decide and enforce whether truth-sensitive release qualification is a
pre-merge gate, a post-merge release gate, or split by surface.

**Files**:
- `.github/workflows/ci.yml`
- `.github/workflows/release-qualification.yml`
- `docs/release/QUALIFICATION.md`

**Acceptance**:
- the chosen model is explicit and enforced in CI
- truth-sensitive surfaces cannot ship under an ambiguous qualification model
- docs no longer imply stronger pre-merge confidence than the workflows provide

---

## Phase 25: Adoption Parity and Distribution Hardening

> **Goal**: Make the public SDK and distribution surface match the corrected
> runtime contract and become consumable outside the monorepo.
> **Depends on**: Phase 24.
> **Refs**:
> - `docs/protocols/DX-AND-ADOPTION-ROADMAP.md`
> - `docs/protocols/HTTP-FRAMEWORK-INTEGRATION-STRATEGY.md`
> - `docs/SDK_PARITY_EXECUTION_ROADMAP.md`

**Current repo baseline**:
- [`sdks/python/chio-py`](../../sdks/python/chio-py) and
  [`sdks/typescript/chio-ts`](../../sdks/typescript/chio-ts) already exist with package
  structure, tests, and release-check scripts such as
  [`scripts/check-chio-py-release.sh`](../../scripts/check-chio-py-release.sh) and
  [`scripts/check-chio-ts-release.sh`](../../scripts/check-chio-ts-release.sh).
- [`crates/chio-http-core/src/verdict.rs`](../../crates/chio-http-core/src/verdict.rs)
  already emits richer deny structure, and the remaining work is carrying that
  contract cleanly through the Python and TypeScript SDKs and into externally
  consumable artifacts.

### 25.1 End-to-End Deny Payload Parity

**What**: Carry structured deny context through Python and TypeScript clients so
the enriched Rust contract is visible to users.

**Files**:
- `crates/chio-http-core/src/verdict.rs`
- `sdks/python/chio-py/src/chio/errors.py`
- `sdks/python/chio-py/tests/test_errors.py`
- `sdks/typescript/chio-ts/src/errors.ts`
- `sdks/typescript/chio-ts/src/types.ts`
- `sdks/typescript/chio-ts/test/errors.test.ts`

**Acceptance**:
- Python and TypeScript surface the same deny details contract that Rust emits
- tests cover flat and nested deny payloads plus backward compatibility
- Phase 0.5 is actually complete across the client-facing SDK surface

### 25.2 TypeScript Testing Parity

**What**: Add a TypeScript testing surface comparable to Python's
`MockChioClient`.

**Files**:
- `sdks/typescript/chio-ts/src/testing.ts`
- `sdks/typescript/chio-ts/package.json`
- `sdks/typescript/chio-ts/test/`

**Acceptance**:
- JavaScript and TypeScript users can unit test without a live sidecar
- `@chio-protocol/sdk` exports allow-all, deny-all, and policy fixtures from a
  stable testing surface
- package-backed examples or tests use the same test-double contract

### 25.3 Registry and Artifact Hardening

**What**: Make published SDK and binary artifacts consumable outside the repo
and verifiable as release outputs.

**Files**:
- `sdks/python/chio-py/pyproject.toml`
- `sdks/typescript/chio-ts/package.json`
- `sdks/python/chio-py/RELEASING.md`
- `sdks/typescript/chio-ts/README.md`
- `scripts/check-chio-py-release.sh`
- `scripts/check-chio-ts-release.sh`
- `.github/workflows/publish-typescript.yml`
- `.github/workflows/publish-python.yml`
- `.github/workflows/release-binaries.yml`
- release artifact scripts under `scripts/`

**Acceptance**:
- published SDK packages do not rely on local-only path assumptions
- package and binary release lanes emit signed artifacts and provenance or SBOM
  metadata
- `npm pack`, `pip install`, and binary download flows work from a clean
  external environment

---

## Non-Goals For This Addendum

This addendum does not automatically widen Chio into:

- a proved market-position thesis
- a general public transparency-log claim beyond the qualified publication path
- a blanket requirement for full release qualification on every routine PR
- new product breadth that bypasses the trust, runtime, and truth gaps above

Those can be reconsidered only through separate external programs and research
tracks after the numbered closure ladder ends.

---

## Repo-Solvable Full-Vision Closure After Phase 25

The phases above close the near-term truth, runtime, and release gaps. They do
not yet make the strongest Chio thesis literally true.

The remaining repo-solvable work to reach the strongest honest Chio boundary
falls into the following candidate phases.

### Phase 26: Authenticated Provenance DAG and Cross-Kernel Continuity

> **Goal**: Make Chio able to prove who authorized what across recursive,
> cross-kernel, and cross-protocol execution with one durable provenance model.
> **Refs**:
> - `spec/PROTOCOL.md`

**Current repo baseline**:
- [`spec/PROTOCOL.md`](../../spec/PROTOCOL.md) already defines the
  `asserted`, `observed`, and `verified` provenance classes plus versioned
  artifacts such as `chio.session_anchor.v1`,
  `chio.request_lineage_record.v1`,
  `chio.receipt_lineage_statement.v1`, and
  `chio.call_chain_continuation.v1`.
- [`docs/standards/CHIO_BOUNDED_OPERATIONAL_PROFILE.md`](../standards/CHIO_BOUNDED_OPERATIONAL_PROFILE.md)
  already states that session anchors and request-lineage records are part of
  the shipped bounded profile, while stronger cross-kernel receipt lineage and
  continuation proofs remain bounded or optional.

**Primary work**:
- unify governed `call_chain`, request-lineage, receipt-lineage, and capability
  lineage into one durable provenance DAG
- require signed parent receipts, parent hashes, and replay-safe continuation
  artifacts before remote provenance upgrades to `verified`
- bind provenance subjects to authenticated caller and capability subject across
  refresh, restart, and failover

**Exit condition**:
- reviewer-pack, authorization-context, and outward report surfaces never
  upgrade `asserted` lineage into `verified`
- cross-kernel continuation is signed, replay-safe, and provenance-complete

### Phase 27: Verifier-Backed Runtime Assurance and Strong Hosted Identity

> **Goal**: Make verified runtime attestation and strong sender-constrained
> identity continuity the default strong path rather than a bounded profile.
> **Refs**:
> - `spec/PROTOCOL.md`

**Current repo baseline**:
- [`crates/chio-core-types/src/capability.rs`](../../crates/chio-core-types/src/capability.rs)
  already includes `RuntimeAssuranceTier`, governed-autonomy requirements, and
  workload-identity structures. The missing piece is making the strongest
  runtime-assurance path the default qualified path.
- [`spec/PROTOCOL.md`](../../spec/PROTOCOL.md) and
  [`docs/standards/CHIO_BOUNDED_OPERATIONAL_PROFILE.md`](../standards/CHIO_BOUNDED_OPERATIONAL_PROFILE.md)
  already distinguish stronger sender-constrained or attested modes from
  bounded hosted compatibility modes such as `shared_hosted_owner`.
- This phase is about verifier-backed attestation records and sender-constrained
  continuity on Chio's existing runtime-assurance path. It does not require
  TEE-rooted receipt signing, enclave-sealed receipt keys, or hardware-bound
  receipt execution claims.

**Primary work**:
- introduce a first-class verified attestation record as the only strong
  runtime-assurance admission input
- bind verified attestation records to the caller, workload identity, or
  session that actually uses the capability
- make the strong hosted profile the default or fence weaker modes as
  compatibility-only
- either prove non-interference for `shared_hosted_owner` or keep it outside
  the strong hosted-security story

**Exit condition**:
- runtime assurance depends on verified attestation, not imported assertion
- hosted identity continuity is cryptographically or transport bound end to end

### Phase 28: Public Transparency and Non-Repudiation Network

> **Goal**: Move from bounded trust-anchor publication to a real append-only,
> externally checkable transparency substrate.
> **Refs**:
> - `spec/PROTOCOL.md`

**Current repo baseline**:
- [`spec/PROTOCOL.md`](../../spec/PROTOCOL.md) already defines checkpoint
  statements, trust-anchor bindings, and explicit `audit_only` and
  `transparency_preview` claim boundaries.
- [`crates/chio-anchor/src/bundle.rs`](../../crates/chio-anchor/src/bundle.rs),
  [`crates/chio-anchor/src/ops.rs`](../../crates/chio-anchor/src/ops.rs), and
  [`crates/chio-web3/src/lib.rs`](../../crates/chio-web3/src/lib.rs) already
  implement checkpoint packaging, publication operations, and verification.
  Phase 28 is the step from bounded transparency preview to externally
  checkable append-only semantics.

**Primary work**:
- replace batch-local checkpoint continuity with one prefix-growing append-only
  log over the full receipt family and claim tree
- anchor verification to external trust roots or witnesses rather than embedded
  keys alone
- add anti-equivocation detection, key continuity, and external verification
  workflows

**Exit condition**:
- Chio can truthfully claim public append-only receipt verification on the
  qualified publication path
- trust-anchor and witness conflicts are detectable and reviewer-visible

### Phase 29: Consensus-Grade Control Plane and Distributed Spend Truth

> **Goal**: Move from bounded leader-local control to real quorum-safe or
> escrow-safe authority and spend invariants.
> **Refs**:
> - `docs/standards/CHIO_BOUNDED_OPERATIONAL_PROFILE.md`

**Current repo baseline**:
- [`docs/standards/CHIO_BOUNDED_OPERATIONAL_PROFILE.md`](../standards/CHIO_BOUNDED_OPERATIONAL_PROFILE.md)
  already documents that trust-control writes are leader-local and budgets are
  local-only or bounded on clustered paths. That file is the clearest statement
  of the current floor.
- [`spec/PROTOCOL.md`](../../spec/PROTOCOL.md) already avoids consensus-grade or
  distributed-linearizable spend claims. Phase 29 is therefore a true control
  plane capability expansion, not just wording cleanup.

**Primary work**:
- replace leader-local coordination with consensus or another real quorum-commit
  protocol for authority and receipt continuity
- implement consensus-backed spend authorization or partitioned escrow that
  preserves a distributed spend invariant
- provide linearizable reads or a proved consistency model

**Exit condition**:
- failover and recovery preserve authority, issuance, and spend truth under
  tested partition and repair scenarios
- Chio can truthfully claim comptroller-grade HA and distributed spend semantics

### Phase 30: Portable Trust, Passport Clearing, and Sybil Resistance

> **Goal**: Turn bounded reputation and multi-issuer artifact packaging into a
> real trust-portable network.
> **Refs**:
> - `docs/VISION.md`

**Current repo baseline**:
- [`spec/PROTOCOL.md`](../../spec/PROTOCOL.md) already contains shipped or bounded
  passport, OID4VCI, OID4VP, discovery, cross-issuer portfolio, trust-pack,
  and migration semantics.
- [`crates/chio-did/src/lib.rs`](../../crates/chio-did/src/lib.rs),
  [`crates/chio-credentials/src/oid4vci.rs`](../../crates/chio-credentials/src/oid4vci.rs),
  [`crates/chio-credentials/src/oid4vp.rs`](../../crates/chio-credentials/src/oid4vp.rs),
  [`crates/chio-core/src/identity_network.rs`](../../crates/chio-core/src/identity_network.rs),
  [`crates/chio-federation/src/lib.rs`](../../crates/chio-federation/src/lib.rs),
  and [`docs/IDENTITY_FEDERATION_GUIDE.md`](../reference/IDENTITY_FEDERATION_GUIDE.md)
  already provide real identity, federation, clearing, and Sybil-control
  substrate. Phase 30 is about turning that substrate into a trust-portable
  network with explicit issuer accountability and bounded clearing.

**Primary work**:
- define issuer descriptors with ownership, accountability, trust-root lineage,
  and correlation boundaries
- define subject continuity and migration semantics across operators
- turn passport portability into trust portability through an explicit clearing
  model
- implement anti-Sybil controls: issuance cost, issuer limits, corroboration,
  and public identity or discovery rules

**Exit condition**:
- a relying party can evaluate trust portability and issuer accountability
  without bilateral private assumptions
- passports and imported trust are bounded by explicit anti-Sybil policy

### Phase 31: Verified Core Boundary and Claim-Proof Discipline

> **Goal**: Make Chio's formal-verification story literally true inside one
> explicit verified core and prevent claim drift.
> **Refs**:
> - `spec/PROTOCOL.md`

**Current repo baseline**:
- [`formal/lean4`](../../formal/lean4),
  [`scripts/check-formal-proofs.sh`](../../scripts/check-formal-proofs.sh), and
  [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) already provide a
  real formal toolchain and CI hook.
- [`spec/PROTOCOL.md`](../../spec/PROTOCOL.md)
  already states that the current Lean model is informative and ongoing rather
  than a closed proof of the production runtime. Phase 31 makes the public
  claim boundary line up with a named verified core and refinement story.

**Primary work**:
- define one explicit `Verified Core` boundary
- map every public formal claim to named theorems in that boundary
- prove or machine-check a refinement from production Rust decision logic to
  the Lean model
- make theorem inventory and public-claim drift fail CI and release gates

**Exit condition**:
- public formal claims are bounded to a named verified core with enforced CI
  alignment
- the security-critical pure evaluator routes through the verified boundary
- proof-discipline remains a standing release and documentation gate after
  Phase 31 rather than becoming another numbered roadmap phase

## After Phase 31

The numbered closure ladder stops at Phase 31.

What remains after that is still necessary for the strongest Chio vision, but
it is no longer honest to represent it as more repo-solvable roadmap phases.
The remainder splits into:

- two external evidence programs tracked in
  `docs/POST_31_EXTERNAL_PROGRAMS.md`:
  `Standards And Trust-Portability Qualification` and
  `Market Validation And External Proof`
- explicit research tracks that remain outside the product ladder
- standing release and claim-discipline controls that continue without becoming
  new phases

This separation is deliberate.
It prevents the addendum from becoming a shadow market-proof roadmap and keeps
ship truth, repo-local stronger claims, external evidence, and research in
distinct documents.

### Research Track: ZK Receipt Proofs and TEE-Backed Execution

These should run as explicit research tracks, not silently inside product
milestones:

- ZK verification over signed receipt chains
- TEE-backed receipt and runtime-assurance binding

Current research memos:
- `docs/research/CHIO_ZK_RECEIPT_PROOFS_MEMO.md`
- `docs/research/TEE_RUNTIME_ASSURANCE_BINDING_MEMO.md`

Working boundary:
- the ZK track is about proving narrow predicates over Chio's existing signed
  receipts, lineage artifacts, and checkpoint proofs after the Phase 26 and
  Phase 28 substrate is stable enough to prove over honestly
- the TEE track is about adding hardware-rooted receipt or checkpoint
  provenance on top of Phase 27's verifier-backed runtime-assurance path, not
  replacing Phase 27's admission model
- outputs here can include research memos, design notes, prototype code,
  verifier benchmarks, and threat-model work, but not numbered-phase exit
  criteria or widened ship claims

They are powerful extensions, but they are not required for Phases 26 through
31 or the post-31 external programs to establish the non-research Chio thesis.

---

## Bottom Line

The post-roadmap priority is to make Chio's strongest safety-sensitive and
ship-facing claims line up with the runtime's default behavior, public entry
points, and release gates.

Phases 21 through 25 tighten truth.
Phases 26 through 31 are the remaining repo-solvable path from truthful bounded
Chio to the strongest honest repo-local Chio boundary.
After Phase 31, the remaining vision work continues in external programs and
research, not more numbered product phases.
