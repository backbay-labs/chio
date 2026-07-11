# Chio Active-Defense Implementation Plan

**Status:** Revised implementation contract, implementation not started

**Revised:** 2026-07-10
**Design contract:** `docs/superpowers/specs/2026-07-09-security-folder-design.md`

## Goal

Ship information-flow enforcement, private deception, deterministic temporal detection, and durable reversible containment without introducing a kernel/guards dependency cycle, duplicating manifest truth, or claiming security properties that the implementation cannot prove.

## Non-negotiable constraints

- No em dash characters in code, comments, fixtures, or documentation.
- New production code has no `unwrap`, `expect`, or `unsafe`.
- Signed payloads use Chio canonical JSON and an explicit domain-separation context.
- `chio-kernel` and `chio-guards` do not depend on any active-defense engine.
- `chio-security-kernel` implements the existing `chio_kernel::Guard` and `chio_kernel::PostInvocationHook` APIs. It may depend on the pure flow and decoy engines, but it does not depend on `chio-guards` or platform crates and does not replace the hook APIs.
- Kernel construction is centralized behind one security-installation helper. `chio-control-plane::build_kernel`, runtime harness, HTTP authority, CLI MCP wrapping, and every other direct constructor must call it or reject `chio.manifest.v2` manifests requiring `flow_v1`.
- Heavy-action execution depends on the protocol-primitives threshold governed-approval set verifier and atomic replay reservation. Until they land, heavy plans are dry-run. `chio-quarantine` must not implement a local quorum format or verifier.
- Every failure in label parsing, classification, flow state, manifest security lookup, or declassification consumption denies or blocks.
- Deception signals are high confidence, not zero false positive.
- Temporary containment uses a reversible overlay. The insert-only revocation oracle is not used for an action advertised as reversible.
- A bounded, truncated, locally incomplete, unfenced, or stale lineage query cannot authorize automatic containment.
- Source grep is not security verification. Release gates execute the behavior described below.
- Threat rows stay unchanged until the existing conformance and caught-mutant evidence gate passes.

## Target dependency graph

| Crate | Direct Chio dependencies | Forbidden dependencies |
|---|---|---|
| `chio-security-types` | None | all kernel, guard, trust, platform, and observability crates |
| `chio-core-types` | `chio-security-types` plus existing portable dependencies | security engines, kernel, guards, and platform crates |
| `chio-flow` | `chio-security-types`, `chio-core-types` | `chio-kernel`, `chio-guards`, platform crates |
| `chio-security-kernel` | `chio-security-types`, `chio-flow`, `chio-decoy`, `chio-core`, `chio-kernel` | `chio-guards`, trust and platform crates |
| `chio-decoy` | `chio-security-types`, `chio-core-types` | `chio-kernel`, `chio-guards`, platform crates |
| `chio-quarantine` | `chio-security-types`, `chio-core-types` | `chio-kernel`, `chio-guards`, concrete trust and platform crates |
| `chio-store-sqlite` | `chio-security-types` plus existing store dependencies | security engines and `chio-security-kernel` |
| `chio-control-plane` | all five security crates plus existing runtime dependencies | none beyond workspace policy |

The root `Cargo.toml` registers all five crates and workspace dependencies. Add a dependency-direction test that parses `cargo metadata --format-version 1` and fails if the forbidden edges appear.

## Final file map

### New crates

- `crates/security/chio-security-types/Cargo.toml`
- `crates/security/chio-security-types/src/lib.rs`
- `crates/security/chio-security-types/src/flow.rs`
- `crates/security/chio-security-types/src/declassification.rs`
- `crates/security/chio-security-types/src/deception.rs`
- `crates/security/chio-security-types/src/event.rs`
- `crates/security/chio-security-types/src/response.rs`
- `crates/security/chio-security-types/src/ports.rs`
- `crates/security/chio-flow/Cargo.toml`
- `crates/security/chio-flow/src/lib.rs`
- `crates/security/chio-flow/src/lattice.rs`
- `crates/security/chio-flow/src/engine.rs`
- `crates/security/chio-flow/src/classification.rs`
- `crates/security/chio-flow/src/declassification.rs`
- `crates/security/chio-security-kernel/Cargo.toml`
- `crates/security/chio-security-kernel/src/lib.rs`
- `crates/security/chio-security-kernel/src/pre_invocation.rs`
- `crates/security/chio-security-kernel/src/post_invocation.rs`
- `crates/security/chio-security-kernel/src/tripwire.rs`
- `crates/security/chio-security-kernel/src/containment.rs`
- `crates/security/chio-decoy/Cargo.toml`
- `crates/security/chio-decoy/src/lib.rs`
- `crates/security/chio-decoy/src/registry.rs`
- `crates/security/chio-decoy/src/lifecycle.rs`
- `crates/security/chio-decoy/src/materialize.rs`
- `crates/security/chio-decoy/src/watermark.rs`
- `crates/security/chio-decoy/src/matcher.rs`
- `crates/security/chio-quarantine/Cargo.toml`
- `crates/security/chio-quarantine/src/lib.rs`
- `crates/security/chio-quarantine/src/rules.rs`
- `crates/security/chio-quarantine/src/correlation.rs`
- `crates/security/chio-quarantine/src/blast.rs`
- `crates/security/chio-quarantine/src/approval.rs`
- `crates/security/chio-quarantine/src/state_machine.rs`
- `crates/security/chio-quarantine/src/executor.rs`
- `crates/security/chio-quarantine/src/scheduler.rs`

### Existing ownership boundaries to modify

- `crates/core/chio-core-types/src/manifest.rs`: sole normative `ToolDefinition`
- `crates/core/chio-core-types/src/declassification.rs`: Chio-signed wrapper around the portable declassification body
- `crates/core/chio-core-types/src/capability/governance.rs`: reusable approval verification extensions only
- `crates/core/chio-core-types/src/receipt/`: active-defense receipt bodies and kinds
- `crates/kernel/chio-kernel/src/runtime.rs`: request field for a signed declassification grant
- `crates/platform/chio-manifest/src/lib.rs`: reexport normative tool type, retain signing and validation
- `crates/platform/chio-manifest/src/validation.rs`: validate flow declarations
- `crates/platform/chio-store-sqlite/src/security_state.rs`: concrete active-defense stores and additive schema
- `crates/platform/chio-control-plane/src/security/mod.rs`: composition and lifecycle owner
- `crates/platform/chio-control-plane/src/security/adapters.rs`: lineage, issuance, velocity, receipt, and SIEM adapters; SQLite stores remain in `chio-store-sqlite`
- `crates/platform/chio-control-plane/src/security/scheduler.rs`: durable response worker
- `crates/platform/chio-control-plane/src/policy.rs`: active-defense configuration
- `crates/platform/chio-control-plane/src/lib.rs`: registration in `build_kernel`
- `crates/kernel/chio-runtime-harness/src/kernel.rs`, `crates/platform/chio-http-core/src/authority.rs`, and `crates/products/chio-cli/src/cli/mcp/wrap.rs`: direct construction paths to centralize or make explicitly enforcement-ineligible
- `.github/workflows/apalache-safety.yml`, `formal/proof-manifest.toml`, and the applicable formal manifests: register the new lattice model and negative case
- protocol adapters that construct `ToolDefinition`, located with `rg "ToolDefinition \\{" crates sdks`
- `spec/schemas/chio-wire/v1/security/`: new portable schemas
- `spec/PROTOCOL.md`, `spec/SECURITY.md`, and `spec/GUARDS.md`: normative behavior

## Phase 0: Provenance and architecture guardrails

### Task 0.1: Record the adaptation boundary

**Files**

- Create `docs/security/clawdstrike-active-defense-provenance.md`
- Modify repository `NOTICE` only if implementation copies or materially adapts copyrightable code

**Work**

- Record the reviewed Clawdstrike commit `666303e5f3428f3b6e6b72f118c269a02388e0a4`.
- Record the exact source files used for temporal rules, deception lifecycle, response transitions, watermarks, and tripwire tests.
- For each implementation file, classify reuse as concept, test-vector adaptation, or code adaptation.
- Verify the license of any file that itself names another upstream source before copying it. Concept-only reuse is allowed when provenance is unresolved; verbatim or close code reuse is not.
- Preserve Apache-2.0 headers, modification notices, and applicable Clawdstrike `NOTICE` text.

**Tests and gate**

- Add `scripts/check-security-provenance.sh` to require a provenance entry for files containing `Adapted from Clawdstrike`.
- Add shell tests in `scripts/tests/check-security-provenance.test.sh` for missing entry, unknown source commit, and valid entry.
- Run `bash scripts/tests/check-security-provenance.test.sh`.

### Task 0.2: Enforce the dependency direction

**Files**

- Modify root `Cargo.toml`
- Create `scripts/check-security-dependencies.sh`
- Create `scripts/tests/check-security-dependencies.test.sh`

**Work**

- Register the five crates with minimal manifests.
- Implement the metadata check against resolved package ids, not textual Cargo.toml grep.
- Fail if `chio-kernel` or `chio-guards` reaches a security engine, if a pure engine reaches kernel or guards, or if `chio-security-kernel` reaches `chio-guards` or a platform crate.
- Add the script to the same CI lane that runs architecture and hygiene checks.

**Tests and gate**

- Test a valid fixture graph and one fixture for each forbidden edge.
- Run `bash scripts/tests/check-security-dependencies.test.sh`.
- Run `bash scripts/check-security-dependencies.sh`.

## Phase 1: Portable types and the DLM lattice

### Task 1.1: Implement canonical label types

**Files**

- Create `chio-security-types/src/flow.rs`
- Create `spec/schemas/chio-wire/v1/security/information-label.schema.json`

**Required API and validation**

- `PrincipalId` and `Compartment` validated newtypes.
- `InformationLabel::Known { owners: BTreeMap<PrincipalId, BTreeSet<PrincipalId>>, compartments }` and `InformationLabel::Top`.
- `InformationLabel::bottom()` returns an empty known label.
- Construction and deserialization reject blank or whitespace-padded ids, owner sets that omit the owner, duplicate JSON keys, unknown fields, and configured cardinality overflow.
- Serialization uses one canonical tagged shape and sorted collections. `Top` has no payload fields.
- The crate builds with `--no-default-features` for `wasm32-unknown-unknown`.

**Exact tests**

- `bottom_is_unique_public_label`
- `owner_must_be_its_own_reader`
- `duplicate_owner_json_is_rejected`
- `blank_principal_and_compartment_are_rejected`
- `known_and_top_canonical_vectors_round_trip`
- `noncanonical_input_normalizes_to_identical_canonical_bytes`
- JSON Schema positive and negative vectors for every validation rule

**Commands**

- `cargo test -p chio-security-types flow`
- `cargo check -p chio-security-types --no-default-features --target wasm32-unknown-unknown`

### Task 1.2: Implement and verify the lattice

**Files**

- Create `chio-flow/src/lattice.rs`
- Create `formal/tla/InformationFlowLattice.tla`
- Create `formal/tla/MCInformationFlowLattice.cfg`
- Modify `formal/MAPPING.md`, `formal/theorem-inventory.json`, and the applicable formal manifest

**Required behavior**

- `flows_to` follows the owner-to-reader subset and compartment subset definition in the design.
- `join` intersects same-owner reader sets, retains one-sided policies, unions compartments, and propagates `Top`.
- Runtime egress rejects `Top` separately from the mathematical relation.
- Functions return validation errors rather than manufacturing a permissive label.

**Exact tests**

- Property tests for reflexivity, antisymmetry, and transitivity.
- Property tests that each operand flows to its join.
- Property test that join flows to every generated common upper bound.
- Commutativity, associativity, and idempotence of join.
- Regression: redundant same-owner policies cannot create two unequal labels that flow both ways.
- Regression: adding an owner restriction is upward in the order.
- Regression: narrowing readers is upward in the order.
- Regression: `Top` is mathematical top but is operationally denied on egress.
- Negative formal model that reverses reader subset direction must fail.

**Commands**

- `cargo test -p chio-flow lattice`
- Run the repository's Apalache/TLA gate for `MCInformationFlowLattice.cfg` and its negative model.
- Register both models in `.github/workflows/apalache-safety.yml`, `formal/proof-manifest.toml`, and the repository's model inventory so the normal CI gate cannot omit them.

## Phase 2: One manifest truth and portable wire shapes

### Task 2.1: Unify `ToolDefinition`

**Files**

- Modify `crates/core/chio-core-types/src/manifest.rs`
- Modify `crates/platform/chio-manifest/src/lib.rs`
- Modify `crates/platform/chio-manifest/src/validation.rs`
- Modify every Rust constructor returned by `rg "ToolDefinition \\{" crates sdks`

**Work**

- Add `ToolFlowDeclaration { output_label, input_clearance, egress, declassification_purposes }` to the normative core type.
- Move `LatencyHint` to the normative type and make `latency_hint` the only v2 latency field. Remove `ToolAnnotations.estimated_duration_ms` so scheduling never has two authorities.
- Add `deny_unknown_fields` and strict nested validation to the normative `ToolDefinition`, `ToolPricing`, `ToolAnnotations`, `ToolFlowDeclaration`, label, and latency types before removing any platform type. Add regression fixtures proving unknown nested fields still reject.
- Introduce `chio.manifest.v2` for the canonical unified shape. Keep `TOOL_MANIFEST_SCHEMA` v1 parsing in an explicit version-dispatch function, convert through a private `LegacyToolDefinitionV1`, and require re-signing before v2 admission. Do not deserialize both versions into one ambiguous type.
- Remove the public duplicate in `chio-manifest` only after the v2 parser and fixtures pass, then reexport the normative `ToolDefinition`, `ToolPricing`, `PricingModel`, `ToolAnnotations`, and `LatencyHint` types.
- Replace `has_side_effects` call sites with `ToolAnnotations.read_only` and conservative annotation values. Do not keep two fields that can disagree.
- Keep a private `LegacyToolDefinitionV1` only in the versioned parser. Convert `has_side_effects=true` to `read_only=false`, `destructive=true`, `idempotent=false`, and `requires_approval=true`; convert false to `read_only=true` while leaving the other flags false. Operators must re-sign the canonical migrated manifest.
- Convert legacy `estimated_duration_ms` deterministically: `0..=1` to `instant`, `2..=999` to `fast`, `1000..=59_999` to `moderate`, and `60_000..` to `slow`. Preserve an existing platform v1 `latency_hint` exactly. Reject a legacy migration input that supplies both representations through any merged or adapter shape.
- Treat manifest flow declarations as publisher requests. Runtime topology computes a mandatory egress bit that is ORed with manifest egress. Tenant or data-owner policy supplies authoritative clearances and output floors; manifest clearance and purposes may only narrow them.
- Validation rejects effective egress without every required policy clearance, `Top` output declarations, `Top` destination clearance, duplicate purposes, invalid label ids, and any manifest attempt to widen operator policy.
- Security lookup accepts only a successfully verified v2 `ToolManifest`, authenticated tenant policy, and runtime topology record, never an adapter discovery object.

**Exact tests**

- Existing v1 manifests parse only through the legacy parser and become enforceable only after conversion and v2 re-signing.
- Tampering any flow declaration invalidates the signature.
- Egress without clearance is rejected.
- Publisher-declared `egress=false` cannot override a remote runtime boundary.
- Publisher clearance cannot exceed tenant or data-owner policy.
- Unknown fields in every nested normative type reject before signature admission.
- Legacy side-effecting tools migrate to conservative annotations.
- Latency threshold boundary fixtures map deterministically and v2 rejects any second latency representation.
- There is one public Rust `ToolDefinition` type after migration.
- All 62 constructor sites found at plan review compile with explicit security semantics.

**Commands**

- `cargo test -p chio-core-types manifest`
- `cargo test -p chio-manifest`
- `cargo check --workspace`

### Task 2.2: Preserve flow metadata across adapters

**Files**

- Modify `crates/protocol/chio-openapi/src/generator.rs`
- Modify `crates/protocol/chio-openapi-mcp-bridge/src/lib.rs`
- Modify MCP, A2A, ACP, OpenAI, Anthropic, cross-protocol, and provider adapter projections that consume or construct `ToolDefinition`
- Add `BridgeSecurityMetadata` to the existing internal bridge model that all applicable adapters can retain

**Work**

- Define and validate OpenAPI `x-chio-flow` input.
- Keep flow metadata in an internal sidecar when the remote protocol cannot represent it.
- Reject an export/import path that would turn a constrained egress tool into an unconstrained local manifest.
- Do not encode security metadata in human-readable descriptions.

**Exact tests**

- OpenAPI extension to normative manifest to OpenAPI extension is lossless.
- MCP, A2A, ACP, OpenAI, and Anthropic internal round trips preserve identical canonical flow bytes.
- Removing the sidecar from a constrained tool returns an explicit adapter error.
- Cross-protocol routing does not change clearance or purposes.

**Commands**

- Run the unit tests for every modified protocol crate.
- `cargo test -p chio-cross-protocol`
- `cargo test -p chio-provider-conformance`

### Task 2.3: Add four-language schemas and vectors

**Files**

- Add schemas under `spec/schemas/chio-wire/v1/security/` for declassification, event, finding, response plan, effect, and transition receipt bodies
- Add vectors under `crates/tooling/chio-conformance/vectors/security/`
- Regenerate committed Rust, Python, TypeScript, and Go artifacts through `cargo xtask codegen`

**Exact tests and commands**

- Each language decodes and re-encodes the same positive vectors.
- Each language rejects unknown fields, duplicate map keys where its parser exposes them, invalid ids, and a missing action binding.
- `make codegen-check`
- `cargo test -p chio-conformance vectors_schema_pair`

## Phase 3: Durable security state

### Task 3.1: Define neutral port contracts

**Files**

- Create `chio-security-types/src/ports.rs`

**Required ports**

| Port | Atomic contract |
|---|---|
| `FlowStateStore` | monotonic principal, lineage, and session joins; context generation; egress fence valid through dispatch commitment |
| `ClassificationPort` | return typed findings plus classifier identity/version, or a typed failure; never collapse failure to no findings |
| `TripwireDetectorPort` | match canary, honey-tool, and watermark inputs through `chio-decoy` without exposing registry material |
| `DeclassificationUseStore` | insert grant id exactly once with request hash and outcome state |
| `SecurityEventVerifierPort` | verify detector signature or source receipt, producer trust class, tenant, freshness, and event-time bounds |
| `SecurityEventStore` | append verified events by unique event id and scan a bounded rule partition; advisory events remain segregated |
| `DecoyRegistryStore` | compare-and-swap lifecycle, private lookup by id or marker digest |
| `ResponseStore` | create plan, compare-and-swap generation, persist effects, claim due work |
| `ContainmentOverlayStore` | effect-ID-keyed contributions, compositional effective posture, conditional removal, scheduler fence rejection |
| `BlastRadiusPort` | return authoritative commit-indexed `Exact` or `Incomplete`; after approval acquire/query/release a bounded issuance-and-delegation fence by deterministic action id |
| `ApprovalVerifierPort` | verify operator capability and proposal, trusted role, freshness, distinctness and intent binding; coordinate approval-only admission and replay state |
| `EffectPort` | apply or remove one contribution with idempotency key, expected version, and monotonic scheduler fencing token |
| `SecurityReceiptSink` | sign and append canonical transition evidence |
| `SecurityAlertPort` | page with hashes and ids, never raw security material |

Every store error is typed as unavailable, conflict, invalid data, or integrity failure. Engines must not collapse those into empty state.

Port request and response types use only portable security types, canonical body bytes, hashes, ids, and opaque receipt references. They do not name kernel, trust, lineage, or Chio signature types. `chio-core-types`, `chio-flow`, and control-plane adapters perform those conversions at their existing ownership boundaries.

**Exact tests**

- Compile-time fake implementations cover every port.
- A fault-injection fake can fail before or after each write.
- Port contract tests run against both fakes and SQLite implementations.

### Task 3.2: Implement the SQLite stores

**Files**

- Create `crates/platform/chio-store-sqlite/src/security_state.rs`
- Modify `crates/platform/chio-store-sqlite/src/lib.rs`
- Create `crates/platform/chio-store-sqlite/tests/security_state.rs`

**Schema requirements**

- Additive `CREATE TABLE IF NOT EXISTS` migrations following existing store patterns.
- Tables for principal, lineage, and session flow state; isolation epochs; egress fences; declassification uses; verified and advisory security events; correlation partials; decoy registry; response plans; approvals; effect contributions; transitions; overlay state; lineage fences; and scheduler leases.
- Tenant id participates in every primary or unique lookup boundary.
- Canonical body hash is stored alongside serialized bodies and verified on read.
- Response and overlay writes use transactions with compare-and-swap generation checks. Removing one effect recomputes posture from all remaining active contributions.
- Scheduler claims use a lease owner, expiry, and monotonically increasing fencing token so a resumed stale worker cannot mutate an effect after takeover.
- Marker material and rollback payloads use the existing encrypted-blob facility; raw values are absent from ordinary tables.

**Exact tests**

- Migration is idempotent and preserves an existing receipt database.
- Concurrent principal, lineage, and session joins cannot lose either restriction.
- A new session inherits principal and lineage taint unless a verified isolation-epoch transition exists.
- A concurrent taint generation change invalidates an egress fence before dispatch.
- Duplicate declassification consume returns already-consumed without mutation.
- Cross-tenant reads and writes fail.
- Corrupt canonical hash fails closed.
- Two scheduler workers cannot own the same live lease.
- Every stale scheduler fencing token is rejected by overlay and effect stores.
- Process restart recovers expired leases.
- Overlapping overlay contributions may expire in either order without removing the remaining restriction.

**Commands**

- `cargo test -p chio-store-sqlite --test security_state`
- `cargo test -p chio-store-sqlite --test tenant_isolation`

## Phase 4: Pure flow decisions and one-shot declassification

### Task 4.1: Implement classification and session transitions

**Files**

- Create `chio-flow/src/classification.rs`
- Create `chio-flow/src/engine.rs`
- Modify `crates/guards/chio-data-guards/src/lib.rs` and add a focused structured-classification module and tests
- Add the `ClassificationPort` adapter in `crates/platform/chio-control-plane/src/security/adapters.rs`

**Work**

- Add a typed, non-transforming `ClassificationFinding` API to `chio-data-guards`; the current `QueryResultGuard` redaction API is not a classifier and cannot satisfy this task. Findings bind category, confidence, byte range or field path, classifier id, and classifier version. Classification failure is distinct from an empty result.
- Accept findings through `ClassificationPort`, not a direct `chio-flow -> chio-data-guards` dependency. Map configured categories to label restrictions. Unknown categories return an error.
- Join classifier output with operator output floor, manifest output floor, principal taint, lineage taint, and current session label before persistence.
- Pre-invocation decisions take a fully resolved `FlowRequest` containing request hash, authoritative principal, lineage, and session labels, context generation, payload label, runtime topology, policy clearances, manifest declaration, and optional verified declassification result.
- Compute the pre-invocation source label as the join of classified payload, operator input floor, principal taint, lineage taint, and session taint. Compare that complete label with every effective destination clearance. Treat all outbound bytes as potentially derived from the agent's accumulated knowledge even when the bytes do not independently match a classifier.
- A verified declassification result substitutes its exact signed target only for that request, destination, and purpose after the complete source label is recomputed. It never changes durable principal, lineage, or session state.
- Acquire an egress fence for that generation and keep it valid through dispatch commitment. A generation change causes re-evaluation or denial.
- Missing policy clearance, publisher-only clearance, `Top`, state overflow, classifier error, fence conflict, or any read/write error returns a deny reason suitable for structured guard evidence.

**Exact tests**

- PII, PHI, secret, and tenant category mappings add the expected owner and compartment restrictions.
- Unknown classifier category denies.
- Classifier error and malformed finding deny; an authenticated empty finding set remains distinguishable.
- Many small outputs monotonically accumulate taint.
- An unclassified outbound payload after sensitive knowledge acquisition retains the accumulated source label and cannot bypass clearance.
- Concurrent joins retain both reader restrictions and compartments at principal, lineage, and session levels.
- Starting a new session with the same subject and isolation epoch inherits taint.
- A verified fresh isolation epoch resets only the new isolated principal instance.
- A response that advances generation before another egress dispatch invalidates the stale fence.
- Egress missing clearance denies.
- Runtime remote topology overrides `manifest.egress=false`; a manifest cannot grant its own clearance.
- Non-egress calls do not require clearance but still retain taint.
- Classifier and store fault injection blocks output.

### Task 4.2: Implement signed one-shot declassification

**Files**

- Create `chio-security-types/src/declassification.rs`
- Create `crates/core/chio-core-types/src/declassification.rs`
- Create `chio-flow/src/declassification.rs`
- Modify `crates/kernel/chio-kernel/src/runtime.rs` and its wire-facing request conversions

**Work**

- Put the portable `DeclassificationGrantBody` in `chio-security-types`. Put `SignedDeclassificationGrant`, which uses Chio `PublicKey`, `Signature`, and `SigningAlgorithm`, in `chio-core-types`. This preserves the dependency direction `chio-core-types -> chio-security-types` and avoids inventing a second cryptographic envelope.
- Add an optional grant to `ToolCallRequest` and the generated wire schema.
- Sign and verify with Chio canonical JSON plus `chio:declassification-grant:v1` domain separation.
- Recompute the canonical request hash and source-label hash inside the verifier.
- Validate capability, tenant, subject, agent, session, destination, the intersection of policy and manifest purposes, times, target label, and trusted authority. A valid downgrade requires `target.flows_to(source)` and rejects an equal target as a no-op grant.
- Consume the grant atomically only after every static binding validates and immediately before returning an allow decision.
- Persist a consumed-but-dispatch-failed outcome separately from successful release.
- Apply the target only to the signed request payload. Never lower principal, lineage, or session taint.

**Exact tests**

- Success for the exact signed request.
- Replay, request mutation, destination mutation, purpose mutation, subject mutation, session mutation, expired grant, not-yet-valid grant, untrusted key, invalid signature, source hash mutation, target mutation, and store outage all deny.
- `Top` cannot be declassified.
- Two concurrent requests with one grant produce exactly one successful consumption.
- A consumed grant remains consumed after simulated dispatch failure.

**Commands**

- `cargo test -p chio-flow declassification`
- `cargo test -p chio-kernel declassification`

## Phase 5: Kernel adapters and composition

### Task 5.1: Implement adapters against current hook APIs

**Files**

- Create `chio-security-kernel/src/pre_invocation.rs`
- Create `chio-security-kernel/src/post_invocation.rs`
- Create `chio-security-kernel/src/tripwire.rs`
- Create `chio-security-kernel/src/containment.rs`
- Modify `crates/kernel/chio-kernel/src/kernel/mod.rs`
- Modify `crates/kernel/chio-kernel/src/post_invocation.rs`
- Modify `crates/kernel/chio-kernel/src/kernel/dispatch.rs`
- Modify `crates/kernel/chio-kernel/src/kernel/responses.rs`
- Modify the session-backed calls in `crates/kernel/chio-kernel/src/kernel/evaluation.rs`

**Work**

- `FlowPreInvocationGuard` implements `chio_kernel::Guard::name` and `evaluate`.
- `FlowPostInvocationHook` implements the existing hook API, but evidence attribution is keyed by request id or returned atomically with the verdict through a backward-compatible pipeline extension. It must not use one shared `take_evidence()` slot that concurrent requests can interchange.
- Add a versioned optional `SecurityInvocationContext` accessed through constructors and accessors on `GuardContext` and `PostInvocationContext`, containing authoritative tenant, session, subject, isolation epoch, lineage root, and context generation. Because these structs are public and literal-constructed, treat this as an API migration: enumerate and update every in-tree constructor, add a deprecation window for downstream literals where feasible, and never claim field addition is source-compatible. Enforce mode denies missing context rather than trusting request fields.
- Treat `PostInvocationContext.agent_id` and `server_id` as optional typed ids. Synthetic context without a session is denied when enforcement is enabled.
- Return existing `PostInvocationVerdict::Allow` or `Block`; do not introduce a stale `Pass` variant.
- `TripwireGuard` and the raw-output watermark hook call `TripwireDetectorPort`, implemented with `chio-decoy`, and always deny a match before dispatch or delivery.
- `ContainmentGuard` checks active overlays before all ordinary guards and denies on overlay-store error when enabled.
- Adapters translate domain decisions to `GuardDecision` and `GuardEvidence`; engines never import those kernel types.

**Exact tests**

- Trait conformance compiles against the current kernel API.
- Synthetic post-invocation context blocks under enforcement.
- Every flow-domain error becomes deny or block.
- Tripwire and containment guards never dispatch in the fake-server integration harness.
- Event persistence failure preserves tripwire deny.
- Overlay lookup failure preserves containment deny.

### Task 5.2: Centralize installation across every kernel constructor

**Files**

- Create `crates/platform/chio-control-plane/src/security/mod.rs`
- Create `crates/platform/chio-control-plane/src/security/adapters.rs`
- Modify `crates/platform/chio-control-plane/src/policy.rs`
- Modify `crates/platform/chio-control-plane/src/lib.rs`
- Modify `crates/kernel/chio-runtime-harness/src/kernel.rs`
- Modify `crates/platform/chio-http-core/src/authority.rs`
- Modify `crates/products/chio-cli/src/cli/mcp/wrap.rs`
- Audit every remaining non-test `ChioKernel::new` call returned by `rg "ChioKernel::new" crates`

**Registration order**

1. `TripwireGuard`
2. `ContainmentGuard`
3. `FlowPreInvocationGuard`
4. existing default runtime guard profile
5. configured `GuardPipeline`

For post-invocation, the watermark tripwire hook sees the raw response first, existing redaction and sanitizer hooks run next, and `FlowPostInvocationHook` runs last so it classifies and persists the final representation immediately before delivery. A block at any stage prevents delivery. Add an integration test that fixes this exact order and proves that removed secret bytes do not taint the delivered representation while the signed manifest's output label still applies.

**Configuration**

- Add `active_defense.mode = disabled | shadow | enforce`.
- Require a persistent security database and verified manifest registry for `enforce`.
- Refuse startup when enforcement is configured with ephemeral flow, declassification, decoy, event, response, or overlay stores.
- Add one shared security-installation helper that receives a fully constructed `SecurityRuntime` and installs the exact guard and hook order. `build_kernel` and every enforcement-capable constructor call it. A constructor that cannot supply persistent stores, verified v2 manifest registry, policy, and topology rejects `flow_v1` rather than returning an unprotected kernel. Disabled mode installs nothing.

**Exact tests**

- Disabled mode preserves the existing guard and receipt bytes.
- Shadow mode emits decisions but does not alter calls.
- Enforce mode refuses ephemeral stores.
- Guard order is exact and tripwire wins over later allows.
- Runtime harness, HTTP authority, CLI MCP wrapping, and every remaining direct constructor either install the same security runtime or reject a flow-required manifest.
- `cargo tree -i chio-flow` shows no path from kernel or guards to flow.

**Commands**

- `cargo test -p chio-control-plane security`
- `bash scripts/check-security-dependencies.sh`

## Phase 6: Deception and tripwire detection

### Task 6.1: Implement the private registry and lifecycle

**Files**

- Create `chio-security-types/src/deception.rs`
- Create `chio-decoy/src/registry.rs`
- Create `chio-decoy/src/lifecycle.rs`
- Create `chio-decoy/src/materialize.rs`
- Create `chio-decoy/src/matcher.rs`

**Work**

- Support canary capability, honey tool, credential-shaped file, cookie-shaped value, internal hostname, and watermark surfaces.
- Implement the lifecycle and compare-and-swap transitions from the design.
- Materialize files only beneath an operator-configured root using safe relative components, create-new semantics, restrictive permissions, and content digests.
- Refuse overwrite, symlink escape, parent traversal, absolute paths, and cleanup when ownership or digest differs.
- Arm a rotated replacement before retiring the previous version.
- Store raw markers and materialization payloads only in encrypted blobs.

**Exact tests**

- Lifecycle accepts every legal edge and rejects every illegal edge.
- Materialization is idempotent for the same operation id.
- Existing file, symlink, parent traversal, absolute path, and changed-content cleanup all fail.
- Rotation never leaves a window with no armed version.
- Tenant boundaries and privileged registry export are enforced.
- Scanner and operator-touch fixtures demonstrate that a tripwire is high confidence but not treated as mathematical proof of malice.

### Task 6.2: Implement signed watermark envelopes

**Files**

- Create `chio-decoy/src/watermark.rs`
- Add canonical vectors under `crates/tooling/chio-conformance/vectors/security/watermark/`

**Work**

- Bind every payload field listed in the design, using the public opaque `marker_ref` rather than the private registry id.
- Verify the canonical payload bytes equal the decoded payload before signature validation.
- Require a trusted key id with active or configured overlap status.
- Enforce expiry and registry lifecycle.
- Deduplicate observations without losing the first evidence reference.
- Never include the signing seed or raw private registry entry in serialized config.

**Exact tests**

- Valid extraction, payload tamper, encoded-data mismatch, signature tamper, untrusted key, expired marker, retired marker, sequence replay, observation dedupe, active key, overlap key, and rejected old key.
- Cross-language canonical vector verification.

### Task 6.3: Prove tripwire-before-execution

**Files**

- Add `crates/kernel/chio-kernel/tests/active_defense_tripwire.rs`
- Add adversarial fixtures under `crates/core/chio-adversarial-suite/cases/canary_evasion/`

**Exact tests**

- Valid canary capability is denied and fake server invocation count remains zero.
- Honey tool name is denied and invocation count remains zero.
- Event-store outage still leaves invocation count zero and receipt evidence records the outage.
- Near-match and retired marker do not auto-contain, but produce configured observation behavior.
- Marker leakage through output is blocked before response delivery.

## Phase 7: Deterministic temporal detection

### Task 7.1: Implement rule parsing and validation

**Files**

- Create `chio-security-types/src/event.rs`
- Add the Chio-signed event envelope in `crates/core/chio-core-types/src/receipt/` or a focused sibling module
- Create `chio-quarantine/src/rules.rs`
- Add policy configuration to `chio-control-plane/src/policy.rs`

**Work**

- Adapt Clawdstrike `hunt-correlate` ordered-stage semantics to Chio event fields.
- Define `SecurityEventBody`, `SignedSecurityEvent`, `VerifiedSecurityEvent`, producer id/key, trust class, and receipt-backed provenance. Verify signature or source receipt, tenant, producer policy, freshness, and event-time bounds before correlation.
- Only configured internal detector trust classes can yield an automatic-response finding. External SIEM imports and unsigned observations are stored in an advisory partition that can alert but cannot execute containment.
- Require each non-first stage to name a prior stage with `after` and a positive bounded `within` duration.
- Require an explicit grouping key and policy version.
- Reject cycles, unknown stages and fields, zero or excessive windows, ambiguous duplicate names, unbounded regexes, and rules whose state estimate exceeds configured tenant limits.

**Exact tests**

- Valid two-stage and multi-stage rules.
- Forged, unsigned, untrusted-producer, cross-tenant, stale, future-dated, and invalid-receipt events cannot enter automatic correlation.
- Unknown `after`, forward reference, cycle, missing window, zero window, overflow duration, invalid field, duplicate stage, and excessive-state rules reject at load time.
- Parse then serialize then parse preserves canonical rule bytes.

### Task 7.2: Implement event-time correlation

**Files**

- Create `chio-quarantine/src/correlation.rs`

**Work**

- Accept only `VerifiedSecurityEvent` for automatic-response partitions; advisory partitions have no response executor route.
- Partition by tenant, rule, and configured group key.
- Deduplicate event ids.
- Track event time separately from ingest time.
- Accept bounded lateness, advance a deterministic watermark, and evict partials only when they can no longer match.
- Persist partial matches and watermark transactionally.
- Compute finding ids from rule version, group hash, ordered event ids, and evidence digests.
- On overflow or store failure emit detector-health evidence and suppress heavy automatic response for that partition.

**Exact tests**

- In-order match, bounded out-of-order match, too-late rejection, exact-window boundary, duplicate event, unrelated group, eviction, restart recovery, state cap, and store failure.
- Replaying the same corpus after restart yields the identical finding id once.
- Permuting ingest order within allowed lateness yields the same ordered contributing event ids.
- A single event cannot satisfy two ordered stages unless the rule explicitly allows reuse.

**Commands**

- `cargo test -p chio-quarantine correlation`

## Phase 8: Causal scope and durable response

### Task 8.1: Resolve and freeze exact affected sets

**Files**

- Create `chio-quarantine/src/blast.rs`
- Extend `crates/platform/chio-store-sqlite/src/capability_lineage.rs` with a bounded descendant query if the current upward-only delegation query cannot supply it
- Reuse truncation semantics from `chio-lineage::query`

**Work**

- Run this task only for plans containing `SuspendCapabilitySet` or `FreezeIssuance`. Session-local throttle, egress restriction, and suspension bind an exact session and do not acquire a lineage fence.
- Resolve descendants from an authoritative capability and receipt-lineage snapshot at a committed index without retaining a fence while approval is pending.
- Return sorted unique targets, graph-slice digest, query bounds, source lineage version, and commit index.
- Return `Incomplete` on any truncation, replica lag, missing completeness watermark, missing seed, corrupt edge, cross-tenant edge, or store failure.
- Bind the exact provisional set, digest, and lineage index in the plan before approval.
- Require `FreezeIssuance` to be the first ordered effect in every lineage-scoped plan before hashing or approval; the executor cannot inject it after approval.
- After approval, persist deterministic fence-acquisition intent, acquire a bounded issuance-and-delegation fence lease by action id, and re-query under the fence. Require the same commit index and affected-set hash; any change releases the lease, invalidates approvals, and requires a new plan.
- Persist the acquired lease as the first `FreezeIssuance` effect and renew it only under the response scheduler's fencing token. Recovery queries by action and lease id if acquisition may have preceded effect persistence. A bounded orphan expires automatically.
- Keep issuance and delegation frozen until all other containment contributions lift. Do not re-query on lift. Pre-approval cancellation, expiry, or failure owns no fence.

**Exact tests**

- Exact chain, branch, cycle, duplicate edge, cross-tenant edge, missing seed, depth truncation, row truncation, replica lag, absent completeness watermark, corrupt edge, and concurrent new descendant.
- Truncated results never create an executable automatic plan.
- Delegation attempted under the application fence fails. A descendant committed before fence acquisition changes the set and invalidates the plan and all approvals.
- Cancellation, expiry, and failure before apply leave no live fence. Crash after fence acquisition and before effect persistence is recovered by deterministic id or expires at the bounded lease deadline.

### Task 8.2: Implement plan approvals

**Cross-arc prerequisite**

The protocol-primitives plan must first ship threshold governed-approval set verification with distinct signer enforcement, operator-capability proposal binding, a generic approval-only `AdmissionOperation`, and atomic replay reservation. Before that prerequisite passes its conformance tests, every approval-requiring response plan remains dry-run, including one-approver policy. No legacy single-token execution exception and no local threshold verifier are permitted.

**Files**

- Create `chio-quarantine/src/approval.rs`
- Integrate the protocol-primitives governed approval-set API in `chio-quarantine`; do not introduce or extend a second signature envelope here

**Work**

- Require a Chio operator capability whose subject equals the executor and whose existing tool scope grants every proposed effect on internal server `chio.control-plane.active-response`, using the closed logical tool names `throttle_session`, `restrict_egress`, `suspend_session`, `suspend_capability_set`, and `freeze_issuance`. Put its id, canonical digest, and expiry in the complete response plan and domain `chio:response-plan:v1`.
- Require that capability for auto-reversible plans as well as heavy plans. A zero-human-vote policy does not remove executor authorization.
- Compute the existing `GovernedTransactionIntent::binding_hash()` over that intent. Bind each `GovernedApprovalToken.governed_intent_hash` to the resulting binding hash and `request_id` to `action_id`; do not substitute a separately computed arbitrary hash into the verifier.
- Require the policy-authority-signed threshold proposal to bind the operator-capability digest and set its deadline no later than capability and plan expiry.
- Before replay reservation, persist a generic `AdmissionOperation` of kind `GovernedActiveResponse` whose id binds executor authority, action id, capability digest, and governed intent hash. Budget and execution-nonce participants are absent.
- Delegate trusted approver roles, m-of-n distinct keys, token validity, approved decision, atomic replay reservation, dispatch commitment, and crash recovery to the shared governed approval verifier and coordinator through `ApprovalVerifierPort`. Enforce submitter separation as response-plan policy before execution.
- Recompute capability validity and the complete governed intent binding hash at execution time. For a lineage-scoped plan, also acquire and verify the application fence and approved affected-set hash before effects.

**Exact tests**

- Valid quorum.
- Duplicate key, duplicate token, submitter approval, untrusted role, denied token, expired token, future token, replay, wrong action id, wrong subject, wrong or revoked operator capability, capability expiry beyond proposal deadline, and every individual plan-field mutation reject.
- Approval remains invalid if effects are reordered.
- Crash after approval reservation or dispatch commitment recovers the same operation id and cannot apply twice.

### Task 8.3: Implement the response state machine

**Files**

- Create `chio-security-types/src/response.rs`
- Create `chio-quarantine/src/state_machine.rs`

**Work**

- Implement only the transitions in the design diagram.
- Require expected generation on every transition.
- Derive stable transition ids and effect ids from canonical inputs.
- Record requested, applied, failed, rollback, and final states separately.
- `applying` lease timeout transitions to partial apply and rollback.
- `active` TTL transitions to expiring and rollback.
- Rollback failure remains restrictive and pages; it cannot transition to lifted.

**Exact tests**

- Table-driven test for every legal transition.
- Every unlisted transition rejects.
- `failed` rejects after any effect has applied; the same input transitions to `apply_partial`.
- Duplicate transition is idempotent.
- Stale generation conflicts.
- Applying timeout, active expiry, cancellation before apply, partial apply, full rollback, and partial rollback.
- Property test that `lifted` implies every applied reversible effect has a successful restore record.
- Property test that permanent revocation never appears in a reversible plan.

### Task 8.4: Implement effect execution and rollback

**Files**

- Create `chio-quarantine/src/executor.rs`
- Create `chio-control-plane/src/security/adapters.rs`

**Concrete adapters**

- Temporary deny and egress restrictions as effect-ID-keyed `ContainmentOverlayStore` contributions.
- Throttle overrides as composable contributions around `AgentVelocityGuard`, never as blind restoration of one prior value.
- Issuance and delegation freeze as a commit-indexed reversible fence, not irreversible revocation.
- Alert through `chio-siem`.
- Exact blast resolution through `chio-lineage` and SQLite lineage.
- Receipt signing through existing Chio receipt machinery.

**Work**

- Persist effect intent before external mutation.
- For a lineage-scoped plan, persist the lineage-fence acquisition intent before calling its authority. Promote the acquired bounded lease to the first recorded effect before applying any other lineage-scoped effect. Do not add an implicit heavy fence to a session-local auto-reversible plan.
- Pass effect id, expected target version, and current scheduler fencing token to every port call.
- Persist the contribution and observed result after each call. Effective posture is recomputed from base policy plus all active contributions.
- On failure, stop forward application and remove the successfully applied prefix in reverse order. Removing one contribution must retain every overlapping restriction.
- For a non-composable external effect, serialize by target and use compare-and-swap restore only when current state still matches the version installed by that effect. Conflict retains the restrictive state and escalates.
- Do not call the revocation oracle for temporary actions.

**Exact crash matrix**

For each effect type, terminate and restart at these points:

1. before intent persistence;
2. after intent persistence and before port call;
3. after port call and before result persistence;
4. after result persistence and before next effect;
5. during rollback before port call;
6. after restore and before rollback-result persistence.

Every case must converge without duplicate external mutation, false success, or loss of the restrictive overlay.

Add overlapping-plan tests in which two restrictions on the same target expire in both possible orders. The target remains at the most restrictive posture until the last contribution is removed.

## Phase 9: Durable TTL scheduler and posture transitions

### Task 9.1: Implement scheduler leasing

**Files**

- Create `chio-quarantine/src/scheduler.rs`
- Create `chio-control-plane/src/security/scheduler.rs`

**Work**

- Persist `due_at`, lease owner, lease expiry, monotonically increasing fencing token, attempts, and last error.
- Claim due actions transactionally in deterministic order.
- Renew leases only while work is active.
- Use the state-machine transition id as the retry idempotency key and pass the lease fencing token to every effect and restore call. Ports reject stale tokens after takeover.
- Exponential backoff is bounded below the operator page threshold.
- A failed rollback moves to `rollback_partial`, retains restrictive posture, and pages immediately.
- On clean shutdown release leases; after crash allow lease expiry and takeover.

**Exact tests**

- Fake-clock tests for exact TTL boundary, early tick, delayed tick, clock rollback, and large forward jump.
- Two-worker contention and lease takeover.
- A paused old worker resuming after takeover cannot apply or remove an effect with its stale fencing token.
- Restart during apply and rollback.
- Repeated port outage never reports lifted.
- Successful retry removes only its own contribution and recomputes exact effective posture.

### Task 9.2: Verify posture enforcement

**Files**

- Add `crates/kernel/chio-kernel/tests/active_defense_containment.rs`
- Add `crates/platform/chio-control-plane/tests/active_defense_recovery.rs`

**Exact tests**

- Normal to restricted to normal at TTL.
- Normal to quarantined to rollback-partial remains denied.
- Overlapping temporary actions may expire out of order; each removal preserves every remaining contribution.
- Exact subtree effects all lift, including descendants; the root is not the only restored target.
- Store outage while an overlay may be active denies.
- Planner outage with no active overlay leaves existing preventive guards functional.

## Phase 10: Receipts, conformance, and adversarial evidence

### Task 10.1: Add truthful receipt bodies

**Files**

- Modify `crates/core/chio-core-types/src/receipt/kinds.rs`
- Add bodies under `crates/core/chio-core-types/src/receipt/`
- Modify `chio-lineage` ingestion and `chio-siem` mappings

**Work**

- Add the receipt bodies listed in the design.
- Domain-separate every independently signed body.
- Bind response receipts to plan, finding, exact affected-set hash, effects, transitions, and prior receipt ids.
- Keep raw payloads, markers, credentials, and rollback material out of receipts.
- Map boundary guard denies to mediated decisions and off-boundary observations to the correct existing semantic class.

**Exact tests**

- Canonical golden vectors.
- Signature tamper for every body field.
- Partial apply cannot validate as complete.
- Partial rollback cannot validate as lifted.
- Raw marker and fixture secret scanner finds no value in receipt JSON.
- Lineage links every transition to its plan and trigger.

### Task 10.2: Add conformance and adversarial cases

**Files**

- Extend existing files under `crates/tooling/chio-conformance/tests/threats/`
- Add adversarial cases under `crates/core/chio-adversarial-suite/cases/label_downgrade/`, `canary_evasion/`, `temporal_evasion/`, and `containment_rollback/`
- Update adversarial manifest and arena registration

**Required conformance cases**

- Slow cumulative exfiltration is denied after taint accumulation.
- PII and PHI classifications survive adapter round trips and deny insufficient clearance.
- Stolen canary is denied before execution.
- Sequence events outside `within` do not match; inside do match deterministically.
- One-shot declassification cannot replay.
- Replacing a session without a verified isolation-epoch transition preserves principal and lineage taint.
- Unsigned, externally sourced, stale, and untrusted-producer events cannot trigger automatic containment.
- Truncated lineage cannot auto-contain.
- Overlapping TTL effects may lift out of order without removing any remaining restrictive contribution.
- Partial rollback stays restrictive and attested.

**Mutation gate**

- Seed mutants for reader subset direction, missing-clearance allow, ignored store error, grant replay, tripwire after dispatch, event-time versus ingest-time, truncation ignored, approval plan-field omission, root-only lift, and false lifted status.
- Require each mutant to be caught before proposing a threat-row state change.

**Commands**

- `cargo test -p chio-conformance --test threats`
- `cargo test -p chio-adversarial-suite`
- `bash scripts/check-threat-coverage-mutants.sh`

## Phase 11: Behavioral CI gates and rollout

### Task 11.1: Add executable gates

**Files**

- Create `scripts/check-flow-security.sh`
- Create `scripts/check-deception-security.sh`
- Create `scripts/check-response-recovery.sh`
- Add corresponding script self-tests
- Modify the applicable CI workflow

**Gate contents**

- `check-flow-security`: lattice properties and registered Apalache models, no-default portable build, strict v2 manifest and adapter vectors, policy-owned clearance, principal/session inheritance, context-generation fence, fail-closed matrix, and declassification replay race.
- `check-deception-security`: lifecycle safety, watermark trust/expiry, tripwire fake-server invocation count, registry secret scan.
- `check-response-recovery`: authoritative application-time fenced lineage, orphan-fence expiry/recovery, operator-capability and approval mutation matrix, approval-only admission recovery, full effect crash matrix, overlapping out-of-order TTL removal, stale-worker fencing, and receipt truthfulness.
- All scripts fail if a required test filter matches zero tests.

### Task 11.2: Shadow migration

**Files**

- Add migration command to the existing Chio CLI surface rather than a standalone unowned binary
- Add operator documentation under `docs/security/active-defense-rollout.md`

**Work**

- Inventory and migrate all signed manifests, requiring re-signing after canonical shape changes.
- Produce a report listing every egress tool without clearance and every adapter unable to preserve a declaration.
- Backfill principal, capability-lineage, and session state only from verified receipt and v2 manifest evidence. Unknown history becomes `Top`, not `Bottom`; closing a legacy session does not erase principal knowledge.
- Run shadow classification and correlation with metrics for unknown labels, store errors, late events, state evictions, decoy touches, lineage truncation, proposed effects, rollback simulation, and false-positive review.
- Define numeric promotion thresholds in the operator document before enforce mode. Do not hard-code unreviewed thresholds in this plan.

### Task 11.3: Enforce and close evidence

**Promotion sequence**

1. Enforce flow for explicit `flow_v1` policy only on re-signed `chio.manifest.v2` tools and constructors that installed `SecurityRuntime`.
2. Require declarations on new egress manifests.
3. Arm production-specific decoys for selected tenants.
4. Enable dry-run response plans.
5. Enable `ThrottleSession` and `RestrictEgress` automatic actions.
6. Enable suspension and issuance freeze only after crash and rollback evidence is accepted.
7. Keep permanent revocation manual.

**Rollback sequence**

- Stop new planning and correlation consumption.
- Let active actions lift or explicitly lift them using the durable scheduler.
- Verify no active or rollback-partial overlays remain.
- Unregister runtime adapters only after that check.
- Retain signed receipts, taint, event, decoy, and response history.

## Final verification

Run from the repository root after every phase-specific gate passes:

```bash
bash scripts/check-security-provenance.sh
bash scripts/check-security-dependencies.sh
bash scripts/check-flow-security.sh
bash scripts/check-deception-security.sh
bash scripts/check-response-recovery.sh
make codegen-check
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
./scripts/check-formal-proofs.sh
git diff --check
```

Before marking the arc complete, re-run `rg "ToolDefinition \\{" crates sdks`, verify every constructor sets or deliberately omits `flow`, audit every non-test `ChioKernel::new`, inspect `cargo metadata` for forbidden dependency paths, confirm the lattice models are in the normal Apalache workflow, and confirm the working tree contains no generated drift.

## Completion criteria

This plan is complete only when all of these statements are supported by executable evidence:

- the DLM is a canonical partial order with a verified least-upper-bound join;
- unknown security state cannot authorize egress;
- publisher metadata cannot widen operator clearance or hide runtime egress, and strict v2 metadata survives supported bridges;
- principal and lineage taint survive session replacement unless an attested isolation epoch proves destruction;
- egress admission is fenced against concurrent taint generation changes through dispatch commitment;
- declassification is typed, one-shot, exact-request, exact-destination, and exact-purpose bound;
- canary and watermark matches deny before dispatch or response delivery;
- temporal findings are deterministic under bounded out-of-order delivery and only verified internal events can trigger automatic response;
- lineage-scoped automatic containment uses a complete, commit-indexed affected set under an issuance and delegation fence, while session-local actions acquire no implicit heavy fence;
- approvals bind a verified operator capability, canonical governed response-plan intent containing every executable action field, and the shared approval-only admission operation;
- crashes, retries, stale workers, overlapping TTL expiry, and partial failures preserve truthful state and every remaining restrictive contribution;
- no temporary action is implemented with irreversible revocation;
- every receipt says what actually happened;
- threat-coverage claims remain gated by conformance and caught-mutant evidence.
