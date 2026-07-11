# Design: Chio active defense and information-flow security

- Status: REVIEWED DESIGN, implementation not started
- Date: 2026-07-09
- Revised: 2026-07-10 after comparison with Clawdstrike
- Scope: information-flow control, deception, temporal detection, and reversible containment
- Normative companions: `spec/PROTOCOL.md`, `spec/SECURITY.md`, `spec/GUARDS.md`, and `docs/security/threat-coverage.md`

## 1. Decision

Chio will add active defense without creating a dependency cycle or a second security runtime inside the kernel. Pure domain types and store ports will live below the kernel. A small adapter crate will implement the existing `chio_kernel::Guard` and `chio_kernel::PostInvocationHook` traits. Concrete SQLite store implementations live in `chio-store-sqlite`; the platform bootstrap constructs a `SecurityRuntime` and installs it through a shared kernel-construction helper. `chio-control-plane::build_kernel` is one production caller, not the only constructor in the repository. Every alternate constructor must use the same helper or reject manifests that require active-defense enforcement. `chio-guards` and `chio-kernel` do not depend on any active-defense engine.

The implementation consists of five crates under `crates/security/`:

| Crate | Responsibility | May depend on `chio-kernel` | TCB status |
|---|---|---:|---|
| `chio-security-types` | Portable wire/domain types and port traits | No | Types only |
| `chio-flow` | DLM algebra, taint transitions, declassification verification | No | Pure decision engine |
| `chio-security-kernel` | Flow, deception, and containment adapters for existing kernel hooks | Yes | Enforcement adapter |
| `chio-decoy` | Signed watermarks, private decoy registry, lifecycle, matching | No | Detection engine |
| `chio-quarantine` | Temporal correlation and durable response state machine | No | Planner and executor, not prevention TCB |

Concrete implementations of the persistence ports belong in `chio-store-sqlite`. Lineage, issuance, velocity, receipt, and SIEM adapters belong in `chio-control-plane`, which constructs and composes all implementations. This keeps trust and observability crates from depending upward on security engines and keeps persistence logic out of the composition root.

## 2. Corrected baseline

The design builds on these current facts:

- `chio-kernel` owns `Guard`, `PostInvocationHook`, `PostInvocationContext`, and `PostInvocationPipeline`.
- `chio-guards` depends on `chio-kernel` and reexports post-invocation types. The kernel intentionally does not depend on `chio-guards`.
- `chio-control-plane::build_kernel` registers the default guard profile, configured guard pipeline, and post-invocation pipeline, but `chio-runtime-harness`, `chio-http-core`, and CLI paths also construct kernels directly. Active-defense enforcement must centralize construction or make those paths reject `flow_v1`.
- Session-backed evaluation already threads an authoritative `SessionId` and resolves tenant identity from session authentication, but `GuardContext` and `PostInvocationContext` do not expose them. Both are public literal-constructed structs, so adding fields is a breaking API migration. The implementation must use a versioned nested context or enumerate and migrate every constructor. It must never trust a session or tenant supplied inside `ToolCallRequest`.
- Chio has two public `ToolDefinition` structs: the protocol type in `chio-core-types`, which is embedded in signed manifests, and an operational type in `chio-manifest`. Security metadata cannot be added independently to both.
- `chio-lineage` queries are bounded and explicitly report truncation. A truncated graph is not an exact blast radius.
- `chio-revocation-oracle` is insert-only. It cannot implement reversible quarantine. Temporary containment therefore uses a separate deny-overlay store rather than pretending revocation can be lifted.
- Existing `GovernedApprovalToken` binds a signed approval to a subject, request, intent hash, decision, and validity window. Active response consumes the shared protocol-primitives threshold governed-approval set once available rather than extending approvals privately inside `chio-quarantine`.

## 3. Security properties

The release must establish all of the following properties:

1. **No dependency cycle.** Neither `chio-kernel` nor `chio-guards` depends on `chio-flow`, `chio-decoy`, or `chio-quarantine`.
2. **Flow failures deny.** Unknown labels, missing egress clearance, classifier errors, taint-store errors, malformed label declarations, and declassification-store errors deny the affected invocation or block the affected output.
3. **No implicit downgrade.** A label can become less restrictive only through a valid, one-shot, destination-bound and purpose-bound declassification grant.
4. **Tripwire before execution.** A recognized canary capability or honey-tool call is denied before tool-server dispatch. Failure to persist the detection never turns the denial into an allow.
5. **Private deception state.** Public bait may be visible by design, but registry membership, raw marker values, honey credentials, materialization payloads, private artifact ids, and lifecycle internals are not exposed through ordinary tool discovery, receipts, logs, or operator APIs.
6. **Policy-owned clearance.** A tool publisher may request a narrower label or declare a boundary, but only tenant or data-owner policy can authorize clearance. Runtime topology can force egress even when the manifest says otherwise.
7. **Durable knowledge tracking.** Starting a new session does not clear knowledge held by the same agent principal or capability lineage. Reset requires a separately attested isolation boundary.
8. **Exact containment.** A response plan binds a provisional sorted set from an authoritative lineage snapshot. Immediately before lineage-scoped effects, issuance and delegation are fenced and the exact set is recomputed; only an identical set may execute. Truncated, stale, or changed lineage cannot auto-contain.
9. **Durable reversibility.** Temporary restrictions are effect-keyed contributions. Removing one contribution recomputes posture from all remaining effects and cannot erase an overlapping restriction.
10. **Action-bound approval.** Every heavy action is encoded as a governed response-plan intent whose existing binding hash commits to affected-set hash, effect types, TTL, tenant, policy version, and action id.
11. **Verified event authority.** Only events from configured internal detector keys or verified Chio receipts may trigger automatic response. Unsigned and external events remain advisory.
12. **Deterministic correlation.** Event-time evaluation, deduplication, bounded lateness, and eviction produce the same finding for the same ordered input corpus.
13. **Receipt truthfulness.** Signed receipts describe requested, applied, failed, and rolled-back effects separately. A partial execution cannot be represented as success.

## 4. Dependency topology

The allowed dependency graph is:

```text
chio-security-types
    ^          ^            ^
    |          |            |
chio-flow  chio-decoy  chio-quarantine
    ^                       ^
    |                       |
chio-security-kernel        |
    ^                       |
    +----------+------------+
               |
       chio-control-plane
          /      |       \             \
 chio-kernel  chio-guards  trust adapters  chio-store-sqlite
```

`chio-security-types` is `no_std + alloc` by default and depends only on portable serialization and hashing dependencies already accepted by `chio-core-types`. Hosted store traits are behind its `std` feature. `chio-core-types` depends on it for labels, declarations, and portable signed-body shapes; Chio `PublicKey`, `Signature`, and `SigningAlgorithm` wrappers remain in `chio-core-types`, so no reverse dependency is needed. `chio-security-kernel` may depend on `chio-flow`, `chio-decoy`, and `chio-kernel`, but not on `chio-guards` or platform crates. Classification and persistence enter through typed ports. Platform bootstrap owns all cross-domain wiring.

## 5. Canonical DLM lattice

### 5.1 Representation

`InformationLabel` has two canonical forms:

- `Known { owners, compartments }`
- `Top`

`owners` is a `BTreeMap<PrincipalId, BTreeSet<PrincipalId>>`. There is exactly one reader set per owner. A missing owner means that owner imposes no restriction, equivalent to the universal reader set. Every stored reader set must contain its owner. `compartments` is a sorted set of validated, non-empty identifiers. Duplicate owner policies, blank identifiers, non-canonical identifiers, and reader sets that omit their owner are rejected at deserialization or construction.

`Known` with empty owners and compartments is `Bottom`, the public label. `Top` is the unknown or overflow state and is maximally restrictive. It is a real lattice element, not a substitute for missing configuration.

### 5.2 Order

For known labels `A` and `B`, `A flows_to B` if and only if:

- every compartment in `A` is present in `B`; and
- for each owner constrained by `A`, `B` also constrains that owner and `readers(B, owner)` is a subset of `readers(A, owner)`.

Owners present only in `B` add restrictions and do not prevent the flow. Every known label flows to `Top`; `Top` flows only to `Top`. With canonical maps this relation is reflexive, antisymmetric, and transitive.

### 5.3 Join

The join of known labels unions compartments and owner keys. For an owner present in both labels, join intersects the reader sets. For an owner present in only one label, join retains that reader set because the other label contributes the universal set. A join involving `Top` is `Top`.

The implementation must demonstrate that `join(A, B)` is the least upper bound: both operands flow to the join, and the join flows to every common upper bound.

### 5.4 Operational handling of `Top`

Mathematical `Top flows_to Top` is required for a valid lattice. Runtime egress is stricter: data labeled `Top` or data whose classification is unknown is never released, even to a `Top` clearance. Missing clearance is a configuration error and denies. Declassification from `Top` is forbidden. This explicit operational rule prevents the common error where resolving unknown data and missing clearance to the same element accidentally allows egress.

### 5.5 Principal, lineage, and session taint

Knowledge is tracked at two levels. Durable principal taint is keyed by `(tenant_id, subject_fingerprint, isolation_epoch)` and is also indexed by capability-lineage root. Session taint is keyed by `(tenant_id, subject_fingerprint, isolation_epoch, session_id)` and begins at the join of the applicable principal and lineage labels. Closing or replacing a session does not lower either durable label.

An isolation epoch changes only after a trusted launcher or attestation verifier proves that the old agent process, model context, writable memory, and inherited state were destroyed and that the new subject cannot read them. Without that evidence, a new session inherits the prior principal taint. Administrative retention expiry may archive records but cannot silently reinterpret retained agent knowledge as `Bottom`.

The raw-output tripwire runs first, existing sanitizers and redactors produce the effective response next, and the flow adapter then classifies that effective response, joins operator and signed-manifest output floors, and atomically joins the result into session, principal, and lineage state before delivery. Removed secret bytes do not taint the delivered representation solely because they existed before redaction, but declared and policy floors still apply. Cardinality overflow transitions every affected label to `Top`.

Each state record has a monotonic generation. Pre-invocation egress obtains an admission fence over the authoritative session context generation and keeps it valid through the dispatch commitment boundary. If output delivery advances taint or context generation before dispatch, the fence fails and the kernel re-evaluates or denies. Taint advancement happens before the corresponding output becomes observable to the agent. A failed classification, read, fence, or write denies or blocks.

For every pre-invocation call, the source label is the join of the classified request payload, applicable operator input floor, durable principal taint, capability-lineage taint, and current session taint. The flow decision compares that complete source label with every effective destination clearance. A payload that does not itself contain a recognizable secret is still treated as derived from everything the agent can know. A valid declassification grant replaces only this exact request's source label with its signed target for the named destination and purpose; it does not change any durable taint record.

## 6. Manifest security contract

The signed `chio_core_types::manifest::ToolDefinition` becomes the sole normative tool definition. `chio-manifest` will reexport and validate that type instead of maintaining a divergent public struct. Every normative nested type gains `deny_unknown_fields` before the platform duplicate is removed. The migration introduces `chio.manifest.v2`; a version-dispatched v1 parser converts the legacy shape and requires the operator to re-sign the v2 manifest. The migration removes `has_side_effects` in favor of `ToolAnnotations.read_only`. It also makes categorical `latency_hint` the sole latency authority by moving `LatencyHint` to the normative type and removing `ToolAnnotations.estimated_duration_ms`. Legacy millisecond values map through fixed, tested thresholds; v2 never carries both representations.

Each tool may carry one optional `ToolFlowDeclaration`:

| Field | Meaning |
|---|---|
| `output_label` | Minimum label joined into every successful output |
| `input_clearance` | Maximum restriction accepted by this destination |
| `egress` | Whether arguments cross a trust or network boundary |
| `declassification_purposes` | Closed set of purposes this destination accepts |

The manifest is publisher-authenticated input, not authorization for the publisher to receive data. Runtime composition derives `runtime_egress` from transport and adapter topology. Effective egress is `runtime_egress OR manifest.egress`; a publisher cannot hide a boundary. Tenant or data-owner policy supplies one or more authoritative clearances, and the complete pre-invocation source label must flow to every applicable policy clearance and to the manifest clearance. The manifest can narrow acceptance but cannot widen policy. Declassification purposes are the intersection of policy and manifest purposes. Effective output sensitivity is the join of the operator floor, manifest floor, and classifier result.

The kernel consults only a successfully verified v2 manifest from the manifest registry plus an authenticated policy snapshot and runtime topology record. An adapter-provided or model-provided description is never authoritative. An effective egress destination without every required policy clearance denies. A non-egress tool may omit manifest clearance, but operator policy still applies. An absent manifest `output_label` contributes `Bottom`; it does not disable classification or the operator floor.

The migration must cover every constructor and protocol projection found by `rg "ToolDefinition \\{" crates sdks`. OpenAPI uses an `x-chio-flow` extension. MCP, A2A, ACP, OpenAI, and provider adapters retain the declaration in an internal `BridgeSecurityMetadata` sidecar when the external dialect cannot express it. Export code must never silently erase a declaration and then re-import the tool as unconstrained. The four-language wire codegen receives schemas for labels, declassification grants, security events, and response receipts, and `make codegen-check` is a required gate.

## 7. Typed declassification

Declassification is not encoded as a comma-separated caveat predicate. The Capability Authority issues a `SignedDeclassificationGrant` carried on the tool-call request. Its canonical body contains:

- grant id and domain version;
- capability id, tenant id, subject, agent id, and session id;
- hash of the exact source label and the complete target label;
- destination server id and tool name;
- one purpose selected from the destination manifest declaration;
- canonical request hash;
- issued-at and expires-at times;
- authority key id.

The signature uses canonical JSON and a dedicated domain-separation context. The flow adapter verifies the signature, trusted authority, time window, every identity binding, source-label hash, target-label validity, destination, effective policy-and-manifest purpose, and request hash. It then atomically consumes the grant id in `DeclassificationUseStore`. A grant is one-shot even when downstream dispatch later fails. Consumption and outcome are separately attested so an operator can distinguish an authorized release from a consumed-but-failed attempt. Declassification authorizes only the signed request payload; it never lowers durable principal, lineage, or session taint.

The target label must be demonstrably less restrictive than the source and must be exactly the signed target. In lattice terms, `target.flows_to(source)` must hold and equality is rejected as a no-op grant. Runtime callers cannot choose a different subset. No grant authorizes declassification of `Top`.

## 8. Deception model

### 8.1 Decoy surfaces

Supported surfaces are canary capabilities, honey tools, credential-shaped artifacts, files, browser-cookie-shaped values, internal hostnames, and signed text watermarks. Each artifact has a stable private id, tenant, scope, marker digest, creation policy, current version, expiry, and lifecycle state.

Deception detections are high-confidence signals, not zero-false-positive proofs. Inventory agents, backup software, scanners, operator mistakes, and test harnesses can touch a decoy. Policy may auto-contain only after the configured correlation and risk threshold. A direct canary presentation always denies before dispatch regardless of response policy.

### 8.2 Lifecycle and registry

The lifecycle is `planned -> materializing -> armed -> triggered -> rotating -> retired`, with `error` transitions that preserve the last known state and attempted operation. An operator may retry from `error` to the recorded prior operation or retire the artifact; no other recovery edge is legal. Materialization is idempotent and refuses to overwrite an existing path. File artifacts require safe relative paths, component-by-component containment checks, create-new semantics, restrictive permissions, and a content digest. Cleanup verifies registry ownership and digest before removal. Rotation arms the replacement before retiring the old marker.

The registry is encrypted at rest and excluded from normal receipt evidence. Receipts contain artifact id hashes and version hashes, never raw markers or honey credentials. Listing or exporting raw registry entries requires a separate privileged operator capability.

### 8.3 Signed watermark envelope

A watermark is a signed canonical envelope, not a deterministic hex substring. It binds tenant, application, session, source receipt, tool, sequence, issued-at, expires-at, a public opaque marker reference, key id, and encoding. The public reference is distinct from the private registry id and reveals no marker material. Extraction verifies byte-for-byte canonical payload equality, a trusted active or overlapping verification key, signature, expiry, and registry status. Detection deduplicates on `(marker_ref, observation_id)`.

### 8.4 Tripwire ordering

`TripwireGuard` is registered before configurable pre-invocation guards. A canary or honey-tool match causes an immediate deny, records guard evidence, and attempts a durable security-event append before returning. Event-store failure remains a deny and is represented in the kernel receipt. The post-invocation detector runs before response delivery; a valid watermark hit blocks egress and emits the same event shape.

## 9. Security events and temporal correlation

`SecurityEventBody` is a canonical, replayable observation with event id, event time, ingest time, tenant, subject, agent, session, capability, source receipt id, event kind, severity, evidence references, lineage seed, producer id, producer key id, trust class, and policy version. Raw secrets and decoy markers are forbidden. A `SignedSecurityEvent` binds the canonical body to a configured detector key, or the event carries a verified Chio receipt whose signer and event projection establish equivalent provenance.

Ingestion produces `VerifiedSecurityEvent` only after signature or receipt verification, tenant binding, producer authorization, freshness, and event-time bounds pass. Only configured internal trust classes may enter automatic-response correlation. External SIEM imports, unsigned observations, and events from untrusted tool servers may create advisory findings and alerts, but cannot authorize containment.

Rules are ordered stages adapted from Clawdstrike's `hunt-correlate` semantics. Each stage has an event predicate, an optional `after` stage, a `within` duration, and a grouping key. The engine uses event time, deduplicates event ids, accepts a configured bounded-lateness interval, advances a deterministic watermark, evicts expired partial matches, and caps state per tenant and rule. Overflow or store failure emits a detector-health event and suppresses automatic heavy response for the affected partition. It does not reinterpret an incomplete sequence as a match.

A correlated finding commits to the rule version, group key hash, ordered contributing event ids, evidence digests, first and last event times, and lineage seed. Replay of the same corpus and policy produces the same finding id.

## 10. Causal blast radius

Any plan containing a lineage-scoped effect, currently `SuspendCapabilitySet` or `FreezeIssuance`, queries an authoritative, complete capability and receipt-lineage snapshot at a committed index, sorts and deduplicates target identities, and records the graph-slice digest, query bounds, and commit index. `Exact(AffectedSet)` requires a complete authoritative snapshot, not merely a local query that did not report truncation. The planned set is approval-bound but provisional because issuance and delegation remain live while approval is collected. Incomplete results produce an escalation and dry-run plan only. Session-local throttle, egress, and suspension effects bind their exact session target and do not acquire a lineage fence.

Every lineage-scoped plan includes `FreezeIssuance` as its first ordered, approval-bound effect. After approval and before that effect, the executor durably records a deterministic fence-acquisition intent, obtains a bounded issuance-and-delegation fence lease for the lineage root, and recomputes the exact set under that fence. Execution proceeds only if the commit index and affected-set hash still equal the approved plan. A mismatch releases the lease and invalidates the approvals. The acquired lease is then persisted as the already-approved `FreezeIssuance` effect and renewed under the scheduler's fencing token. A crash before effect persistence is recovered by querying the deterministic action and lease ids; otherwise the bounded lease expires. No pre-approval or pre-apply terminal plan owns a lineage fence. Lift removes lineage-scoped restrictions from the recorded set and releases the fence only after all other effects are safely removed; it never recomputes a different subtree.

## 11. Response plans and effects

### 11.1 Temporary actions

Response actions are either observational or reversible overlay operations:

| Action | Default approval class | Effect |
|---|---|---|
| `EscalateAlert` | none | signed alert only |
| `ThrottleSession` | auto-reversible | composable temporary rate-limit contribution |
| `RestrictEgress` | auto-reversible | temporary destination deny overlay |
| `SuspendSession` | heavy | temporary session deny overlay |
| `SuspendCapabilitySet` | heavy | temporary deny overlay over the exact affected set |
| `FreezeIssuance` | heavy | commit-indexed issuance and delegation fence contribution |

Operator policy sets bounded TTL ceilings for each class. A plan at or below its auto-reversible ceiling may apply without human approval. Any extension beyond that ceiling is heavy and requires the shared threshold approval set.

Permanent revocation is not presented as reversible and is outside automatic response. A separately approved operator workflow may invoke the existing revocation oracle after containment, but no `LiftOrder` can undo it.

### 11.2 Plan binding

`ResponsePlan` includes action id, trigger finding id, tenant, policy version, exact affected set and hash, ordered proposed effects, TTL, creation and expiry, authorizing Chio operator-capability id, digest and expiry, executor subject, required approval policy, submitter, and reason hash. The capability subject is the response executor. Its existing tool scope must contain one grant on internal server `chio.control-plane.active-response` for every proposed effect's closed logical tool name, such as `throttle_session`, `restrict_egress`, `suspend_session`, `suspend_capability_set`, or `freeze_issuance`. This reuses current capability scope instead of inventing an unverified action-class string. Issuer trust, subject, time, scope, and revocation are checked before approval collection and again before apply. `plan_hash` is the domain-separated hash of the canonical body.

The operator capability is required for every executable plan, including an auto-reversible plan that requires no human vote. Threshold approval is an additional policy condition for heavy effects, not a substitute for executor authorization.

Heavy actions require the protocol-primitives threshold governed-approval set. The response plan is encoded as a canonical governed response-plan intent, and the existing `GovernedTransactionIntent::binding_hash()` is computed over that complete intent. The policy-authority-signed threshold proposal binds the operator-capability digest and has a deadline no later than both capability and plan expiry. Distinct approvals bind `governed_intent_hash` to that binding hash and `request_id` to `action_id`. Trusted approver roles, separation from the submitter, validity windows, duplicate rejection, atomic replay reservation, and consumption are mandatory. Changing any plan or capability field changes the governed intent or proposal and invalidates all approvals.

The control-plane executor opens a generic `AdmissionOperation` of kind `GovernedActiveResponse` before reserving replay state. Its operation id binds executor authority, action id, operator-capability digest, and governed intent hash. Budget and execution-nonce participants are absent, but approval reservation, dispatch commitment, crash recovery, and replay tombstones use the same coordinator contract as governed tool calls. `chio-quarantine` consumes this through `ApprovalVerifierPort` and does not depend on kernel implementation types. Until the shared proposal, coordinator, and replay reservation are implemented, every approval-requiring response remains dry-run, including a one-approver policy. `chio-quarantine` does not implement a private quorum verifier.

### 11.3 Durable state machine

The only legal transitions are:

| From | To |
|---|---|
| `planned` | `awaiting_approval`, `applying`, `cancelled`, `expired`, `failed` |
| `awaiting_approval` | `applying`, `cancelled`, `expired`, `failed` |
| `applying` | `active`, `apply_partial`, `failed` |
| `apply_partial` | `rolling_back` |
| `active` | `expiring`, `rolling_back` |
| `expiring` | `rolling_back` |
| `rolling_back` | `lifted`, `rollback_partial` |
| `rollback_partial` | `rolling_back` |

`cancelled`, `expired`, `failed`, and `lifted` are terminal. `failed` is legal only when no external effect was successfully applied; otherwise the state is `apply_partial`. Every transition is a compare-and-swap update carrying a monotonic generation and transition id. Duplicate commands return the existing result. An `applying` lease timeout moves to `apply_partial` and triggers rollback of recorded successful effects. An `active` TTL timeout moves to `expiring` and is claimed by a durable scheduler. A rollback failure remains restrictive, moves to `rollback_partial`, and pages an operator. It never reports `lifted`.

### 11.4 Effects and rollback

Each `ResponseEffect` has a deterministic effect id, target, operation, contribution, observed base-version digest, apply status, scheduler fencing token, timestamps, and error code. Reversible restrictions are stored as effect-ID-keyed contributions. Effective posture is the most restrictive composition of the base state and every active contribution. Lift removes only its own contribution and recomputes posture, so plans may expire out of order without erasing one another. A non-composable external effect requires per-target serialization and compare-and-swap restore against the version installed by that effect; conflict keeps the restrictive state and escalates.

The executor persists intent before calling a port, passes both effect id and scheduler fencing token, and then persists the observed result. A stale worker or stale fence cannot mutate or restore external state. Partial apply, partial rollback, expiry, cancellation, overlap, and retry each produce distinct signed receipts. `EscalateAlert` is observational and has no rollback contribution.

The containment overlay is consulted by an early kernel guard. When enabled, overlay-store failure denies because an active containment decision may otherwise be bypassed. Failure of the planner or correlator does not affect baseline preventive guards.

## 12. Chio-native receipt mapping

Active defense extends the receipt vocabulary with canonical bodies for:

- flow denial;
- declassification consumption and outcome;
- tripwire observation;
- correlated finding;
- response plan;
- effect transition;
- response completion;
- lift or rollback completion;
- detector and scheduler health.

Kernel-boundary denials remain mediated decision receipts with structured guard evidence. Off-boundary planning and response events use signed observation or advisory receipts as appropriate. Receipt ids and effect ids are cross-linked, and lineage ingestion records the relationships. No receipt carries a raw tainted payload, marker, credential, or rollback secret.

## 13. Migration and rollout

1. Land portable types, schemas, lattice tests, and manifest unification without enabling enforcement.
2. Add SQLite stores and dual-write principal, lineage, and session taint plus verified security events while decisions remain report-only.
3. Enable post-invocation classification in shadow mode. Any shadow-store failure is surfaced but does not yet alter responses.
4. Enable fail-closed flow enforcement for manifests that explicitly opt into `flow_v1`.
5. Require flow declarations for newly registered egress tools, then migrate existing signed manifests.
6. Arm deception for test tenants, then selected production tenants. Never reuse development markers in production.
7. Run correlation and response in dry-run until false-positive, truncation, and rollback evidence meets the release thresholds.
8. Enable reversible automatic actions by tier. Permanent revocation remains human-operated.

Rollback disables new adapter registration and leaves the durable event and response history readable. It does not delete taint, decoy, or containment records. An active containment overlay must be explicitly lifted or allowed to expire before disabling its enforcement guard.

## 14. Behavioral release gates

Release gates execute behavior, not source grep:

- lattice property tests and a formal partial-order plus least-upper-bound model;
- unknown label, missing clearance, classifier failure, taint-store failure, and declassification-store failure all deny;
- signed manifest flow fields survive every supported adapter and four-language schema round trip;
- a canary call cannot reach a fake tool server even when event persistence fails;
- watermark tampering, untrusted keys, expiry, replay, and key overlap behave as specified;
- temporal `after/within` rules are deterministic under duplicate and bounded out-of-order events;
- truncated lineage never auto-applies containment;
- crash recovery between every effect transition converges without double application;
- TTL expiry rolls back the exact applied set;
- forced partial apply and partial rollback produce truthful states and receipts;
- approval replay, duplicate approvers, submitter approval, expired approval, and plan mutation all fail;
- threat rows remain unchanged until conformance and caught-mutant evidence pass the existing coverage gate.

## 15. Provenance and adaptation boundary

The following Clawdstrike code at local commit `666303e5f3428f3b6e6b72f118c269a02388e0a4` informs this design:

- temporal rules and engine: `crates/libs/hunt-correlate/src/rules.rs` and `engine.rs`;
- deception types and honey lifecycle: `crates/libs/clawdstrike-policy-event/src/edr/deception.rs` and `honey.rs`;
- response plans, effects, status, and rollback: `crates/libs/clawdstrike-policy-event/src/edr/response.rs`;
- signed watermark envelope: `crates/libs/clawdstrike/src/watermarking.rs`;
- tripwire-before-execution behavior: `crates/services/clawdstrike-brokerd/src/api.rs` and `crates/services/clawdstrike-brokerd/tests/e2e.rs`.

The implementation adapts invariants and tests to Chio types, canonical signing, receipts, and lineage. It does not copy Clawdstrike's broker serialization, inherited-environment behavior, non-atomic execution count, or any code without verified provenance. Both repositories are Apache-2.0, but copied or materially adapted files must retain copyright attribution, identify modifications, and propagate applicable `NOTICE` text. Code marked as adapted from another upstream source requires that source's license to be verified before use.

## 16. Bounded claims

This work supplies mechanisms and evidence gates. It does not claim that deception has no false positives, that containment is guaranteed when response services are unavailable, or that a threat row is covered before the existing coverage process accepts conformance and caught-mutant evidence.
