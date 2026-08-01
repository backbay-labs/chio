# WS10 Design: Comptroller Console (live spend observability)

- Date: 2026-07-10
- Program: agent-economy program, wave 1 (see 2026-07-10-agent-economy-program-design.md)
- Depends on: none (WS1 settlement telemetry enriches it when present)
- Claim track: implementation (the documented roadmap-Next observability item)
- Branch: chio/ws10-comptroller-console off main

## Goal

Turn the signed receipt log into a live comptroller surface: a spend-event
stream, budget-utilization webhooks, deterministic burn-rate projections, and
corpus-level spend-anomaly detectors. The differentiator is that every finding
over a complete, lineage-verified corpus is a signed, independently recomputable
artifact eligible for an explicit local underwriting evidence policy. An
incomplete corpus produces a separate operational signal, never a finding or
underwriting fact. No detector or webhook enforces
anything; capabilities plus policy and guards remain the pre-action authority,
while receipts and findings are evidence.

## Context

`docs/reference/AGENT_ECONOMY.md:1242-1247` names observability as the next
roadmap phase: a spending dashboard (query layer over the receipt store),
budget-utilization webhooks, and real-time cost streaming from the receipt log.
Section 4.4 (lines 806-816, 1074-1076) already sketches the Chio Watch surface,
including webhook thresholds at 50/80/95 percent.

The substrate exists:

- `FinancialReceiptMetadata`
  (`crates/core/chio-core-types/src/receipt/economics.rs:32-62`) carries
  `cost_charged`, `currency`, `budget_remaining`, `budget_total`,
  `delegation_depth`, `root_budget_holder`, and `settlement_status`
  (`SettlementStatus`, same file lines 113-124).
- The receipt query surface is cursor-paginated over the `seq` column with
  currency-bound `minCost`/`maxCost` filters and a 200-row cap
  (`docs/reference/RECEIPT_QUERY_API.md:14-63`; `ReceiptQuery` at
  `crates/kernel/chio-kernel/src/receipt_query.rs:93-127`). Cost filtering runs
  as `json_extract(r.raw_json, '$.metadata.financial.cost_charged')`
  (`.../receipt_store/evidence_retention.rs:549-550`), not a dedicated indexed
  column (the `chio_tool_receipts` table has none:
  `.../receipt_store/bootstrap/open.rs:131-158`). This corrects the doc and the
  brief; see Open questions.
- `VelocityGuard` throttles per `(capability_id, grant_index)` with integer
  milli-token buckets (`crates/guards/chio-guards/src/velocity.rs:128-200`).
- `derive_underwriting_signals`
  (`crates/platform/chio-control-plane/src/trust_control/underwriting_and_support/policy_support.rs:315-555`,
  called at line 93) already builds a `Vec<UnderwritingSignal>` including
  pending/failed settlement signals (lines 484-505). Signal, class, reason, and
  evidence enums live in `crates/economy/chio-underwriting/src/lib.rs:87-147`.
- `chio-siem` ships a reusable webhook exporter with HTTPS enforcement, a typed
  `HttpEgressContract`, and 5xx/429 retry
  (`crates/observability/chio-siem/src/exporters/webhook.rs:143-353`).
- The mixed-currency null-unless-converted rule is already implemented in
  metering (`crates/economy/chio-metering/src/query.rs:163-170`).

## In scope

1. Reuse-first detector and projection modules in `chio-metering`, which already
   owns cost attribution, window math, and mixed-currency aggregation. A new
   pure `chio-spend-telemetry` crate is allowed only if implementation discovery
   proves that home creates a dependency cycle or unworkable feature boundary.
2. A trust-control spend surface: a cursor spend-event stream, a webhook
   registration and delivery path, and signed burn-rate and anomaly report
   endpoints, wired through `chio-control-plane` and persisted behind
   `chio-store-sqlite` traits.
3. New spend metric names in `chio-metrics-spec` and their emission from the
   trust-control spend surface.
4. New `UnderwritingReasonCode` and `UnderwritingEvidenceKind` variants plus a
   policy-gated spend-anomaly evidence input to `derive_underwriting_signals`,
   with explicit local and imported evidence classes.
5. Signed anomaly-evidence and underwriting decision policies, strict shared
   policy-input/decision v2, retained decision chains, and an external governance
   anchor for current policy/decision heads.
6. A `chio spend` CLI subcommand group mirroring the `chio receipt` and
   `chio trust <family> export` conventions.
7. JSON schemas under `spec/schemas/chio-spend/`, schema-id constants, and
   conformance coverage; a `spec/PROTOCOL.md` spend-family subsection; and all
   signed-schema registry, hash-manifest, known-schema, positive-fixture, and
   unknown-schema-negative gates.
8. In phase 2, receipt-store currency and a full-`u64`, order-preserving derived
   cost key plus a
   tenant/currency/cost/sequence index, with an atomic migration and query-parity
   verification for existing rows.

## Out of scope (explicit cuts)

- A web UI. The deliverable is API and CLI first. A dashboard consumes these
  endpoints later and is a separate track.
- Any automatic enforcement. Detectors and webhooks never revoke, clamp, or
  deny. Enforcement stays with the guards and policies.
- Overloading `chio-otel-receipt-exporter`. That crate is OTLP-span ingress into
  signed receipts (`crates/observability/chio-otel-receipt-exporter/src/lib.rs:1-6`),
  not receipt-to-OTel egress; WS10 does not route financial dimensions through
  it.
- Distributed-linearizable spend truth. The HA overrun bound (ADR-0006) stands;
  `budget_remaining` is a best-effort snapshot (economics.rs:24-28).

## Design

### Spend event stream

A spend event is a projection of one already-signed receipt: it copies the
`FinancialReceiptMetadata` financial dimensions plus the source `receipt_id`,
`content_hash`, `tool_server`, `tool_name`, `timestamp`, and `seq`. The frame is
digest-bound to the signed receipt, so it is not independently signed. Receipt
verification authenticates the post-action evidence; it does not turn the event
into pre-action authority.

Transport is pull-based long-poll and Server-Sent Events over the existing
seq-cursor pagination (`GET /v1/spend/stream?cursor=<seq>`), extending the
receipt query surface (`RECEIPT_QUERY_PATH` at
`crates/platform/chio-control-plane/src/trust_control/service_types/paths.rs:117`).
The cursor is an opaque, authenticated value binding tenant, filter digest,
exclusive last-scanned store sequence, and store generation. Every batch carries
`from_cursor`, `next_cursor`, `scanned_seq_start`, `scanned_seq_end`,
`store_high_water_seq`, `source_checkpoint`, `complete_through_seq`, and optional
`gap`. `source_checkpoint` is a signed `chio.spend.stream-checkpoint.v1` binding
the tenant, store generation, high-water sequence, base receipt-checkpoint root,
a tenant-projection root over every receipt visible to that tenant, a
tenant-time-index root over the same leaves ordered by
`(signed_receipt_timestamp, global_sequence)`. It never commits only rows
matching the requested filter. Each projection leaf carries tenant, global
sequence, signed receipt timestamp, receipt hash, financial/non-financial
marker, and the canonical projections for every allowed stream filter,
including currency and the order-preserving cost key. The sequence and time
index leaves are inserted in the same receipt-writer transaction as the receipt
and cross-bind the same leaf digest. The checkpoint also binds a
`(budget_authority_digest, global_sequence)` index root for threshold
processing. A financial receipt whose trusted capability snapshot cannot resolve
that digest inserts an unresolved-authority marker in the tenant projection;
such a marker freezes threshold completeness rather than disappearing.
Each batch supplies a boundary-complete proof over all tenant leaves in the
declared global sequence range; the verifier applies the filter itself and
derives the matching count. A root over a server-selected matching subset is
explicitly insufficient because it cannot prove a matching row was not omitted.
Sequence numbers missing from the tenant leaves may belong to another tenant;
the authenticated tenant index plus predecessor/successor boundaries proves
that exclusion without disclosing the other row.

A consumer must present the prior `next_cursor` unchanged. A cursor older than
retention, from another tenant or filter, or from an incompatible store
generation yields a typed gap response with `earliest_available_seq` and no
events; the server never silently resumes at the new floor. Detector input is
not proven complete by a cursor chain alone because receipt timestamps need not
increase with store sequence. For an analytic window `[start, end)`, the server
returns a range proof from the tenant-time index containing every key in
`[(start, 0), (end, 0))`, plus the immediate predecessor and successor (or
authenticated collection boundaries). The verifier checks every member against
the same checkpoint's tenant projection root, applies the filter locally, and
derives the count. Window semantics use the signed receipt timestamp explicitly;
they do not infer wall-clock order from sequence. This makes the tail a thin read
while giving corpus consumers a precise completeness test.
Webhook push is reserved for the discrete threshold crossings below, not the
full firehose, because a firehose over webhook is an unbounded at-least-once
delivery obligation the stream tail does not incur.

### Webhooks

Budget-utilization webhooks fire on threshold crossings per verified budget
authority at 50, 80, 95, and 100 percent of `max_total_cost`. A v1 authority key
is `(tenant, capability_id, grant_index, budget_authority_digest, currency)`.
Tenant-wide thresholds are allowed only when a signed tenant-budget authority
defines one total; otherwise the API returns per-authority partitions and no
tenant aggregate. Crossings are computed from `budget_remaining`/`budget_total` on
spend events (and, when WS1 settlement telemetry is present, from budget-store
events directly). Each crossing is emitted at least once as a signed
`chio.spend.budget-threshold-crossing.v1` payload; the receiver verifies the
signature and treats the webhook as evidence, never as authority. Delivery
reuses the `chio-siem` webhook exporter machinery
(`crates/observability/chio-siem/src/exporters/webhook.rs`): HTTPS enforcement,
the typed `HttpEgressContract`, bounded response handling, and secret-zeroizing
auth. Its in-process retry loop is not the durability boundary; WS10 invokes one
transport attempt per durable claim and owns retry scheduling in SQLite.

Threshold evaluation is ordered per verified budget-authority key. The receipt
writer maintains the checkpoint-bound authority-event index ordered by global
sequence within each authority. A `threshold_cursor` row stores the last processed relevant sequence,
last utilization, authority version, and row version. A worker may advance only
from the expected cursor to the next proven authority-index member; a boundary
proof against the checkpoint root must show there is no skipped relevant member.
Any unresolved-authority marker before the checkpoint freezes evaluation. A higher sequence arriving
or being scheduled first cannot advance over the true next member. Gaps,
out-of-order input, missing authority evidence, and stale versions freeze the
cursor rather than becoming older-sequence no-ops.

Each payload carries a deterministic crossing id derived from the threshold key
`(tenant, capability_id, grant_index, budget_authority_digest, currency,
threshold_bps)` and the first crossing receipt sequence. Crossing detection,
cursor advance, threshold-state update, signed payload insert, and one delivery
row per active registration commit in one `Immediate` transaction. A signing
or insert failure advances none of them. Ordinary budget fluctuations do not
re-arm a threshold; only a new signed budget-authority digest starts a new
lifecycle.

Delivery rows are keyed by
`delivery_id = sha256(crossing_id, registration_id, registration_version)` and
bind the immutable payload digest and exact egress-policy digest. Their closed
state machine is `Pending -> Leased -> Delivered | Pending | DeadLetter` with
checked attempt count, next-visible time in milliseconds, row version, lease
owner/token/deadline, bounded result code plus detail digest, and acknowledgement
time. A bounded worker claims due rows by lease CAS, performs network I/O outside
the transaction, then acknowledges, reschedules 429/5xx/transport failures with
validated capped backoff, or dead-letters permanent 4xx and exhausted attempts
by exact version/token CAS. A crash before acknowledgement leaves an expired
lease for restart recovery, so delivery is at least once. Receiver dedupe uses
the signed crossing id. Delivered and dead-letter rows are terminal; manual
replay creates a new audited delivery generation rather than mutating history.

The authority digest and grant index are not inferred from copied financial
metadata. The projector resolves the receipt's capability id through the trusted
capability snapshot, identifies the matched grant, verifies its cost constraint
and signer, and hashes that canonical authority. If the snapshot, matched grant,
or receipt binding is unavailable, webhook and burn-rate evaluation are
incomplete. Velocity-guard trip webhooks are deferred until a durable signed
guard-event source exists; v1 does not label best-effort inference as a crossing.

### Burn-rate projections

Given a trailing window `[now - W, now)` with `W` declared on the request, the
v1 request names exactly one verified budget-authority key. The projection sums
`cost_charged` per currency over matching spend events for that key and
computes, in integer arithmetic only, `spend_in_window` (checked sum of minor
units), `time_to_exhaustion_seconds` as a checked
`budget_remaining * W / spend_in_window` (integer division, `null` when the
window spend is zero). `budget_remaining` and `budget_total` come from the
highest-sequence verified event at or before the named checkpoint carrying the
same authority digest; conflicting totals, absent state, or mixed authority
versions produce an incomplete projection. Multi-authority requests return
separate partitions and no aggregate exhaustion time. The projection also computes
`projected_window_spend` as `spend_in_window` scaled by an integer window
multiple. Overflow returns a typed incomplete projection, never a saturated
financial value. Aggregates are `MonetaryAmount`. Mixed-currency windows follow the
null-unless-converted rule (query.rs:163-170): a per-currency partition is
always returned, and any cross-currency total is `null` unless
`OracleConversionEvidence` is attached. The same projection runs over commerce
mandate allowances, whose `chio.commerce.mandate-allowance-ledger.v1` binds a
maximum amount, currency, validity window, and usage count
(`spec/PROTOCOL.md:1118-1119`, section 6.3.4). Output is a signed
`chio.spend.burn-rate-projection.v1` carrying the window bounds, the inputs,
integer results, source checkpoint, tenant-time-index range proof, and
sequence-root cross-bindings so a verifier recomputes it exactly. A projection
over an incomplete corpus emits
`chio.spend.incomplete-corpus.v1` instead of a numeric result.

### Anomaly detectors

Three deterministic corpus-level detectors, all integer or fixed-point so a
verifier independently recomputes the statistic from the cited receipts. A
finding requires a boundary-complete tenant-time-index proof through a named
checkpoint, sequence-root cross-bindings, verified receipt signatures, and
verified subject/capability bindings. Delegation and
velocity findings additionally require a complete signed capability lineage:
root holder, capability id, grant index, parent-child grant edges, and the
receipt refs that establish each edge. Copied `root_budget_holder` or
`delegation_depth` metadata alone is not lineage proof. Missing or conflicting
lineage, a partial window, or a retention gap emits
`chio.spend.incomplete-corpus.v1` and no anomaly finding.

On complete input, each detector emits a signed
`chio.spend.anomaly-finding.v1` carrying the detector class, severity, subject,
verified lineage refs, source checkpoint, digest-bound evidence receipt refs,
and the statistic plus the threshold it crossed. Each detector has a canonical
`detector_config_digest` over its exact version, algorithm, window/baseline,
thresholds and every other parameter. Severity is deterministically derived from
that config and statistic, never supplied independently. `finding_id` is SHA-256
over the complete canonical unsigned finding body excluding only `finding_id`
and signature, so it includes detector config, severity, authority, subject,
window, checkpoint, evidence roots and refs, statistic, threshold and resolved
evidence classes. It is not keyed by any one evidence receipt. Storage retains a
separate body digest and rejects the same ID with different bytes.

- Delegation-chain cost amplification. Sum `cost_charged` for a child subtree
  selected by verified capability-lineage edges, using `root_budget_holder` and
  `delegation_depth` only as consistency checks (economics.rs:44-47). Compare
  against the complete parent-level corpus and flag when the child-to-parent
  ratio in basis points exceeds a declared bound.
- Spend-pattern drift. Per `(subject, tool_server, tool_name)`, compare the
  current window's mean per-invocation cost against a trailing baseline mean;
  the divergence is a fixed-point ratio in basis points against a declared
  threshold. No floats enter the recorded statistic.
- Velocity clustering. `VelocityGuard` buckets are per grant
  (velocity.rs:128-130), so N sibling grants each just under the limit aggregate
  to N times the intended rate. The detector sums sibling-grant invocation and
  spend counts within a complete window under a shared verified lineage root and
  flags when the aggregate exceeds a declared multiple of the per-grant ceiling.

### Underwriting feedback loop

Anomaly findings are eligible to become underwriting signals only through an
active signed `chio.spend.anomaly-evidence-policy.v1` artifact. Its canonical
`SpendAnomalyEvidencePolicyV1` body contains `policy_id`, tenant, normalized
subject/scope digest, monotonic sequence, optional predecessor policy id and
digest, accepted finding-authority key ids, a sorted bounded detector-to-version
map of accepted exact detector-config digests per version, maximum finding age,
minimum sample count and window, required
complete-corpus schema, a sorted bounded severity-to-signal mapping,
`not_before`, `expires_at`, policy authority id, and key epoch. The policy ID is
domain-separated RFC 8785 over all body fields except the ID. The signed envelope
uses the normal signed-artifact schema gates.

Local `SpendAnomalyPolicyTrust` resolves `(tenant, policy_authority_id,
key_epoch)` to an active key and permitted scope. Embedded keys are never trust
roots, and the policy's accepted finding-key set may only narrow the local
finding-authority registry. Validation rejects empty or duplicate sets, unknown
detector versions or config digests, invalid severity mappings, zero bounds, bad scope, inverted
validity, lineage gaps, or a nonincrementing sequence.

The policy store retains `Staged -> Active -> Superseded | Revoked` rows and one
active head per `(tenant, scope_digest)`. Activation compare-and-swaps the exact
current policy id, envelope digest, sequence, and row version; revocation retains
a tombstone. The production resolver requires the authoritative current head and
trusted clock on every evaluation. Missing, unavailable, expired, superseded, or
revoked policy means no spend finding is admissible; the default accepts none.
Tenant-admin APIs create, list, stage, activate, and revoke policies, while a
read-only simulation may evaluate an explicitly supplied policy but cannot
persist an active underwriting decision.

Persisted underwriting decisions also require an active signed
`chio.underwriting.decision-policy.v1`. Its
`UnderwritingDecisionPolicyArtifactV1` body contains policy id, tenant/scope,
sequence and exact predecessor, the complete strict serialized
`UnderwritingDecisionPolicy` rules, evaluator compatibility range, `not_before`,
`expires_at`, authority id and key epoch. Local `UnderwritingPolicyTrust`
resolves that authority and scope; embedded keys are never roots. The lifecycle
is the same retained `Staged -> Active -> Superseded | Revoked` CAS model. The
live unsigned built-in default remains available only for read-only simulation
or nonpersistent bootstrap diagnostics. It cannot authorize a persisted active
decision.

Verification checks the finding signature, source checkpoint, complete
tenant-time-index range and predecessor/successor boundary proof, receipt refs,
capability lineage, subject scope, freshness, and detector recomputation before
policy evaluation. A cursor chain alone is not completeness proof.

A finding records `derivation_class` separately from `evidence_class`. Local
deterministic computation has derivation class `observed`, but the final evidence
class is the floor across every receipt, capability-lineage, conversion, and
other source dependency plus that derivation. An asserted or imported input
therefore prevents an observed finding even when computation is local. The same
signed finding presented across an organization boundary is capped at
`asserted`, even when its issuer signature verifies, and no trust pack may
upgrade it. `chio.spend.incomplete-corpus.v1` is an operational health signal,
never adverse underwriting evidence.

Add `UnderwritingEvidenceKind::SpendAnomalyFinding`
and `UnderwritingReasonCode` variants (`SpendDelegationAmplification`,
`SpendPatternDrift`, `SpendVelocityClustering`) to
`crates/economy/chio-underwriting/src/lib.rs:98-124` and to the taxonomy default
(lines 167-194). Extend `derive_underwriting_signals` with a spend-anomaly
evidence input. After verification and policy filtering, group findings by exact
`(tenant, subject, UnderwritingReasonCode)`, independent of input order. For
each group, select the maximum signal class (`Guarded < Elevated < Critical`),
take the evidence-class floor across the union, union and byte-sort finding ids
and digest-bound receipt/lineage refs, and emit one deterministically identified
`UnderwritingSignal`. A lower-severity finding can never suppress a higher one.
Replace the live first-wins `dedupe_findings` behavior
(`decision.rs:813-827`) for same-reason inputs with deterministic strongest-
outcome selection and stable sorting before decision evaluation; do not rely on
arrival order. These signals sit alongside existing reputation, certification,
runtime-assurance, and settlement signals and retain the settlement-signal
evidence-reference pattern (`policy_support.rs:568-584`).

The live `UnderwritingSignal` and `UnderwritingEvidenceReference` cannot carry
this resolved class. WS10 therefore does not squeeze the new input into
`chio.underwriting.policy-input.v1`. `chio-underwriting` adds
`UnderwritingResolvedEvidenceClass::{Asserted, Observed, Verified}`,
`UnderwritingSignalV2 { signal_id, tenant_id, subject_key, class, reason,
resolved_evidence_class, source_binding, description, evidence_refs }`, a tagged
`UnderwritingSignalSourceBindingV2`, and
`chio.underwriting.policy-input.v2` with version-first strict decoding. WS6 and
WS10 coordinate this one v2 body before either integration ships so its optional
imported-financial and spend-anomaly arms are both versioned; if v2 has already
shipped, the later workstream uses v3 rather than mutating v2.
The source binding is either
`SpendAnomaly { evidence_policy_body_digest,
evidence_policy_envelope_digest, finding_ids }` or
`ImportedFinancial { source_manifest_digest, presentation_digest,
credential_body_envelope_pairs, verifier_policy_id,
verifier_policy_body_digest, verifier_policy_generation,
lifecycle_generation_checkpoint_digests, lifecycle_source_index_proof_digests,
lifecycle_result_digest, lifecycle_pin_digest,
credential_evidence_class_bindings }` or
`LegacyV1 { source_input_digest, signal_index }`.
`evidence_policy_body_digest` is SHA-256 over the RFC 8785 canonical verified
policy body and `evidence_policy_envelope_digest` binds the exact signed
envelope. Both are required only for the spend-anomaly arm and must equal the
active resolved policy head used for evaluation. Each of
`SpendDelegationAmplification`, `SpendPatternDrift`, and
`SpendVelocityClustering` requires `SpendAnomaly`; that arm requires a nonempty
sorted-unique finding-id set exactly equal to the policy-selected group and an
evidence-ref set exactly equal to the sorted union recomputed from those
findings. A spend reason in `LegacyV1`, a non-spend reason in `SpendAnomaly`, or
any missing/extra finding or evidence ref rejects.

`ImportedFinancial` is valid only for the imported-trust reason emitted by WS6.
Its sorted unique credential body/envelope pairs and per-credential source,
presentation and resolved evidence classes, source manifest and exact
presentation digest, operator-pinned verifier-policy identity/body/generation,
issuer-global lifecycle checkpoint and source-index proof, and authenticated
lifecycle result plus independently durable pin must equal one
`VerifiedFinancialCredentialSet`. It cannot be constructed from counts or raw
passport input. A financial signal in `LegacyV1` or `SpendAnomaly`, a spend
signal in `ImportedFinancial`, or any omitted credential or lifecycle binding
rejects.

`LegacyV1` binds the SHA-256 digest of the complete canonical signed v1 policy
input and the exact zero-based index in its `signals` array rather than
inventing a spend policy or nonexistent signal id for legacy reputation,
certification, runtime, or settlement evidence. The verifier resolves that
index and requires class, reason, description, and evidence refs to equal the
source signal exactly before adding v2-only fields. Duplicate equal v1 signals
remain unambiguous because their indexes differ. `signal_id` is SHA-256 over the
canonical tenant id, subject, reason, maximum risk class, resolved evidence
class, complete tagged source binding, and sorted evidence refs. The verifier
recomputes every applicable digest and the signal id and rejects a mismatch.
Tenant, source binding, and resolved class are required and signed in the v2
input; none is an optional display annotation.

Existing v1 inputs remain readable only through their v1 decoder. A named
`upgrade_underwriting_input_v1` requires a trusted local resolver to stamp the
tenant, subject, resolved evidence class, canonical `LegacyV1` source binding,
and recomputed signal id for every legacy signal and fails if any input is
ambiguous; it preserves the indexed v1 class, reason, description, and evidence;
there is no default-to-observed conversion and v1 cannot directly carry WS10
signals. The v2-to-v1 conversion rejects any WS10 signal or other field that
would be lost. Policy evaluation reads the signed v2 resolved class, and an
organization-boundary verifier recomputes the asserted cap before accepting the
input.

### Versioned underwriting decision chain

Policy-input v2 is persisted only through strict
`chio.underwriting.decision-report.v2` and
`chio.underwriting.decision.v2` families. `UnderwritingDecisionReportV2` binds
the policy-input schema and exact signed-envelope digest, underwriting decision
policy id, version, body and envelope digests, active anomaly-evidence-policy
body and envelope digests when spend signals are present, sorted signal root and
count, evaluator version, subject binding, outcome, reason codes, credit ceiling,
and premium quote. A verifier recomputes every signal and policy binding before
accepting the report.

`UnderwritingDecisionArtifactV2` contains `decision_id`, stable
`decision_chain_id`, sequence, optional predecessor schema/id/envelope digest and
sequence, tenant and normalized subject/scope binding, input-envelope digest,
decision-policy id, version, body digest and envelope digest, optional
anomaly-evidence-policy body and envelope digests, evaluator version, issued
time, required validity end, the
complete report v2, and lifecycle state `Active | Superseded`. The chain ID is
domain-separated RFC 8785 over underwriting authority, tenant, subject, and
normalized scope only; mutable policy versions are excluded. The decision ID is
derived over every body field except itself. The signed envelope digest and
decision ID are distinct and both are retained.
`valid_until` is the checked minimum of the input validity, active decision-policy
expiry, active anomaly-policy expiry when present, and every imported-financial
credential/presentation plus `FinancialVerifierPolicyV1` validity bound. An empty
interval rejects. Lifecycle remains a current-status condition and is rechecked;
it is not converted into a guessed expiry.

The decision store enforces unique `(decision_chain_id, sequence)` and one active
head. Appending a successor in one transaction verifies the expected active
decision id, envelope digest, sequence, and row version; verifies that the
resolved signed decision-policy and anomaly-evidence-policy heads still equal the
digests used by evaluation; inserts the successor; and marks the predecessor
superseded. Cross-tenant, cross-subject, cross-scope, skipped-sequence, expired,
or arbitrary-predecessor chains reject. Rotating or revoking the anomaly policy
makes an earlier WS10-bearing decision stale for current-use resolution and
requires reevaluation; it does not rewrite history.
Every current-use resolution rechecks the anchored current policy heads,
decision-head inclusion, and `valid_until`. When an imported-financial arm is
present it also resolves the currently active operator-pinned
`FinancialVerifierPolicyV1` generation/body and trusted time, requires them to
equal the bound policy and remain valid, reconciles the issuer-global lifecycle
checkpoint for every issuer, verifies each current source-index proof, queries
and pins every authenticated per-passport status before branching, and requires
all sources still `Active`. Policy generation change, expiry, lifecycle
suspension/revocation, anchor/pin outage, stale generation, or a restored resolver
denies current use and requires reevaluation. Historical verification remains
available but cannot authorize current use.

V1 and v2 use version-first strict decoders. A v1 predecessor can enter a v2
chain only through a trusted migration resolver that proves the same authority,
tenant, subject, and scope and binds the exact v1 envelope; otherwise it remains
a separate legacy chain. A v1-only runtime fails startup when the active head is
v2. Downstream artifacts carry a tagged `VersionedUnderwritingDecisionRef` with
schema, decision id, body digest, envelope digest, chain id when available, and
sequence. They never store an untagged decision string. V2-to-v1 conversion
rejects spend signals, imported-financial signals, resolved evidence classes, or
any other field v1 cannot represent.

### Underwriting governance continuity

SQLite lifecycle and head rows are staging and cache state, not anti-rollback
authority. Persisted WS10 underwriting requires an
`UnderwritingGovernanceAnchor` outside the SQLite backup/restore domain. Its
signed `chio.underwriting.governance-checkpoint.v1` binds tenant/scope,
monotonic governance sequence and predecessor digest, active or terminal
anomaly-policy head, active or terminal decision-policy head, a Merkle root and
count over every active decision-chain head, and trusted-clock high-water.

Pure verification constructs a private `VerifiedUnderwritingGovernanceAdvance`.
It enforces sequence plus one, exact predecessor, nondecreasing time, legal
policy lifecycle/sequence changes, retained revocation and supersession, and an
authenticated Merkle update from exactly one verified decision append. No other
head may change. The external anchor accepts only this verified type through a
linearizable compare-and-swap; opaque signed successors reject.

Policy activation/revocation and decision append use `DbStaged ->
AnchorAdvanced -> DbActive`. Recovery completes an exact staged/anchored match,
may discard an unanchored stage while retaining the anchored predecessor, and
fails startup when the anchor is ahead, behind, divergent or unavailable.
Current-use resolution reads the anchor, verifies the policy heads and the
decision head's inclusion proof, and denies on any mismatch. Read-only spend
streaming may remain available during an underwriting-anchor outage, but no
spend signal or active decision is admitted or served.

### Artifacts and types

- `chio.spend.event.v1`: stream frame; digest-bound to a signed receipt, not
  independently signed.
- `chio.spend.stream-checkpoint.v1`: signed by a trusted store authority; tenant,
  store generation, high-water sequence, base receipt-checkpoint root,
  all-tenant-leaf sequence-projection root, tenant-time-index root,
  authority-event-index root, projection counts, and issuance time. Filters are
  query inputs evaluated over proven leaves, not part of a self-selected
  completeness root.
- `chio.spend.budget-threshold-crossing.v1`: signed webhook payload with the
  crossing id, budget-authority digest, first crossing receipt sequence, and
  prior/current threshold state.
- `chio.spend.burn-rate-projection.v1`: signed; window, inputs, checkpoint,
  tenant-time-index range and boundary proof, sequence-root cross-bindings, and
  integer results.
- `chio.spend.anomaly-finding.v1`: signed; class, severity, statistic,
  threshold, deterministic finding id, evidence refs, verified lineage refs, and
  complete-corpus proof.
- `chio.spend.anomaly-evidence-policy.v1`: signed governed admission policy with
  authority/key epoch, tenant/scope, sequence and predecessor, validity,
  detector/finding-authority allowlists, evidence bounds, severity mappings, and
  retained lifecycle.
- `chio.spend.incomplete-corpus.v1`: signed operational sidecar; requested
  window, detector or projection, cursor/checkpoint or time-index proof,
  gap/boundary or missing-lineage reason, and known missing refs. It cannot be
  deserialized as an anomaly
  finding and is never an underwriting input.
- `chio.underwriting.policy-input.v2`: signed strict versioned input with exact
  source bindings and optional jointly versioned WS6 and WS10 arms.
- `chio.underwriting.decision-policy.v1`: signed governed decision rules with
  trust, scope, sequence/predecessor, validity and retained lifecycle.
- `chio.underwriting.decision-report.v2` and
  `chio.underwriting.decision.v2`: signed strict decision chain described above.
- `chio.underwriting.governance-checkpoint.v1`: externally anchored policy and
  decision-head continuity checkpoint.

All monetary fields are `MonetaryAmount` (u64 minor units, ISO-4217). Signed
artifacts are canonical JSON (RFC 8785) with schema-id constants and JSON
schemas under `spec/schemas/chio-spend/` (the schemas directory already
partitions by family, for example `spec/schemas/chio-commerce`). Every signed
family is admitted through `spec/schemas/registry.json`,
`spec/schemas/MANIFEST.sha256`, `KNOWN_SIGNED_ARTIFACT_SCHEMAS`, positive
fixtures, and unknown-schema negatives before any verifier accepts it.

### Integration points

- `chio-control-plane` gains `/v1/spend/stream`, `/v1/spend/webhooks`
  (register and list), `GET /v1/reports/burn-rate`, and
  `GET /v1/reports/spend-anomalies`, plus tenant-admin
  `/v1/spend/anomaly-evidence-policies` create/list/stage/activate/revoke
  operations and tenant-admin underwriting decision-policy lifecycle operations,
  registered beside the existing report paths
  (paths.rs:117-190). Stream, reports, and webhook list use tenant read
  authority. Webhook create, rotate, disable, and delete require a distinct
  tenant-admin/write capability; the authenticated tenant is the stored owner
  and cannot be overridden by request data. Registration accepts a secret
  reference rather than inline credentials and compiles the HTTPS URL through an
  operator-approved exact-authority `HttpEgressContract` policy that fixes
  scheme, host, port, allowed path, redirect denial, DNS policy, and response
  bounds. A tenant writer cannot register an arbitrary exfiltration host outside
  that operator policy.
- `chio-store-sqlite` persists webhook registrations and delivery attempts and
  the ordered authority cursor, threshold state, leased outbox, terminal
  delivery/dead-letter history, incomplete-corpus signals, emitted findings,
  staged signed anomaly/decision-policy lifecycle and heads, underwriting
  decision-v2 chain heads, governance-checkpoint bodies and Merkle proofs
  behind new traits. Signed receipts stay immutable. Crossing rows are keyed by
  deterministic `crossing_id` and deliveries by registration-bound
  `delivery_id`, so one receipt sequence may create several threshold rows and
  each crossing may fan out durably. Findings are keyed by `finding_id`; a separate
  `(finding_id, receipt_id)` evidence-reference table and receipt-id secondary
  index represent their many-to-many source relationship. Neither artifact is
  forced into the one-sidecar-per-receipt settlement-reconciliation shape
  (AGENT_ECONOMY.md:753-760).
- The production underwriting evaluator accepts only a verified signed
  policy-input version and the resolver's exact active decision-policy and
  anomaly-evidence-policy heads. The transaction that appends decision v2 CASes
  both policy heads and the decision-chain head, stages the exact governance
  advance, and finalizes only after external anchor CAS. The control-plane owns
  the anchor adapter and startup recovery. Simulation endpoints may accept
  caller-selected policies but cannot write an active decision.
- Phase 2 rebuilds `chio_tool_receipts` with stored derived columns
  `cost_charged_be BLOB` and `cost_currency`, then adds an index ordered by
  tenant, currency, cost key, and sequence. Rust parses the canonical receipt
  JSON as `u64` and encodes cost as exactly eight big-endian bytes, whose
  lexicographic order matches unsigned numeric order across the full domain.
  SQLite `INTEGER` and JSON numeric coercion are not used because they cannot
  faithfully index values above `i64::MAX`. The migration and new receipt writer
  also populate the authenticated tenant-projection, tenant-time-index, and
  authority-event-index leaves (or unresolved-authority marker) in the same
  transaction.
  Migration verifies every derived value against Rust-parsed immutable receipt
  JSON. It compares old and indexed queries only over values representable by the
  legacy signed-`i64` path, and compares the full `u64` indexed domain against a
  Rust-parsed reference oracle. It swaps only after row-count, root, in-range
  parity, and reference-oracle checks pass. Derived columns and projection leaves
  are rebuildable indexes, never a second source of financial truth.
  Current-version opens perform only a fixed-size canonical manifest check over
  the cost columns, index, and receipt immutability guards. Full row
  reconciliation occurs only inside the transactional migration or an explicit
  operator audit. Archive reopen applies the same fixed column/index check.
  Query SQL selects exact branches for currency-only, lower-bound, upper-bound,
  and closed-range filters so both page and count use the cost index, and both
  statements execute in one deferred reader transaction. Either bound requires
  one three-letter uppercase currency. TypeScript clients encode cost bounds as
  `bigint`; Python clients use their arbitrary-precision integer.
- `chio-metrics-spec` gains spend-family metric names next to the existing
  `CHIO_*` constants (`crates/observability/chio-metrics-spec/src/lib.rs:115+`),
  for example `chio_spend_events_total`, `chio_spend_burn_rate_units`, and
  `chio_spend_anomaly_findings_total`.
- CLI: a `Spend` variant on `Commands`
  (`crates/products/chio-cli/src/cli/types.rs:262-330`) with
  `chio spend stream` (tail the cursor stream), `chio spend burn-rate`
  (fetch or export a projection), `chio spend anomalies export`, and
  `chio spend webhook add|list`.

### Error handling (fail-closed)

Verification errors deny. A malformed spend event (missing or non-canonical
financial metadata) makes the relevant batch incomplete, never a zero-cost
frame or a silently skipped detector input. A cursor scope mismatch, retention
gap, non-contiguous cursor chain, missing or inconsistent time-index boundary
proof, sequence/time-root mismatch, overflow, or missing lineage emits
`chio.spend.incomplete-corpus.v1` and no projection, finding, threshold
crossing, or underwriting signal. Mixed-currency aggregates without conversion
evidence return `null` totals with a per-currency partition, never a wrong sum.
A webhook registration without tenant-admin/write authority, an owner mismatch,
or a URL outside operator-approved egress policy rejects before persistence. A
crossing that cannot be signed is not inserted, and egress fails closed when the
`HttpEgressContract` is absent (webhook.rs:158-165). Authority cursor,
threshold state, crossing, and delivery rows commit atomically; none advances on
an incomplete or out-of-order batch. Lease conflicts, attempt overflow,
unclassifiable transport results, or outcome-unknown delivery preserve durable
work and emit an operator-visible incident rather than acknowledging it.
An underwriting input with missing/unknown resolved evidence class, subject or
signal-id mismatch, ambiguous v1 upgrade, imported finding above `Asserted`, or
unsorted/conflicting merged evidence rejects before policy evaluation.
An absent, unavailable, expired, superseded, revoked, wrong-scope, stale-sequence,
or untrusted anomaly-evidence or decision policy admits no spend signal or
persisted decision. A missing, unavailable, behind or divergent underwriting
governance anchor also denies those paths. A decision append
with a stale policy head, stale chain head, wrong subject/scope, skipped sequence,
arbitrary predecessor, mismatched report/input digest, unknown version, or lossy
downgrade rejects atomically and leaves the prior active decision unchanged.

## Alternatives considered

1. Extend `chio-metering` with pure projection and detector modules and keep I/O
   in the control plane. Recommended first step: metering already owns receipt
   cost attribution, window aggregation, and null-unless-converted rules. The
   new modules consume immutable projections and cannot enter the charge path,
   preserving the enforcement/observation boundary without duplicating money
   math.
2. Extend `chio-siem`. The SIEM path is security-signal-shaped: severity-graded
   events (`AlertSeverity`, `derive_severity` at
   `crates/observability/chio-siem/src/alerting.rs:62,124`) over guard denials,
   not deterministic financial statistics or signed `chio.spend.*` artifacts.
   WS10 reuses its webhook exporter but should not inherit its severity model or
   its export cadence. Rejected as the home crate; adopted for delivery only.
3. New pure crate `chio-spend-telemetry`. Deferred unless implementation
   discovery proves the metering module creates a dependency cycle or an
   unworkable feature boundary. A separate crate would isolate changes, but it
   would also duplicate or wrap metering's core window and currency rules before
   that need is demonstrated.

## Claim and release framing

Implementation track within the bounded release posture. WS10 ships an
observability and signed-evidence surface; it makes no settlement, custody, or
finality claim, and asserts no market-position threshold (those remain unproved,
per the program design's external-evidence framing). Findings and webhooks are
evidence, not authority; capabilities plus policy and guards remain the
pre-action enforcement boundary. Only complete, locally recomputed findings
accepted by an explicit policy can enter underwriting, and their evidence class
is capped by the floor of every source dependency; imported findings remain
asserted, and incomplete-corpus signals are never underwriting facts. The public claim is
"signed spend observability with policy-gated underwriting inputs," never
"automatic spend control."

## Testing strategy

- Determinism: burn-rate and every detector are property-tested for
  recompute-equality, and a fixed corpus yields byte-identical signed findings
  across runs and platforms (insta-style snapshots with sorted maps). A
  mixed-currency corpus returns `null` totals with per-currency partitions and
  never a coerced sum.
- Finding identity: exact detector-config digest and deterministic severity enter
  the complete unsigned-body ID. Parameter, threshold, severity, authority,
  evidence-ref and body-byte mutations change the ID; inserting different bytes
  under one ID conflicts.
- Velocity clustering: a fixture of sibling grants each just under the per-grant
  `VelocityGuard` ceiling produces exactly one aggregate finding only when the
  signed sibling lineage and complete range verify. Missing or forged lineage
  produces one incomplete-corpus signal and no finding.
- Cursor completeness: tenant and filter mismatch, retention floor, store
  generation change, missing batch, and altered checkpoint each return a typed
  gap and cannot produce a projection or finding. Valid global-sequence gaps
  caused by tenant filtering remain complete only when the authenticated tenant
  projection plus predecessor/successor proof covers them. A root constructed
  from matching rows after filtering is rejected as insufficient.
  Out-of-order timestamps prove that a gap-free sequence cursor alone is
  insufficient; a complete tenant-time-index range with predecessor/successor
  boundaries succeeds, while an omitted tied-timestamp leaf or root mismatch
  emits incomplete corpus.
- Webhooks: authority events process strictly in proven sequence order even when
  workers receive higher sequences first. Threshold crossings fire only on the
  persisted below-to-above transition; replay dedupes; concurrent workers
  produce one crossing and one delivery per active registration; one receipt
  crossing multiple thresholds produces distinct rows; and a new signed
  budget-authority version re-arms state. Crash tests before send, after send
  before acknowledgement, and after acknowledgement prove lease recovery and
  at-least-once delivery. Retry visibility/backoff, 429/5xx, permanent 4xx,
  exhaustion/dead-letter, stale lease tokens, restart drain, signature failure,
  gaps, and missing `HttpEgressContract` all follow the durable state machine.
  Read-only tenants cannot register or rotate a webhook, cross-tenant ownership
  rejects, and an unapproved destination never reaches the network.
- Underwriting: a spend-anomaly finding produces the expected
  `UnderwritingSignal` class and reason only under an opt-in matching policy and
  carries digest-bound evidence refs. Two findings may reference the same receipt
  and one finding may reference many receipts without key collisions. Local
  derivation is observed but an asserted source keeps the final finding asserted;
  imported findings are asserted, and incomplete-corpus signals never map.
  Permutations of same-subject/reason findings always retain the maximum class,
  evidence-class floor, and sorted union of evidence; a Guarded input can never
  suppress a Critical input through first-wins dedupe. Local and imported copies
  of the same finding round-trip through v2 with respectively recomputed local
  floor and `Asserted` cap; changing only the signed resolved class changes the
  signal id and fails verification. Changing only `tenant_id`, the tagged source
  arm, the verified spend evidence-policy body or envelope digest, or a legacy source-input
  digest/index also changes the signal id and fails verification. Spend reasons
  reject the legacy arm, and missing, extra, duplicate, or unsorted finding ids
  or evidence refs reject. Duplicate equal v1 signals upgrade by distinct exact
  array indexes. V1 upgrade requires an explicit trusted resolver for tenant,
  subject, evidence class, and source binding; downgrade rejects WS10 signals
  without dropping them.
- Imported-financial source binding mutates each credential body/envelope pair,
  source/presentation/resolved evidence class, source manifest, presentation,
  pinned verifier-policy id/body/generation, issuer-global lifecycle checkpoint,
  source-index proof, lifecycle result and lifecycle pin independently and
  rejects every mismatch.
  Count-only or raw-passport input cannot construct the v2 signal.
- Evidence-policy lifecycle: unknown authority or epoch, embedded-key
  substitution, wrong tenant/scope, duplicate detector versions, invalid
  validity, stale predecessor, concurrent activation, expiry, supersession, and
  revocation all deny. Exactly one policy-head CAS wins, tombstones remain, an
  unavailable resolver admits no spend signal, and accepted finding keys cannot
  widen local trust. The same suite covers signed decision-policy lifecycle; the
  unsigned built-in default can simulate but cannot persist.
- Decision v2 chain: strict v1/v2 dispatch, stable chain ID, exact sequence,
  predecessor body and envelope digests, input/report/policy binding, and one
  active head. Concurrent successors have one winner. Decision-policy or
  anomaly-policy rotation racing append causes the stale append to fail.
  Cross-tenant/subject/scope predecessor substitution, unknown version, v1-only
  restart over active v2, and v2-to-v1 conversion with spend or financial signals
  all reject. Downstream tagged references resolve the exact version and digest.
- Governance continuity: crash before staging, after stage, after external anchor
  CAS and after local finalize for policy activate/revoke and decision append.
  Recovery completes exactly one transition or retains the anchored predecessor.
  Old SQLite snapshot restore, anchor outage/divergence, policy rollback,
  decision-head Merkle substitution and clock regression deny current-use
  underwriting while the read-only spend stream remains available. Imported
  financial current-use tests rotate or expire the verifier-policy generation,
  advance/roll back issuer lifecycle generation, suspend/revoke a passport, and
  fail the generation anchor or per-passport pin; every case denies a previously
  favorable decision.
- Store migration: old and indexed cost queries match across null, minimum,
  maximum, currency, and boundary fixtures through `i64::MAX`. Fixtures at
  `i64::MAX + 1` and `u64::MAX` are validated against the Rust-parsed reference
  oracle, not the known-lossy legacy query. Every cost key is exactly eight bytes
  and lexicographic order matches unsigned numeric order. Row-count, root,
  extraction, in-range parity, tenant-time-index count/root mismatch, or
  reference-oracle mismatch aborts the transactional swap.
  Current-version schema corruption that substitutes columns, index order, or
  named immutability guards must fail on open without scanning receipt rows. A
  one-reader pool must complete page and count from one snapshot. Query-plan
  assertions require the cost index for both bounded statements.
- Conformance: `chio.spend.*` and underwriting-v2 schema coverage plus registry, hash manifest,
  `KNOWN_SIGNED_ARTIFACT_SCHEMAS`, positive fixtures, and unknown-schema
  negatives; the workspace gate passes.

## Implementation phases

1. Reuse-first contracts and schemas. Add pure spend projection, complete-corpus,
   lineage-verification, and detector modules to `chio-metering`; add checked
   burn-rate math, schema ids, `spec/schemas/chio-spend/`, every signed-schema
   gate, and the `spec/PROTOCOL.md` spend-family subsection. No I/O and no new
   crate unless a demonstrated dependency boundary requires one.
2. Read surface and indexed query path. Add `/v1/spend/stream`,
   explicit cursor/gap/checkpoint semantics, the transactional derived cost-key,
   tenant sequence and time projections, and cost-index migration, spend metrics
   in `chio-metrics-spec`, and the `chio spend stream` CLI.
3. Analytics and underwriting loop. Add exact time-index range proofs,
   `GET /v1/reports/burn-rate`, `GET /v1/reports/spend-anomalies`,
   `chio spend burn-rate|anomalies`, incomplete-corpus signals, detector
   sidecar persistence, signed anomaly-evidence-policy contract, trust resolver,
   signed decision-policy contract, both lifecycle stores and tenant-admin APIs,
   external underwriting-governance anchor, staged recovery and decision-head
   Merkle proofs, the jointly coordinated
   `UnderwritingSignalV2` and policy-input-v2 resolved evidence-class binding,
   explicit v1 conversion, strict decision-report-v2 and decision-v2 chains,
   tagged downstream references, and policy-gated reason/evidence variants with
   deterministic strongest-signal merging. Phase exit requires policy-head,
   decision-head, anchor crash/rollback and concurrency tests plus every
   signed-schema gate.
4. Durable webhooks. Add tenant-admin/write registration and operator-approved
   egress policy, ordered authority cursors, atomic threshold/crossing/delivery
   insertion, leased retry/ack/dead-letter workers, restart recovery, signed
   delivery, and the `chio spend webhook add|list` CLI.

## Resolved cuts

- Spend-pattern drift uses a declared fixed trailing baseline window in v1 so
  the statistic is recomputable; adaptive baselines are deferred.
- Velocity-guard trip events are not currently emitted as receipts or store
  events; the guard returns a deny decision inline (velocity.rs:177-179).
  A future guard-side signed event may add trip webhooks. V1 defers them rather
  than shipping a best-effort signal; velocity clustering remains a separate
  corpus detector over spend events.
