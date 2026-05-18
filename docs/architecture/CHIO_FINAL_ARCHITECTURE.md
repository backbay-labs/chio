# Chio Final Architecture

Status: architecture target, not an implementation patch
Date: 2026-05-18

This document defines the Chio-native architecture that absorbs Chiodos into
Chio. "Chiodos" remains useful as historical language for older signed
artifacts, fixtures, and implementation modules. It is not the future public
surface.

The public product model is:

- `chio federation`: treaty scope, governance ladders, peer pins, relay trust,
  bilateral co-signing, and federation authority material.
- `chio attest`: buyer and auditor proof verification, supply-chain
  attestation verification, and runtime quote verification under distinct
  subcommands.
- `chio runtime`: local live admission, trust-floor state, runtime proof
  regeneration, and operator-owned policy evaluation.
- `chio pheromone`: signed observation deposits, scarcity policy, concentration
  query, relay, catch-up, and receive reporting.

The rule is hard: new emitters, new schemas, new public commands, and new docs
use Chio names. Chiodos compatibility is allowed only where byte preservation
of already-signed artifacts requires it, or where a caller explicitly asks for
read-only historical verification.

## Current State Map

This section is grounded in the current dirty worktree on
`codex/chiodos-7-8-live-treaty-buyer-closure`. Line numbers are evidence, not a
stability promise.

### Pheromone substrate

- `crates/chio-pheromone/src/lib.rs:220` defines
  `ObservationCostVerificationMode`.
- `crates/chio-pheromone/src/lib.rs:227` defines
  `PheromoneScarcityPolicy` with `deny_unknown_fields`, but
  `newcomer_horizon_epochs` still has a Rust-side serde default at line 235.
  The target architecture forbids Rust-only defaults for live admission
  semantics.
- `crates/chio-pheromone/src/lib.rs:277` carries
  `PheromoneValidationContext.scarcity_policies`.
- `crates/chio-pheromone/src/lib.rs:318` to
  `crates/chio-pheromone/src/lib.rs:328` has in-memory counters keyed by
  epoch, window, treaty, namespace, class, kernel, and passport dimensions.
- `crates/chio-pheromone/src/lib.rs:503` still has an empty-policy
  compatibility fallback. That is acceptable only for explicit read-only
  historical verification, never for live receive.
- `crates/chio-pheromone/src/lib.rs:1017` verifies cost commitment binding by
  checking deposit fields against policy fields. It does not yet verify a
  signed verifier statement or telemetry-chain inclusion proof. That is a real
  P0 implementation gap for the final architecture.

### Pheromone runtime

- `crates/chio-pheromone-runtime/src/lib.rs:137` defines
  `PheromoneAdmissionPolicyDocument`.
- `crates/chio-pheromone-runtime/src/lib.rs:147` uses serde defaulting for
  `scarcity_policies`, which can keep live policy parsing compatible with
  empty-policy documents. Final live receive must reject that state.
- `crates/chio-pheromone-runtime/src/lib.rs:166` parses transit policy JSON,
  removes the `admission` object, and builds receiver config. This is the
  correct boundary for schema validation before serde.
- `crates/chio-pheromone-runtime/src/lib.rs:639` persists
  `chio_pheromone_scarcity_buckets`; line 655 begins the more granular pair
  bucket table. The persistent model is close to the target bucket scope.

### Relay

- `crates/chio-pheromone-relay/src/service.rs:421` enforces inbound batch peer
  roles and calls pinned ladder checks at line 445.
- `crates/chio-pheromone-relay/src/service.rs:496` validates catch-up
  requests. In the current worktree it checks `Receiver | Hub` at line 519 and
  treaty subscription at line 530.
- `crates/chio-pheromone-relay/src/service.rs:665` enforces outbound receiver
  or hub role, max batch size, treaty subscription, and pinned ladder refs.
- `crates/chio-pheromone-relay/src/service.rs:699` binds transit hops to
  directory-pinned ladder references.

The relay direction is right: access decisions use directory material, not
package-carried claims. Final architecture requires this discipline on every
relay path, including catch-up and future replay endpoints.

### Treaty, buyer proof, and DSSE

- `crates/chio-chiodos-runtime/src/treaty.rs:374` rejects destructive
  `crdt_commutative` action classes during computed intersection.
- `crates/chio-chiodos-runtime/src/treaty.rs:458` rejects the same invariant
  when loading an intersection. That is the correct fail-closed invariant.
- `crates/chio-chiodos-runtime/src/buyer/packet.rs:19` exposes a public
  hash-only buyer verifier. The current worktree returns unresolved when no
  hydrated DSSE hash is supplied at line 122. Final architecture makes that
  public semantic non-negotiable: hash-only paths can be informative, but they
  cannot be accepted.
- `crates/chio-chiodos-runtime/src/buyer/review_package.rs:226` hashes the
  hydrated bilateral DSSE and passes it into the packet verifier at line 227.
  That is the right full-review path.
- `crates/chio-chiodos-runtime/src/buyer/strict_dsse.rs:89` builds
  `TreatyBoundBilateralDsseReview` from verifier-owned package and trust
  context.
- `crates/chio-federation/src/bilateral_verifier.rs:494` defines
  `TreatyBoundBilateralDsseReview`; line 508 verifies the treaty-bound strict
  bilateral DSSE.
- `crates/chio-kernel/src/kernel/tests/federation_cosign.rs:334` verifies that
  runtime treaty metadata is preserved into kernel-produced DSSE. Line 439
  tests request, signer, lease, and governance mismatches fail closed.

### CLI and artifacts

- `crates/chio-cli/src/cli/types.rs:350` defines top-level
  `chio federation`.
- `crates/chio-cli/src/cli/types.rs:356` defines top-level `chio attest`.
- `crates/chio-cli/src/cli/types.rs:362` defines top-level `chio runtime`.
- `crates/chio-cli/src/cli/types.rs:368` defines top-level `chio pheromone`.
- `crates/chio-cli/src/cli/types.rs:374` still exposes `chio chiodos` as a
  compatibility surface. That is a transitional implementation fact, not the
  final public shape.
- `crates/chio-cli/src/cli/types.rs:529` normalizes the Chio-native commands
  back into `ChiodosCommands`. This is acceptable only as an intermediate
  implementation detail. Final handlers should be Chio-native and the legacy
  path should call into them, not the reverse.
- `docs/research/CHIODOS_3VENDOR_FIXTURE.md` says
  `chio attest verify` is the preferred command, with `chio chiodos verify` as
  a compatibility alias for signed artifacts.
- `spec/schemas/registry.json` already registers many Chio pheromone schema
  IDs, but their `artifactKind` values still say `chiodos_*`.
- `spec/schemas/MANIFEST.sha256` lists `cost-commitment.schema.json` and
  `transit-policy.schema.json`, but the current worktree has
  `spec/schemas/chio-pheromone/v1/scarcity-policy.schema.json` untracked and
  not listed in the manifest. Schema semantics are not finalized until the
  schema file is tracked, registered, and present in the manifest.
- `scripts/check-chiodos-pheromone-runtime.sh` and
  `scripts/check-chiodos-pheromone-transit.sh` validate Chio pheromone schema
  IDs but remain Chiodos-named gate scripts.
- `crates/chio-attest-verify/Cargo.toml:2` already defines
  `chio-attest-verify`; its description says it is the shared Sigstore
  verification surface for supply-chain attestation. Its README and lib trust
  boundary also cover Rekor, Fulcio, and TEE quote verification. Buyer proof
  verification must not be collapsed into that crate.

## Target Boundaries

### `chio-pheromone`

Owns pure signed deposit semantics:

- deposit body structs, canonical JSON, signatures, replay identity, and
  subject-class policy
- scarcity policy evaluation that is deterministic given a validation context
- concentration query math and evaporation
- no SQLite, HTTP, CLI, or runtime trust roots
- no dependency on reputation implementation; reputation enters as an injected
  weight function pinned to an epoch

The substrate must not accept live receive traffic when scarcity policy is
missing, ambiguous, stale, out of window, schema-invalid, or mismatched to
subject class and treaty.

### `chio-pheromone-runtime`

Owns live receiver admission:

- JSON schema validation before serde for runtime policy, peer weights,
  receive reports, query reports, and any configured verifier roots
- construction of `PheromoneValidationContext`
- SQLite persistence for deposits, replay nonces, scarcity buckets, pair
  buckets, passport caps, and passport first-seen history
- per-frame receive transactions: if cost verification, replay, scarcity, or
  persistence fails for a frame, that frame consumes no admission state while
  other valid frames in the batch may still commit
- explicit legacy mode for read-only historical verification only

The runtime layer is where Rust defaults are most dangerous. A schema-invalid
policy must not become valid through serde defaults.

### `chio-pheromone-relay`

Owns relay transport and directory-scoped authorization:

- HTTP endpoints and request signatures
- peer directory loading, rotation, and trust-source validation
- role enforcement for origin, hub, and receiver peers
- ladder manifest and intersection pins for transit hops
- bounded catch-up only when a receiver or hub is pinned, subscribed, and within
  catch-up limits

The relay is not an admission authority. It can deny delivery, but it must not
turn package-carried trust material into authority.

### `chio-federation`

Owns federation primitives:

- bilateral handshake and peer pinning
- treaty scope and governance ladder references
- strict DSSE verification
- pheromone gossip envelope semantics that are transport-independent
- future Chio-native schema IDs for treaty scope, ladder intersection, and
  cross-boundary admission

This crate should not know about CLI command compatibility.

### `chio-kernel`

Owns trusted runtime mediation:

- capability validation, guard evaluation, tool dispatch, and receipt signing
- runtime admission hook integration
- kernel-native federation co-signing
- strict DSSE production from runtime treaty material

Kernel-produced federation DSSE must carry the runtime treaty binding,
capability lease reference, governance receipt reference, policy summary,
consistency model, consistency anchor, signers, request hash, outcome hash, and
receipt hashes. If runtime material is missing or mismatched, the kernel denies
before emitting a DSSE envelope.

### `chio-attest-buyer`

Target module boundary, currently implemented through `chio-chiodos-runtime`:

- buyer and auditor proof package verification
- buyer packet and buyer review reporting
- selective disclosure proof verification
- trust-bundle and verifier-context validation
- strict DSSE hydration requirements

This crate is the future owner for cross-vendor buyer proof. It may depend on
`chio-federation` for treaty-bound DSSE verification, but it must not absorb
Sigstore or TEE quote verification.

The public hash-only buyer packet verifier may return a diagnostic report, but
`accepted` must be false unless hydrated DSSE bytes were supplied by the full
review path and verified under strict treaty-bound rules.

### `chio-attest-verify`

Existing crate boundary:

- supply-chain attestation verification
- Sigstore bundle, blob, and byte verification
- Fulcio, Rekor, TUF trust-root handling
- TEE quote verification behind feature gates
- tenant policy loading for expected certificate identity

This crate remains the single source of truth for Sigstore and TEE attestation.
It does not own buyer proof packages, pheromone cost commitments, or
cross-kernel treaty DSSE. The public `chio attest` namespace may expose both
families, but the crate boundaries stay separate:

- `chio attest buyer ...` routes to `chio-attest-buyer`
- `chio attest supply-chain ...` routes to `chio-attest-verify`
- `chio attest runtime-quote ...` routes to `chio-attest-verify`

### `chio-runtime`

Target module boundary, currently mixed through `chio-chiodos-runtime` and
runtime-spine fixtures:

- live admission profile, trust floor, trusted verifiers, peer weights, runtime
  evidence manifests, proof regeneration, and local orchestration reports
- no public Chiodos command naming
- no schema-invalid runtime policy accepted by Rust defaults

## Public CLI Model

The final public CLI is:

```text
chio federation authority ...
chio federation treaty ...
chio attest buyer verify ...
chio attest buyer packet ...
chio attest supply-chain verify ...
chio attest runtime-quote verify ...
chio attest legacy chiodos-v1 verify ...
chio runtime admit ...
chio runtime proof ...
chio runtime ops ...
chio pheromone receive ...
chio pheromone query ...
chio pheromone relay ...
```

Legacy command behavior:

- final public CLI has no `chio chiodos` command
- explicit read-only verification of historical signed artifacts lives under
  `chio attest legacy chiodos-v1 verify`
- bulk migration or byte-inspection tooling lives in a separate migration tool,
  not under the main public command tree
- transition-only `chio chiodos ...` wrappers, if kept while migrating the
  current codebase, must be hidden from normal help, must emit no new artifacts,
  and must delegate to Chio-native handlers
- legacy verification must not rewrite signed bytes, schema IDs, or canonical
  payloads

Hard cutover is cleaner than broad public backwards compatibility. Existing
callers that produce new artifacts should break loudly and move to Chio-native
commands.

## Schema and Artifact Naming

Final naming policy:

- New schema IDs use `chio.*`.
- New schema files live under Chio-native directories such as
  `spec/schemas/chio-pheromone/v1` and future `spec/schemas/chio-federation/v1`,
  `spec/schemas/chio-attest/v1`, and `spec/schemas/chio-runtime/v1`.
- `artifactKind` values in `spec/schemas/registry.json` use Chio-native names.
- Every schema semantic change requires three tracked changes in the same
  patch: schema file, registry entry, and `spec/schemas/MANIFEST.sha256`.
- Gate scripts must fail when a schema exists but is untracked, unregistered,
  or absent from the manifest.
- JSON schema is authoritative for external documents. Rust structs must use
  `deny_unknown_fields` for live policy documents, and defaults must be present
  in schema as explicit defaults or be rejected.

Legacy signed artifact policy:

- Existing signed artifacts with `chio.chiodos.*` schema IDs remain
  read-compatible when byte preservation matters.
- A compatibility verifier may accept deprecated IDs only when the caller
  explicitly selects historical verification or the verifier context marks the
  artifact as legacy signed material.
- Compatibility verification must never rewrite the signed bytes, schema ID, or
  canonical payload.
- New emitters must not create `chio.chiodos.*` artifacts.

## Scarcity Policy v1

Scarcity policy is receiver-owned admission policy. It is not an optional
metadata hint and not an origin-provided claim.

### Material

A complete scarcity policy contains:

- `schema`: `chio.pheromone-scarcity-policy.v1`
- `policyId`: stable receiver-owned policy identifier
- `reputationEpoch`: epoch whose peer weights and passport ages are in force
- `windowId`: deterministic hash of the active window tuple
- `windowStartUnixMs` and `windowEndUnixMs`
- `tokenCapacity`: count admitted per scarcity bucket
- `newcomerHorizonEpochs`: explicit value, no runtime default
- `treatyScope`: one or more treaty IDs this policy authorizes
- `subjectClassNamespace` and `subjectClass`
- `observationCostVerification`: `not_required` or `required`
- `verifierId`: cost verifier identity expected in commitments
- `runtimePolicySha256`: SHA-256 of the canonical signed runtime policy body
  that carried this scarcity policy
- `policySha256`: SHA-256 of the canonical scarcity policy body, excluding this
  field when present
- `activePeersEpoch`: epoch used to compute the sqrt cap

Verifier trust roots are not inline in the scarcity policy. They are resolved
from the same signed runtime policy through
`observationCostVerifierRoots`. A scarcity policy that requires cost
verification is invalid unless the runtime policy contains exactly one active
verifier root matching `(verifierId, treaty_id, namespace, class,
runtimePolicySha256)`.

`windowId` is deterministic, not a free label. It is:

```text
sha256_hex(JCS({
  "schema": "chio.pheromone-scarcity-window-id.v1",
  "reputationEpoch": reputationEpoch,
  "windowStartUnixMs": windowStartUnixMs,
  "windowEndUnixMs": windowEndUnixMs,
  "treatyId": treatyId,
  "subjectClassNamespace": subjectClassNamespace,
  "subjectClass": subjectClass
}))
```

### Admission Path

Live receive proceeds in this order:

1. Verify request authentication and batch recipient.
2. Validate transit policy against JSON schema before serde.
3. Extract admission material from receiver-owned policy.
4. Reject if no scarcity policies are present.
5. Establish `active_reputation_epoch` from receiver-owned runtime policy and
   peer weights. Deposit-carried epoch material is ignored.
6. Filter candidate policies by treaty, namespace, class,
   `reputationEpoch == active_reputation_epoch`, and
   `windowStartUnixMs <= receive_now_unix_ms < windowEndUnixMs`.
7. Recompute each candidate `windowId` and reject any mismatch.
8. Select exactly one active candidate. Zero matches reject with
   `scarcity_policy_missing`; more than one active candidate rejects with
   `scarcity_policy_ambiguous`.
9. Validate treaty scope, subject class, runtime policy hash, verifier ID,
   token capacity, and active-peer epoch.
10. Verify deposit schema, signature, passport, and replay nonce.
11. If cost verification is required, verify the observation-cost commitment
   under the rules below.
12. Check the scarcity bucket, pair bucket, and passport cap.
13. Persist deposit, replay nonce, buckets, passport first-seen history, and
    frame report atomically.
14. Return an accepted frame report only after the frame transaction commits.

Policy rotation:

- Future policies may be loaded before their window opens.
- Past policies may remain loaded for historical report regeneration.
- Live receive considers only active candidates after epoch and window
  filtering.
- Runtime policy load must reject overlapping active windows for the same
  `(reputation_epoch, treaty_id, namespace, class)`.
- If a staged rotation accidentally creates two active candidates, receive
  fails closed with `scarcity_policy_ambiguous`; it does not pick newest,
  highest `policyId`, or insertion order.

No-policy behavior:

- live `chio pheromone receive`: reject with `scarcity_policy_missing`
- live relay-to-receiver handoff: reject before storage
- read-only historical verifier: only under
  `chio attest legacy chiodos-v1 verify` or an equivalent non-live API, and the
  report must say policy was not enforced

### Bucket Scope

Scarcity buckets are keyed by:

```text
(reputation_epoch, window_id, treaty_id, subject_class_namespace, subject_class)
```

Pair buckets are keyed by:

```text
(reputation_epoch, window_id, treaty_id, subject_class_namespace,
 subject_class, kernel_id, agent_passport_key_hash)
```

Passport caps are keyed by:

```text
(reputation_epoch, window_id, treaty_id, subject_class_namespace,
 subject_class, kernel_id)
```

The cap counts distinct agent passport key hashes. The default cap is
`ceil(sqrt(active_peers_in_treaty))`, but final policy must persist the computed
active-peer epoch and cap used for every decision so concentration queries are
replayable.

### Batch Atomicity

Final receive semantics are per-frame transaction atomicity with explicit
partial-batch reporting.

- Each frame is evaluated and committed in its own transaction.
- An accepted frame persists its deposit, replay nonce, scarcity bucket
  increment, pair bucket increment, passport cap state, first-seen passport
  history, and frame report together.
- A rejected frame persists only its rejection report and consumes no replay,
  scarcity, pair, or passport-cap state.
- If persistence fails for a frame after validation, that frame is rejected with
  `storage_commit_failed` and consumes no admission state.
- Other valid frames in the same batch are not rolled back because one frame is
  invalid.
- The top-level receive report carries `batchOutcome`:
  `accepted`, `partial`, or `rejected`, plus accepted and rejected frame counts.
- The top-level `accepted` boolean is true only when `batchOutcome ==
  "accepted"`. Operators must inspect frame reports when `batchOutcome ==
  "partial"`.

This choice prevents one malformed or malicious frame from denying unrelated
valid gossip while keeping replay and bucket consumption deterministic.

### Newcomer Horizon

The newcomer horizon is policy material, not a library default. A passport's
effective weight is:

```text
min(1, (reputation_epoch - first_seen_epoch + 1) / newcomer_horizon_epochs)
```

The first-seen epoch must be persisted per `(kernel_id, agent_passport_key_hash,
treaty_id, namespace, class)` so restarts cannot reset discount history.

### Testable Invariants

- Empty scarcity policy rejects live receive.
- Unknown policy fields reject before serde.
- Missing explicit newcomer horizon rejects live receive.
- Ambiguous active matching policies reject after epoch and window filtering.
- Overlapping active windows for the same tuple reject at runtime policy load.
- Policy treaty not allowed by subject class rejects.
- Destructive subject class with missing cost commitment rejects.
- Replay nonce does not consume scarcity buckets twice.
- Rejected frames consume no replay, scarcity, pair, or passport-cap state.
- Persistence failure returns rejected for that frame and leaves no partial
  bucket increment.
- Restart preserves replay, bucket, and first-seen state.

## Observation-Cost Verification

Current implementation validates only field binding. Final verification must
prove that a trusted verifier attested real observation cost over telemetry
that includes this deposit's observed event.

### Verifier Trust Root

The receiver's signed runtime policy owns the verifier roots. The root schema is
`chio.pheromone-observation-cost-verifier-root.v1`:

- `schema`
- `verifierId`
- `verifierKeyId`
- `publicKey`: Chio `PublicKey::to_hex` encoding from
  `spec/schemas/signature.v1.json`
- `signatureAlgorithm`: `ed25519`, `p256`, `p384`, or `hybrid`
- `validFromUnixMs` and `validUntilUnixMs`
- `allowedTreaties`
- `allowedSubjectClassNamespaces`
- `allowedSubjectClasses`
- `runtimePolicySha256`
- `issuerKernelId`
- `issuerSignature`: signature by the runtime policy issuer over the canonical
  verifier-root body

Verifier roots are never accepted from the deposit, commitment, or relay frame.
They resolve only from the receiver-owned runtime policy. Revocation comes from
the receiver-owned Chio runtime trust-floor state, using final schema
`chio.runtime.trust-floor-state.v1` and current compatibility schema
`chio.chiodos.runtime-trust-floor-state.v1` until the schema cutover lands. A
verifier root is usable only when it is valid for `receive_now_unix_ms`, allowed
for the selected treaty and subject class, and not revoked in the current trust
floor. Live receive denies revoked roots even when the commitment was signed
before revocation; historical verification may expose an explicit as-of mode.

### Commitment Envelope

`chio.pheromone-cost-commitment.v1` contains exactly:

- `schema`: `chio.pheromone-cost-commitment.v1`
- `statement`: a `chio.pheromone-observation-cost-statement.v1` body
- `signature`: Chio `Signature::to_hex` over the RFC 8785 JCS bytes of
  `statement`

The statement body contains:

- `schema`: `chio.pheromone-observation-cost-statement.v1`
- `commitmentId`
- `verifierId`
- `verifierKeyId`
- `runtimePolicySha256`
- `scarcityPolicySha256`
- `depositBodySha256`
- `depositSignatureSha256`
- `kernelId`
- `agentPassportKeyHash`
- `treatyId`
- `subjectClassNamespace`
- `subjectClass`
- `observationWindowStartUnixMs`
- `observationWindowEndUnixMs`
- `observedAtUnixMs`
- `cost`: `{ "unit": "chio.observation.microunit.v1", "amount": u64 }`
- `telemetry`: a `chio.pheromone-observation-cost-telemetry-root.v1` body
- `inclusionProof`: the existing Chio Merkle proof shape from
  `spec/schemas/chio-wire/v1/receipt/inclusion-proof.schema.json`
- `leafPreimageSha256`

There is no currency field in the cost commitment. Economic conversion belongs
outside this verifier. The commitment proves observation work, measured in
`chio.observation.microunit.v1`.

### Telemetry Root and Leaf

The only v1 telemetry proof algorithm is `rfc6962-sha256-v1`, matching
`crates/chio-core-types/src/merkle.rs`:

- leaf hash: `SHA256(0x00 || leaf_bytes)`
- node hash: `SHA256(0x01 || left || right)`
- odd right-edge nodes are carried upward unchanged
- root and audit-path hashes use Chio `Hash` JSON encoding:
  `0x` plus 64 lowercase hex characters

The telemetry root body contains:

- `schema`: `chio.pheromone-observation-cost-telemetry-root.v1`
- `algorithm`: `rfc6962-sha256-v1`
- `rootHash`
- `treeSize`
- `verifierId`
- `verifierKeyId`
- `closedAtUnixMs`

The raw telemetry event is not copied into the deposit. The verifier computes
`eventDigestSha256` as the bare lowercase SHA-256 hex of the RFC 8785 JCS bytes
of `chio.pheromone-observation-event.v1`:

- `schema`: `chio.pheromone-observation-event.v1`
- `sourceSystemId`
- `eventId`
- `eventType`
- `eventPayloadSha256`
- `collectedAtUnixMs`

The verifier must retain the event descriptor and raw payload under its own
audit policy. The receiver validates the signed digest and Merkle inclusion; it
does not trust raw event bytes from the depositor.

The inclusion leaf preimage is the RFC 8785 JCS encoding of
`chio.pheromone-observation-cost-leaf.v1`:

- `schema`: `chio.pheromone-observation-cost-leaf.v1`
- `depositBodySha256`
- `depositSignatureSha256`
- `kernelId`
- `agentPassportKeyHash`
- `treatyId`
- `subjectClassNamespace`
- `subjectClass`
- `observedAtUnixMs`
- `eventDigestSha256`
- `cost`: `{ "unit": "chio.observation.microunit.v1", "amount": u64 }`
- `scarcityPolicySha256`
- `runtimePolicySha256`

`leafPreimageSha256` is the bare lowercase SHA-256 hex of these leaf bytes.
The receiver verifies the Merkle proof against the leaf bytes, not against an
opaque claimed leaf hash.

### Verification Rules

The receiver verifies:

1. Schema is known, registered, and manifest-tracked.
2. Runtime policy hash equals the receiver-owned signed runtime policy hash.
3. Scarcity policy hash equals the selected active scarcity policy hash.
4. `depositBodySha256` equals the canonical hash of the signed deposit body.
5. `depositSignatureSha256` equals the SHA-256 of the deposit signature
   encoding.
6. Kernel ID, passport key hash, treaty, namespace, class, verifier ID, and
   verifier key ID match the selected policy and deposit.
7. Observation window contains `observedAtUnixMs` and is contained within the
   selected scarcity window.
8. Cost unit is exactly `chio.observation.microunit.v1` and amount is positive.
9. Verifier key resolves to exactly one active runtime-policy verifier root.
10. Verifier signature encoding matches the verifier root algorithm and
   validates over the canonical statement bytes.
11. Verifier root is not revoked in the current runtime trust-floor state.
12. Telemetry algorithm is exactly `rfc6962-sha256-v1`.
13. `leafPreimageSha256` matches the canonical leaf bytes.
14. Inclusion proof verifies the leaf bytes against the telemetry root.
15. The telemetry root `treeSize` matches the proof `tree_size`.
16. The telemetry root closed time is within the statement observation window.

### Failure Semantics

Failures are fail-closed with distinct report codes:

- `observation_cost_commitment_missing`
- `observation_cost_commitment_schema_invalid`
- `observation_cost_policy_mismatch`
- `observation_cost_verifier_untrusted`
- `observation_cost_signature_invalid`
- `observation_cost_telemetry_root_mismatch`
- `observation_cost_inclusion_invalid`
- `observation_cost_window_mismatch`
- `observation_cost_revoked`
- `observation_cost_unit_invalid`
- `observation_cost_leaf_mismatch`
- `observation_cost_runtime_policy_mismatch`

The receive report must expose the specific code at frame level. Under
per-frame atomicity, accepted frames in a partial batch remain committed, but
the top-level `accepted` boolean is false when any frame rejects.

## Runtime Admission

Runtime admission is verifier-owned and fail-closed:

- trust floor comes from receiver-owned runtime policy and
  `chio.runtime.trust-floor-state.v1`
- observation-cost verifier roots come from
  `observationCostVerifierRoots` inside the signed runtime policy, never from
  deposit material
- peer weights are receiver-owned and pinned to a reputation epoch
- runtime policy must be schema-valid before serde
- no implicit defaults in Rust can authorize a missing field
- runtime reports carry the policy hash, schema IDs, verifier roots, and
  failure codes used for the decision
- runtime evidence manifests bind every file and signed artifact used to
  regenerate proof

`chio runtime` is not a synonym for "local fixture runner". It is the local
authority surface for live admission decisions.

## Buyer Proof

Buyer proof has two distinct APIs:

- Full review: package, hydrated DSSE bytes, trust bundle, verification context,
  and strict treaty-bound verification. This path may return `accepted: true`.
- Hash-only packet verification: packet plus hashes and reports. This path is a
  diagnostic preflight only and must return `accepted: false` unless the
  hydrated DSSE hash was supplied by the full review path after actual DSSE
  bytes were verified.

Required semantics:

- `verification_state = "unresolved"` means `accepted = false`.
- `verification_state = "hash_resolved"` means hydrated DSSE was available and
  matched the packet hash.
- Admission report claims about `bilateral_dsse` are never enough by
  themselves.
- CLI report output must surface unresolved DSSE plainly.
- The standalone buyer-packet CLI path must not look equivalent to full buyer
  review.

Supply-chain and runtime attestation are separate from buyer proof. They remain
owned by `chio-attest-verify` and appear under separate `chio attest
supply-chain` and `chio attest runtime-quote` subcommands.

## Federation, Treaty, and DSSE

Final federation architecture has four signed materials:

- treaty scope: participant set, treaty IDs, subject classes, validity window,
  required ladder manifest refs
- governance ladder manifest: action class, mode, destructive flag,
  consistency model, co-sign requirements, evidence requirements
- ladder intersection: co-signed intersection of participants' ladders
- strict bilateral DSSE: per-action receipt envelope signed by both kernels

Invariants:

- Destructive action classes cannot be `crdt_commutative`, neither when
  computing nor when loading an intersection.
- A strict DSSE must include treaty binding, subject, lease, governance receipt,
  consistency anchor, and pinned signers.
- Kernel-native DSSE must preserve runtime treaty material. Synthesizing generic
  DSSE from defaults is not acceptable for cross-kernel buyer proof.
- Mismatched request, signer, lease, governance, treaty, or subject material
  fails closed before DSSE emission or buyer acceptance.
- Package-carried trust material never overrides verifier-owned trust bundles.

## Relay Role and Pin Architecture

Relay access is directory-scoped:

- Origins and hubs can submit inbound batches.
- Receivers and hubs can receive outbound delivery.
- Receivers and hubs can request catch-up.
- Every path checks treaty subscription, peer role, size limits, and freshness.
- Any path that carries transit hops checks ladder manifest pins and intersection
  refs against directory material.
- Package-carried transit chains can describe a path, but they cannot authorize
  it.

Future replay or catch-up extensions must keep the same rule. A new endpoint is
unauthorized until it proves how it uses directory role and pin checks.

## Migration Plan

### Phase 0: Baseline freeze

- Land this architecture document.
- Record current dirty implementation state separately.
- Do not widen compatibility while trust-boundary gaps remain.

### Phase 1: P0 security and schema closure

- Remove empty scarcity policy acceptance from live receive.
- Validate runtime policy JSON against schema before serde.
- Require tracked schema, registry, and manifest updates in the same patch.
- Enforce deterministic scarcity policy rotation and active-window uniqueness.
- Implement per-frame transaction atomicity and partial-batch reporting.
- Define and register observation-cost statement, verifier-root, telemetry-root,
  and telemetry-leaf schemas.
- Add verifier trust roots to runtime policy.
- Implement signature and RFC 6962 Merkle inclusion verification.
- Replace string-equality cost checks with real proof verification.
- Add negative fixtures for untrusted verifier, invalid signature, bad Merkle
  path, stale window, revoked verifier, wrong unit, leaf mismatch, and deposit
  hash mismatch.

### Phase 2: Chio-native command ownership

- Move implementation ownership to Chio-native command handlers.
- Remove public `chio chiodos ...` from the final command surface.
- Add `chio attest legacy chiodos-v1 verify` for explicit read-only
  signed-artifact verification.
- Add CLI tests proving Chio-native paths do not normalize through legacy
  command ownership.
- Keep byte-preserving compatibility for existing signed fixtures.

### Phase 3: Chio schema cutover

- Introduce Chio-native schema IDs for attest, runtime, and federation artifacts.
- Dual-read old signed Chiodos IDs only in explicit historical verification.
- Single-write Chio-native IDs everywhere.
- Convert registry `artifactKind` values to Chio-native names.
- Regenerate manifest hashes.

### Phase 4: Module and crate convergence

- Split `chio-chiodos-runtime` into Chio-native modules or crates:
  `chio-attest-buyer`, `chio-runtime`, and `chio-federation` owned pieces.
- Keep existing `chio-attest-verify` focused on Sigstore and TEE verification.
- Rename gate scripts and fixture roots after signed-artifact compatibility is
  pinned.
- Remove public Chiodos docs except archive and migration notes.

## Backlog

### P0

- Live receive without explicit scarcity policy rejects.
  Acceptance: focused receive test proves empty `scarcityPolicies` cannot
  accept, while explicit legacy read-only verification remains separate.
- Scarcity policy rotation is deterministic.
  Acceptance: selection filters by receiver-owned reputation epoch and active
  window before uniqueness; overlapping active windows reject at policy load and
  at receive.
- Batch admission is per-frame atomic.
  Acceptance: valid frames in a mixed batch commit, rejected frames consume no
  replay or bucket state, and reports expose `batchOutcome = "partial"`.
- Observation-cost verification proves signatures and RFC 6962 telemetry
  inclusion.
  Acceptance: invalid verifier, invalid signature, invalid inclusion, stale
  window, revoked verifier, wrong unit, leaf mismatch, runtime policy mismatch,
  and deposit hash mismatch all reject with distinct codes.
- Runtime policy schema validation is authoritative.
  Acceptance: unknown fields, missing newcomer horizon, missing scarcity
  policies, and Rust-only defaults reject before admission.
- Schema registry and manifest discipline is enforced.
  Acceptance: gate fails if a schema file is untracked, unregistered, or missing
  from `MANIFEST.sha256`.

### P1

- Chio-native CLI handlers own implementation.
  Acceptance: `chio federation`, `chio attest`, `chio runtime`, and
  `chio pheromone` route directly to native handlers; no final public
  `chio chiodos` command remains.
- Hash-only buyer packet CLI exposes unresolved DSSE semantics.
  Acceptance: standalone hash-only verification returns `accepted: false`,
  `verification_state: unresolved`, and a failure code unless full review
  supplied hydrated DSSE.
- Relay role and pin checks cover every relay path.
  Acceptance: inbound, outbound, catch-up, and any replay endpoint have negative
  role and ladder-pin tests.
- Attestation boundaries are split.
  Acceptance: buyer proof moves toward `chio-attest-buyer`; existing
  `chio-attest-verify` remains the Sigstore and TEE verification crate and does
  not import buyer proof logic.

### P2

- Chio-native schema IDs for attest, runtime, and federation.
  Acceptance: new fixtures emit Chio-native IDs; old IDs remain
  read-compatible only in historical mode.
- Crate/module rename plan.
  Acceptance: `chio-chiodos-runtime` no longer owns public module names after
  split; signed fixture compatibility tests still pass.
- Rename scripts and docs.
  Acceptance: gate scripts use Chio names; Chiodos-named scripts are wrappers or
  removed.

### P3

- Remove deprecated public Chiodos command surface.
  Acceptance: `chio chiodos` is absent from the final public CLI; historical
  verification uses `chio attest legacy chiodos-v1 verify` or a
  separate migration tool.
- Clean artifact kind names.
  Acceptance: registry has no `chiodos_*` artifact kinds except deprecated
  historical entries with explicit status.
- Conformance suite for Chio-native federation, attest, runtime, and pheromone.
  Acceptance: external implementer can verify fixtures without relying on
  Chiodos docs.

## Required Validation Gates

For architecture-only changes:

- `git diff --check`
- em dash scan on edited docs

For implementation phases:

- `cargo fmt --all -- --check`
- `git diff --check`
- touched-file em dash scan
- focused unit tests for each invariant changed
- relevant gate scripts, including schema/manifest gates
- `cargo clippy --workspace -- -D warnings` before merging broad Rust changes

No broad cargo gate is required for this document-only architecture pass.

## Non-Goals

- Do not preserve public Chiodos compatibility for new artifacts.
- Do not rewrite bytes inside historical signed artifacts.
- Do not treat relay package material as trust authority.
- Do not solve scarcity by global lifetime counters.
- Do not put reputation weighting inside `chio-pheromone`.
- Do not let naming work hide trust-boundary fixes.

## Risks

- Current implementation can still drift because schema, registry, and manifest
  discipline is not fully enforced.
- The cost commitment path is not cryptographic enough yet.
- Runtime serde defaults can silently accept policy omissions unless schema
  validation is placed before parsing.
- A hard CLI cutover will break callers. That break is acceptable for new
  emitters because compatibility shims are more dangerous than explicit
  migration.
- The Chiodos schema tree will remain for old signed artifacts. The risk is
  manageable only if every such entry is marked as deprecated read-compatible
  and no new emitter writes it.
