# Chio Final Architecture

Status: architecture target, not an implementation patch

> **Large-doc status**
> - Category: live architecture contract.
> - Owner: Chio architecture and runtime maintainers.
> - Currentness: current for the v1 Chio architecture target; line-number
>   evidence is illustrative and must be rechecked against the live tree.
> - Last verification command: `python3 scripts/check-architecture-docs.py docs/architecture/CHIO_FINAL_ARCHITECTURE.md`.

This document defines the Chio architecture for federation, attest, runtime,
and pheromone surfaces.

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

The rule is hard: emitters, schemas, public commands, fixtures, and docs use
Chio names only. Historical artifact inspection belongs outside the active
runtime and attest surfaces.

## Current State Map

This section is grounded in the current source tree. Line numbers are evidence,
not a stability promise.

### Pheromone substrate

- `crates/trust/chio-pheromone/src/lib.rs:382` defines
  `ObservationCostVerificationMode`.
- `crates/trust/chio-pheromone/src/lib.rs:389` defines
  `PheromoneScarcityPolicy` with `deny_unknown_fields`, but
  `newcomer_horizon_epochs` is now an explicit field rather than a Rust-side
  serde default.
- `crates/trust/chio-pheromone/src/lib.rs:454` carries
  `PheromoneValidationContext.scarcity_policies`.
- `crates/trust/chio-pheromone/src/lib.rs:494` to
  `crates/trust/chio-pheromone/src/lib.rs:508` has in-memory counters keyed by
  epoch, window, treaty, namespace, class, kernel, and passport dimensions.
- `crates/trust/chio-pheromone/src/lib.rs:684` now rejects empty live scarcity
  policy material with `scarcity_policy_missing` instead of creating
  compatibility admissions.
- `crates/trust/chio-pheromone/src/lib.rs:1322` verifies observation-cost commitments
  by resolving receiver-owned verifier roots, checking trust-floor revocation,
  verifying the signed statement, and proving the RFC 6962 telemetry inclusion
  path.

### Pheromone runtime

- `crates/trust/chio-pheromone-runtime/src/lib.rs:40` defines
  `PheromoneRuntimeError`; workflow verification failures now use the
  Chio-owned `chio_workflow_verification` boundary rather than exposing the
  historical proof-package error type.
- `crates/trust/chio-pheromone-runtime/src/lib.rs:112` defines Chio-owned workflow
  proof-package, trust-bundle, and verification-context wrappers for public
  receiver construction, while the historical verifier types stay private
  backend details.
- `crates/trust/chio-pheromone-runtime/src/lib.rs:155` defines
  `PheromoneAdmissionPolicyDocument`.
- `crates/trust/chio-pheromone-runtime/src/lib.rs:227` validates the transit policy
  JSON schema before serde, line 239 rejects empty live scarcity policies, and
  line 246 rejects overlapping scarcity windows during policy load.
- `crates/trust/chio-pheromone-runtime/src/lib.rs:634` builds
  `VerifiedChioWorkflowResolver` from the Chio workflow wrappers and only then
  delegates to the historical verifier core for read-only proof-package
  validation.
- `crates/trust/chio-pheromone-runtime/src/lib.rs:639` persists
  `chio_pheromone_scarcity_buckets`; line 655 begins the more granular pair
  bucket table. The persistent model is close to the target bucket scope.

### Relay

- `crates/trust/chio-pheromone-relay/src/service.rs:421` enforces inbound batch peer
  roles and calls pinned ladder checks at line 445.
- `crates/trust/chio-pheromone-relay/src/service.rs:498` validates catch-up
  requests. In the current worktree it checks `Receiver | Hub` at line 521 and
  treaty subscription at line 532. Returned catch-up frames are rechecked
  against requester directory ladder pins at line 541 before a successful
  response is served.
- `crates/trust/chio-pheromone-relay/src/service.rs:682` enforces outbound receiver
  or hub role, max batch size, treaty subscription, and pinned ladder refs.
- `crates/trust/chio-pheromone-relay/src/service.rs:716` binds transit hops to
  directory-pinned ladder references.

The relay direction is right: access decisions use directory material, not
package-carried claims. Final architecture requires this discipline on every
relay path, including catch-up and future replay endpoints.

### Treaty, buyer proof, and DSSE

- `crates/kernel/chio-runtime-core/src/treaty.rs:374` rejects destructive
  `crdt_commutative` action classes during computed intersection.
- `crates/kernel/chio-runtime-core/src/treaty.rs:458` rejects the same invariant
  when loading an intersection. That is the correct fail-closed invariant.
- `crates/kernel/chio-runtime-core/src/buyer/packet.rs:19` exposes a public
  hash-only buyer verifier. The current worktree returns unresolved when no
  hydrated DSSE hash is supplied at line 122. Final architecture makes that
  public semantic non-negotiable: hash-only paths can be informative, but they
  cannot be accepted.
- `crates/kernel/chio-runtime-core/src/buyer/review_package.rs:226` hashes the
  hydrated bilateral DSSE and passes it into the packet verifier at line 227.
  That is the right full-review path.
- `crates/kernel/chio-runtime-core/src/buyer/strict_dsse.rs:89` builds
  `TreatyBoundBilateralDsseReview` from verifier-owned package and trust
  context.
- `crates/trust/chio-federation/src/bilateral_verifier.rs:494` defines
  `TreatyBoundBilateralDsseReview`; line 508 verifies the treaty-bound strict
  bilateral DSSE.
- `crates/trust/chio-federation/src/bilateral.rs`,
  `crates/trust/chio-federation/src/bilateral_dsse.rs`, and
  `crates/trust/chio-federation/src/bilateral_verifier.rs` expose production
  documentation and verifier error text as strict Chio bilateral DSSE wording.
- `crates/trust/chio-federation/src/lib.rs` and the active CLI receipt explain help
  text use Chio production wording for selective disclosure and DSSE
  conformance. Focused public-surface guards keep retired wording out of active
  production comments.
- `crates/kernel/chio-kernel/src/kernel/tests/federation_cosign.rs:334` verifies that
  runtime treaty metadata is preserved into kernel-produced DSSE. Line 439
  tests request, signer, lease, and governance mismatches fail closed.

### CLI and artifacts

- `crates/products/chio-cli/src/cli/types.rs:350` defines top-level
  `chio federation`.
- `crates/products/chio-cli/src/cli/types.rs:356` defines top-level `chio attest`.
- `crates/products/chio-cli/src/cli/types.rs:362` defines top-level `chio runtime`.
- `crates/products/chio-cli/src/cli/types.rs:368` defines top-level `chio pheromone`.
- `crates/products/chio-cli/src/cli/types.rs` now gives the public `chio runtime` and
  `chio pheromone` command trees Chio-named type boundaries
  (`ChioRuntimeCommands` and `ChioPheromoneCommands`).
- The public `chio federation authority` and `chio federation treaty` command
  trees now use Chio-named type boundaries (`ChioAuthorityCommands` and
  `ChioTreatyCommands`).
- The nested public `chio federation authority trust-bundle` tree now uses
  `ChioTrustBundleCommands`.
- `spec/schemas/registry.json` registers active Chio schema IDs with Chio-native
  `artifactKind` values. The schema registry gate fails active Chio schema
  files whose JSON Schema `title` uses retired naming, and fails active Chio
  schema text under the checked schema roots, including
  `spec/schemas/chio-wire/`, when stale wording appears.
- `spec/schemas/MANIFEST.sha256` lists `cost-commitment.schema.json` and
  `scarcity-policy.schema.json` plus `transit-policy.schema.json` under
  `spec/schemas/chio-pheromone/v1/`.
- `spec/schemas/chio-federation/v1/` now owns the active federation authority
  wrapper schemas for authority profiles, issuance requests, issuance bundles,
  local signing keys, revocation publication requests, revocation checkpoints,
  peer pins, and verifier trust bundles. New authority emitters write
  `chio.federation.*` wrapper IDs.
- `cargo xtask check fixtures runtime`,
  `cargo xtask check fixtures transit`, and
  `scripts/check-chio-authority-issuance.sh` own Chio pheromone schema,
  fixture, public receive/query CLI validation, and federation authority
  issuance validation.
- `cargo xtask check fixtures <relay-facet>` and
  `cargo xtask check fixtures directory-lifecycle` own relay, relay ops,
  directory lifecycle, observability, and relay alert validation. The 15
  pheromone facets are enumerated in `ci-gates/pheromone.toml`.
- `scripts/check-chio-runtime-spine.sh`, `scripts/check-chio-runtime-policy.sh`,
  `scripts/check-chio-runtime-proof-parity.sh`,
  `scripts/check-chio-runtime-ops-hardening.sh`, and
  `scripts/check-chio-runtime-orchestration.sh` own runtime spine, policy, proof
  parity, ops, and orchestration validation.
- `scripts/check-chio-proof-package.sh`,
  `scripts/check-chio-treaty-bound-provenance.sh`, and
  `scripts/check-chio-live-treaty-buyer-closure.sh` own proof package,
  treaty-bound provenance, and live treaty buyer closure validation.
- `spec/CHIO_PHEROMONE.md` and
  `docs/release/CHIO_PHEROMONE_RELAY_RUNBOOK.md` are the active Chio-named
  pheromone spec and relay runbook, and `docs/release/chio-pheromone-relay/`
  owns the active relay operator examples. The active Chio pheromone spec no
  longer cites Chio-named design docs, and the Chio pheromone transit gate
  rejects reintroduction of Chio-named references in that active spec. The
  active Chio relay runbook likewise contains only Chio-native operator
  wording, and the relay gate rejects retired references in that runbook.
- Generated help for normal public Chio federation, runtime, and pheromone
  commands uses Chio material names.
- `chio receipt explain bilateral` JSON and human output now describe legacy
  DualSignedReceipt as non-section-6 conformant and the DSSE artifact as
  treaty-bound Chio bilateral invocation material without emitting the old
  Chio bilateral spec path.
- `crates/trust/chio-attest-buyer/src/lib.rs` is now the Chio-named buyer proof API
  boundary. It now accepts live `chio.attest.buyer-attestation-packet.v1`
  packets and `chio.attest.buyer-attestation-review-package.v1` full review
  packages, and emits Chio verification and review report schemas, while using
  the hardened buyer core for strict DSSE semantics.
  Fallible public helpers now return the Chio-owned `BuyerAttestationError`
  rather than publicly aliasing or reexporting the historical runtime error.
- `crates/products/chio-cli/src/cli/chio/dispatch/buyer.rs` exposes Chio-named buyer
  command handlers. `chio attest buyer ...` routes through those handlers.
  Buyer proof replay runs through Chio buyer APIs, so the CLI no longer names
  `chio_attest_buyer_core::` or `chio_runtime_core::` inside the buyer dispatch
  module.
- `crates/products/chio-cli/src/cli/chio/dispatch/buyer.rs` exposes
  `cmd_chio_attest_buyer_verify_proof` for Chio-native proof-package
  verification.
- `crates/products/chio-cli/src/cli/chio/dispatch/pheromone/runtime.rs:27` and
  line 109 expose Chio-named pheromone receive and query handlers. The public
  `chio pheromone receive/query` dispatcher calls those handlers in
  `crates/products/chio-cli/src/cli/dispatch`.
- `crates/products/chio-cli/src/cli/chio/dispatch/pheromone/*.rs` expose Chio-named
  relay handlers for core relay, alert routing, delivery evidence, assurance
  export/replay/recovery/archive/closeout, peer-directory rotation, and
  supervisor lint. Public `chio pheromone ...` dispatch now uses Chio-named
  command enum matches and calls Chio-named relay handlers throughout.
- The root public `chio pheromone relay` command tree now uses
  `ChioPheromoneRelayCommands`.
- The public `chio pheromone relay alert`, `directory`, and `supervisor`
  subtrees now use Chio-named type boundaries.
- Nested `chio pheromone relay alert delivery` and `alert assurance` subtrees
  now use Chio-named type boundaries.
- `crates/products/chio-cli/src/cli/chio/dispatch/runtime/*.rs` expose Chio-named
  runtime handlers for admission, signing and peer-weight hashing, pheromone
  evaluation, orchestration, operations, retention planning, and loopback.
  Public `chio runtime ...` dispatch now uses Chio-named command enum matches
  and calls only Chio-named runtime handlers.
- Nested public `chio runtime policy`, `peer-weights`, `pheromone`,
  `orchestrate`, `ops`, and `ops retention` subtrees now use Chio-named type
  boundaries.
- `crates/kernel/chio-runtime/src/lib.rs` is now the Chio-named runtime admission and
  orchestration facade. Public `chio runtime ...` dispatch modules call
  `chio_runtime::` instead of naming `chio_runtime_core::` directly. The
  facade now uses explicit runtime API exports rather than a wildcard reexport
  of the runtime core, and its named public runtime error is no longer a type
  alias to the lower-level runtime error. Its public kernel hook is
  `ChioRuntimeAdmissionHook`. CLI-facing fallible runtime facade
  helpers now return `chio_runtime::ChioRuntimeError` through thin wrappers
  instead of direct-reexporting historical helper signatures.
- `crates/products/chio-cli/src/cli/chio/dispatch/treaty.rs` exposes Chio-named
  federation treaty handlers for intersection, admission, and packet
  verification. Public `chio federation authority ...` and
  `chio federation treaty ...` dispatch uses Chio-named command enum matches
  and calls those handlers.
  Treaty intersection and cross-boundary admission helpers now live in
  `chio-federation`, so the Chio federation treaty handler no longer calls
  `chio_runtime_core::` directly.
- Treaty evidence validators now accept Chio-native federation IDs for
  cross-kernel continuations, receipt lineage statements, receipt lineage
  bundles, and bilateral invocations.
- `crates/products/chio-cli/src/cli/chio/dispatch/authority.rs` exposes Chio-named
  federation authority handlers for issuance, checkpoint publication, and trust
  bundle assembly. Public `chio federation authority ...` dispatch calls those
  handlers.
- `crates/trust/chio-attest-verify/Cargo.toml:2` already defines
  `chio-attest-verify`; its description says it is the shared Sigstore
  verification surface for supply-chain attestation. Its README and lib trust
  boundary also cover Rekor, Fulcio, and TEE quote verification. Buyer proof
  verification must not be collapsed into that crate.
- `chio attest runtime-quote verify` must not return success from
  `report-data` equality alone. Report-data-only mode is an unresolved
  diagnostic; accepted verification requires quote bytes, a TEE kind, verifier
  collateral, and a `chio-attest-verify` backend compiled through the
  `tee-quotes` feature.

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
- Chio-native schema IDs for treaty scope, ladder intersection, and
  cross-boundary admission, with legacy Chio IDs accepted only for
  compatibility reads

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

Target module boundary, with the first public API extraction now present:

- buyer and auditor proof package verification
- buyer packet and buyer review reporting
- selective disclosure proof verification
- trust-bundle and verifier-context validation
- strict DSSE hydration requirements

This crate is the future owner for cross-vendor buyer proof. The current slice
bridges to `chio-runtime-core` to preserve the strict DSSE semantics while
moving callers to the Chio-named boundary. The live packet/report boundary now
uses `chio.attest.buyer-attestation-packet.v1` and
`chio.attest.buyer-attestation-verification-report.v1`; the live full review
boundary now uses `chio.attest.buyer-attestation-review-package.v1` and
`chio.attest.buyer-attestation-review-report.v1`. Legacy proof replay for full
buyer review now lives behind the `chio-attest-buyer` API instead of the CLI.
Fallible JSON, hash, packet, review, and lineage helper APIs now return the
Chio-owned `BuyerAttestationError`. Public buyer packet, review, lineage,
continuation, bilateral invocation, runtime evidence manifest, report, and
schema-ID types are Chio-owned in this crate; historical Chio runtime shapes
are private conversion targets at the strict verifier edge. It may depend on
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

Target module boundary, now present as a Chio-named explicit API boundary over
the historical runtime core while the implementation split continues:

- live admission profile, trust floor, trusted verifiers, peer weights, runtime
  evidence manifests, proof regeneration, and local orchestration reports
- no public Chio command naming
- no schema-invalid runtime policy accepted by Rust defaults

The facade no longer wildcard-reexports the historical core and no longer
aliases the historical runtime error as its named Chio runtime error. It also
exposes a Chio-named admission hook wrapper instead of reexporting
`ChioRuntimeAdmissionHook`. Public runtime admission evaluation now takes
`ChioRuntimeAdmissionInput` and a `ChioRuntimeAdmissionStore` trait object, so
callers no longer need to name the historical runtime admission input or store
traits.

## Public CLI Model

The final public CLI is:

```text
chio federation authority ...
chio federation treaty ...
chio attest buyer verify ...
chio attest buyer packet ...
chio attest supply-chain verify ...
chio attest runtime-quote verify ...
chio attest buyer verify-proof ...
chio runtime admit ...
chio runtime proof ...
chio runtime ops ...
chio pheromone receive ...
chio pheromone query ...
chio pheromone relay ...
```

Retired command behavior:

- the final public CLI has no retired product command tree
- proof-package verification lives under `chio attest buyer verify-proof`
- bulk migration or byte-inspection tooling lives in a separate migration tool,
  not under the main public command tree
- active commands emit only Chio-native schema IDs

Hard cutover is cleaner than broad public backwards compatibility. Existing
callers that produce old artifacts should break loudly and move to Chio-native
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

Signed artifact policy:

- active attest, federation, runtime, and pheromone artifacts use Chio-native
  schema IDs
- registry entries backed by retired schema roots are removed from the active
  registry
- active verifiers reject retired proof schema IDs instead of silently accepting
  them
- migrations regenerate fixtures and signed material through Chio-native
  emitters rather than preserving old IDs

Current enforcement: `scripts/check-chio-schema-registry.sh` fails any active
Chio schema file that is not tracked by Git, any active Chio schema file absent
from `registry.json` or `MANIFEST.sha256`, any registry entry that points at
the retired schema root, and any active Chio schema text that permits retired
schema IDs.

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
- offline proof-package inspection may report that scarcity policy was not
  enforced only when it is explicitly outside live receive

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

Current implementation verifies more than field binding: live admission resolves
trusted verifier roots from receiver-owned runtime policy, rejects revoked
roots, verifies the signed cost statement, reconstructs the telemetry leaf, and
checks the RFC 6962 inclusion proof for this deposit's observed event.

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
`chio.runtime.trust-floor-state.v1`. A verifier root is usable only when it is valid for
`receive_now_unix_ms`, allowed for the selected treaty and subject class, and
not revoked in the current trust floor. Live receive denies revoked roots even
when the commitment was signed before revocation; historical verification may
expose an explicit as-of mode.

Current verification:
`cargo xtask check fixtures runtime --schema-only` validates a Chio-native
trust-floor state against
`spec/schemas/chio-runtime/v1/trust-floor-state.schema.json`.

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
`crates/core/chio-core-types/src/merkle.rs`:

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

## Historical Verification Boundary

Active emitters, schemas, commands, fixtures, and docs use Chio names. Verifiers
may still recognize deprecated schema IDs when checking old signed artifacts
because historical verification must preserve exact bytes and schema IDs already
present in signed receipts. That compatibility path is read-only and does not
authorize new artifact emission.

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

- Do not preserve public Chio compatibility for new artifacts.
- Do not rewrite bytes inside historical signed artifacts.
- Do not treat relay package material as trust authority.
- Do not solve scarcity by global lifetime counters.
- Do not put reputation weighting inside `chio-pheromone`.
- Do not let naming work hide trust-boundary fixes.

## Risks

- Release qualification can still drift because schema, registry, and manifest
  discipline is enforced by focused gates rather than one complete release
  qualification suite.
- The cost commitment path now has signed-statement and Merkle-inclusion
  coverage, but it still needs broader fixture and conformance coverage before
  external implementers can rely on it without repo-specific tests.
- New runtime policy loaders must keep schema validation before serde parsing;
  direct parsing outside the validated path can reintroduce silent omissions.
- A hard CLI cutover will break callers. That break is acceptable for new
  emitters because compatibility shims are more dangerous than explicit
  migration.
- Retired schema roots are removed from the active registry; the remaining risk
  is new emitters accidentally writing retired IDs.
