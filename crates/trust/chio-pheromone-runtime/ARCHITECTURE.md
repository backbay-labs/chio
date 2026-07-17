# chio-pheromone-runtime architecture

## Overview

`chio-pheromone-runtime` is the local receive-side trust boundary for Chio
pheromone signals. It holds the only durable state in the pheromone stack
(admitted deposits, replay nonces, scarcity/diversity counters, and receive
reports) in a SQLite store, and gates every admission on a signed transit
policy, replay/scarcity/diversity checks, and optional Chio workflow
verification. Deposit and scarcity-policy semantics belong to
`chio-pheromone`; gossip transport and envelope shapes belong to
`chio-federation` and `chio-pheromone-relay`; this crate is the durable,
policy-enforcing landing point between them.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | `PheromoneRuntimeError`; Chio-named workflow wrappers (`ChioWorkflowProofPackage`, `ChioWorkflowVerifierTrustBundle`, `ChioWorkflowVerificationContext`) and `VerifiedChioWorkflowResolver`; signed transit-policy loading (`runtime_policy_from_json`) and embedded-schema validation; peer-weights loading (`peer_weights_from_json`) and `StaticPeerWeightProvider`; the `PheromoneRuntimeStore`, `WorkflowContextResolver`, `PeerWeightProvider` traits; `PheromoneReceiver`. |
| `src/store.rs` | `SqlitePheromoneRuntimeStore`: schema migrations, atomic batch receive with per-frame `SAVEPOINT`s, scarcity/diversity/sqrt-N admission bookkeeping, replay-nonce tracking, crash-recovery report lookup, deposit and concentration queries. |
| `schemas/transit-policy.schema.json`, `schemas/peer-weights.schema.json` | JSON Schema (draft 2020-12) contracts for the signed transit-policy envelope and the peer-weights document, embedded via `include_str!` and enforced before serde deserialization. |

## Batch receive lifecycle

1. The caller loads a signed transit policy with `runtime_policy_from_json`,
   which schema-validates the raw JSON, verifies the `SignedExportEnvelope`
   signature, requires the signer to be trusted by both the caller-supplied
   issuer keys and the admission document's own issuer roots, and rejects
   empty or overlapping scarcity policies. This yields a
   `PheromoneTransitPolicy` and a `PheromoneReceiverConfig`.
2. The caller builds a `WorkflowContextResolver` (usually
   `VerifiedChioWorkflowResolver::from_verified_package`, which verifies a
   Chio workflow proof package against a trust bundle and verification
   context) and a `PheromoneRuntimeStore` (usually
   `SqlitePheromoneRuntimeStore`), then combines them with the config in a
   `PheromoneReceiver`.
3. `PheromoneReceiver::receive_batch` forwards to the store.
   `SqlitePheromoneRuntimeStore::receive_batch` first verifies the
   whole-batch envelope (recipient, authenticated sender, time window); a
   failure records one batch-level rejection frame and returns.
4. Otherwise each frame is preflighted (transit-policy and envelope checks,
   then `WorkflowContextResolver::resolve` if the deposit carries a workflow
   context) and admitted inside its own SQL `SAVEPOINT`, so one frame's
   rejection rolls back only that frame's writes while the rest of the batch
   proceeds.
5. Admission validates the deposit's passport, claims a replay nonce, checks
   and increments the scarcity/pair/sqrt-N buckets, and inserts the deposit
   row keyed by its canonical SHA-256 (idempotent under `ON CONFLICT DO
   NOTHING`).
6. The resulting `PheromoneReceiveReport` is persisted in the same outer
   transaction before commit, so a durable report always corresponds to
   durable admission state; if report persistence fails, the whole
   transaction (including any frames admitted in step 5) rolls back.

## Invariants and failure modes

- `PheromoneRuntimeStore::receive_batch` and `admit_deposit_for_treaty`
  default to a hard error; only a store that opts into atomic, treaty-scoped
  persistence can serve live receive.
- A signed runtime policy is accepted only if its `SignedExportEnvelope`
  signature verifies and its signer key is present in both the
  caller-supplied trust-bundle issuer roots and the admission document's own
  `runtimePolicyIssuerPublicKeys`; a signer trusted only by the document it
  signs is rejected (`invalid_field`).
- JSON Schema validation runs on the raw `serde_json::Value` before typed
  deserialization, so a missing required field cannot be silently filled by
  a serde default and an unknown field cannot be silently dropped; the
  `deny_unknown_fields` structs the loaders populate enforce the same
  contract as defense in depth.
- Scarcity policies must be non-empty and pairwise non-overlapping per
  window; `runtime_policy_document_sha256` strips
  `runtimePolicySha256`/`policySha256`/`issuerSignature` before hashing so
  each scarcity policy's hash binds to the exact signed document without
  self-reference.
- Replay protection is a `(kernel_id, passport_key_hash, nonce)` insert that
  must affect a row (`ON CONFLICT DO NOTHING`, checked by affected-row
  count) or admission fails as `replay_window_exceeded`; expired nonces are
  purged first.
- Rate limiting is bucketed by `(reputation_epoch, window_id, treaty_id,
  subject_class_namespace, subject_class)`: a scarcity bucket rejects at
  `token_capacity`, a per-`(kernel_id, passport_key_hash)` bucket rejects at
  `max_deposits_per_pair`, and a sqrt-N cap rejects distinct passports per
  kernel above `ceil(sqrt(active_peers_in_treaty))`.
- A deposit's `workflow_context`, when present, must match the resolver's
  verified evidence field-for-field; any mismatch rejects the frame before
  storage.
- Crash-recovery lookup (`lookup_receive_report_by_batch`) is scoped to
  `(batch_sha256, authenticated_sender_kernel_id)` and prefers a committed
  admitting verdict (accepted or partial) over a later replay rejection of
  the same batch, so retrying after a crash cannot dead-letter
  already-admitted deposits.
- `query_concentration` rejects a `reputation_epoch` outside
  `known_reputation_epochs`; `StaticPeerWeightProvider` rejects non-finite or
  out-of-`[0,1]` weights.
- Public Chio-named wrapper types do not expose `chio_attest_buyer_core::`
  types or aliases through the public API (enforced by
  `tests/public_surface.rs`).
- `#![forbid(unsafe_code)]`.

## Dependencies

Internal: `chio-pheromone` supplies deposit, scarcity-policy, and
transit-evidence types and the validation functions
(`validate_deposit_for_admission`, `scarcity_admissions_for_deposit`,
`scarcity_admissions_for_deposit_treaty`, `newcomer_discount_for_deposit`,
`reject_overlapping_scarcity_windows`, `validate_scarcity_policy_material`)
this crate calls during admission and query. `chio-federation` supplies
`PheromoneGossipBatch`, `PheromoneTransitPolicy`, and gossip envelope/frame
verification (`pheromone_gossip` module). `chio-attest-buyer-core` supplies
Chio workflow proof-package, trust-bundle, and verification-context parsing
and verification, wrapped by this crate's Chio-named types so its own types
stay off the public surface. `chio-core-types` supplies canonical JSON
hashing (`canonical_json_bytes`, `sha256_hex`), `SignedExportEnvelope`, and
`PublicKey`.

External: `jsonschema` validates runtime-policy and peer-weights documents
against the embedded schemas; `rusqlite` backs
`SqlitePheromoneRuntimeStore`; `thiserror` derives `PheromoneRuntimeError`.

No dependency is aliased via `package = ...`; every `chio-*` dependency is
used under its own crate name.

## Extension points

- Implement `PheromoneRuntimeStore` for an alternative durable backend; the
  trait's default `receive_batch` and `admit_deposit_for_treaty` fail closed
  until overridden with an atomic, treaty-scoped implementation.
- Implement `WorkflowContextResolver` for a workflow-verification source
  other than `VerifiedChioWorkflowResolver`.
- Implement `PeerWeightProvider` for a weighting source other than
  `StaticPeerWeightProvider`.
