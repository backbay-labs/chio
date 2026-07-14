# chio-pheromone-runtime

`chio-pheromone-runtime` is the local Chio pheromone receiver: it turns a
signed transit policy and a gossip batch into durably-admitted deposits,
enforcing replay, scarcity, and diversity limits against a SQLite store. It
also verifies that an admitted deposit's Chio workflow context matches a
cryptographically verified workflow proof package.

Use this crate to run a local pheromone receiver. The shared deposit and
transit-evidence types live in `chio-pheromone`; the networked relay that
forwards signals between participants is `chio-pheromone-relay`.

## Responsibilities

- Load a signed transit policy document (`runtime_policy_from_json`):
  schema-validate it, verify the envelope signature, check the signer against
  both the trust-bundle and admission issuer roots, and reject empty or
  overlapping scarcity policies.
- Load and validate a peer-weights document (`peer_weights_from_json`) into a
  `StaticPeerWeightProvider`.
- Verify a Chio workflow proof package against a trust bundle and
  verification context, and bind admitted deposits to that verified workflow
  through `VerifiedChioWorkflowResolver`.
- Define the storage-agnostic `PheromoneRuntimeStore` trait for batch
  receive, deposit admission, deposit/concentration queries, and
  receive-report persistence, with fail-closed defaults for unscoped or
  non-atomic implementations.
- Implement `SqlitePheromoneRuntimeStore`: replay-nonce tracking,
  scarcity/diversity/sqrt-N rate limiting, atomic per-batch receive with
  per-frame savepoints, and crash-recovery report lookup.
- Compute pheromone concentration (decayed strength, peer weighting,
  newcomer discount) over admitted deposits.

## Public API

- `PheromoneReceiver<S, R>` - ties a `PheromoneRuntimeStore` and
  `WorkflowContextResolver` to one `PheromoneReceiverConfig`; `new`, `store`,
  `receive_batch`, `query_concentration`.
- `PheromoneRuntimeStore` - the storage trait (`receive_batch`,
  `admit_deposit`, `admit_deposit_for_treaty`, `query_deposits`,
  `query_concentration`, `record_receive_report`, `receive_reports`).
- `store::SqlitePheromoneRuntimeStore` - SQLite implementation: `open`,
  `open_in_memory`, `lookup_receive_report_by_batch`.
- `runtime_policy_from_json`, `runtime_policy_document_sha256` - verify and
  load a signed transit policy into `(PheromoneTransitPolicy,
  PheromoneReceiverConfig)`.
- `peer_weights_from_json`, `PeerWeightProvider`, `StaticPeerWeightProvider` -
  per-kernel weighting for concentration queries.
- `WorkflowContextResolver`, `VerifiedChioWorkflowResolver` - bind an
  admitted deposit's workflow context to a verified Chio workflow proof
  package.
- `ChioWorkflowProofPackage`, `ChioWorkflowVerifierTrustBundle`,
  `ChioWorkflowVerificationContext` - Chio-named wrappers around
  `chio-attest-buyer-core` verification inputs.
- `PheromoneRuntimeError` - error enum; `.code()` returns a stable string
  code (for example `replay_window_exceeded`, `rate_limit_exhausted`,
  `schema_invalid`).
- `PheromoneReceiveReport`, `PheromoneFrameReport`, `PheromoneBatchOutcome`,
  `PheromoneQueryReport` - receive/query result types.

## Usage

```rust
use chio_pheromone_runtime::store::SqlitePheromoneRuntimeStore;
use chio_pheromone_runtime::{
    runtime_policy_from_json, ChioWorkflowProofPackage, ChioWorkflowVerificationContext,
    ChioWorkflowVerifierTrustBundle, PheromoneReceiver, VerifiedChioWorkflowResolver,
};

let trust_bundle = ChioWorkflowVerifierTrustBundle::from_json(&trust_bundle_json)?;
let (transit_policy, config) = runtime_policy_from_json(
    &policy_json,
    now_unix_ms,
    trust_bundle.runtime_policy_issuer_public_keys(),
)?;
let resolver = VerifiedChioWorkflowResolver::from_verified_package(
    &ChioWorkflowProofPackage::from_json(&package_json)?,
    &trust_bundle,
    &ChioWorkflowVerificationContext::from_json(&context_json)?,
)?;
let store = SqlitePheromoneRuntimeStore::open("pheromone.sqlite3")?;
let receiver = PheromoneReceiver::new(store, resolver, config);

let report = receiver.receive_batch(&gossip_batch, &transit_policy)?;
```

## Testing

`cargo test -p chio-pheromone-runtime`

## See also

- `chio-pheromone` - shared pheromone deposit, scarcity-policy, and
  transit-evidence types and validation this crate calls during admission
  and query.
- `chio-pheromone-relay` - the networked relay that forwards pheromone
  signals between participants; this crate is the local receiver
  counterpart.
- `chio-federation` - pheromone gossip batch/frame types and envelope
  verification (`pheromone_gossip` module).
- `chio-attest-buyer-core` - Chio workflow proof-package verification
  wrapped by this crate's Chio-named types.
