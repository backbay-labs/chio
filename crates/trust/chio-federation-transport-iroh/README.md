# chio-federation-transport-iroh

Iroh (QUIC, direct-dial) transport for `chio-federation`. iroh authenticates a
peer's transport key at the QUIC/TLS handshake; this crate resolves the
authenticated `EndpointId` to a `kernel_id` through an issuer-signed directory
and admits or rejects the connection before any lane handler runs. It sits
strictly underneath `chio-federation` and replaces no trust logic: the
per-frame verifiers `chio-federation` already runs stay unchanged above the
transport.

## Responsibilities

- Verify an issuer-signed transport-directory bundle at load time (schema pin,
  rollback gate, validity window, body-hash pin, issuer signature, per-entry
  passport endorsements) and build the `VerifiedDirectory` every other seam
  reads.
- Enforce a fail-closed, accept-time admission gate (`DirectoryGate`) shared by
  every lane: an `EndpointId` not bound to an admitted, non-removed
  `kernel_id` is rejected (403) before any lane handler runs.
- Carry `chio-federation`'s wire protocols over iroh, one lane per ALPN behind
  the shared gate: pheromone directed batches (lane a), revocation epoch roots
  (lane b), cross-operator gossip fan-out (lane c), bilateral DSSE co-signing
  (lane d).
- Implement `chio_federation::bilateral::BilateralCoSigningProtocol` so a
  networked co-signer (`IrohBilateralCoSigner`) can substitute for
  `chio-federation`'s in-process `InProcessCoSigner`.
- Serve bulk signed epoch roots content-addressed over iroh-blobs (lane e,
  paired with lane b) so catch-up does not have to inline a large history on
  the bounded direct stream.
- Bound every direct lane's accept path against slowloris and resource
  exhaustion: per-phase timeouts plus lane-wide and per-peer concurrency caps.
- Emit hand-rolled `chio_federation_transport_*` Prometheus metrics and
  `tracing` spans for admission, verification, lane outcomes, and directory
  reloads.

## Public API

- `admission::DirectoryGate` - the accept-time `EndpointHooks` gate shared by
  every lane; `NOT_ADMITTED_ERROR_CODE` / `NOT_ADMITTED_REASON` for the reject.
- `identity::{TransportDirectoryBundleDocument, TransportDirectoryBundleTrust,
  VerifiedDirectory, IdentityError}` - load-time directory verification
  (`verify_bundle`) and the directory it produces.
- `catchup::{BlobCatchupClient, BlobBackedHistory, RevocationRootPublisher,
  RevocationCatchupManifest}` - content-addressed epoch-root catch-up over
  iroh-blobs (lane e).
- `lanes::pheromone::{PheromoneBatchHandler, mount_pheromone_lane,
  drain_outbox_over_iroh, enqueue_batch_for_delivery}` - lane a.
- `lanes::revocation::{RevocationHandler, VerifiedSignerDirectory,
  RevocationRootSink}` - lane b.
- `lanes::fanout::{FanoutLane, FanoutTopic, TreatyMembership,
  OriginKeyResolver}` - lane c.
- `lanes::bilateral::{IrohBilateralCoSigner, BilateralCoSignHandler,
  OrgAddressBook, PinnedPassportKeys}` - lane d; `IrohBilateralCoSigner`
  implements `chio_federation::bilateral::BilateralCoSigningProtocol`.
- `lanes::limits::{AcceptLimiter, AcceptLimitConfig, AcceptPhase}` - shared
  accept-side hardening for the three direct lanes.
- `metrics::render_iroh_transport_metrics_prometheus`,
  `observability::lane_accept_span` - Prometheus export and tracing spans.

## Testing

```bash
cargo test -p chio-federation-transport-iroh
```

Nightly loom models for the per-peer accept counter and the directory
`ArcSwap` publish/read are cfg-gated behind `chio_iroh_transport_loom` (off by
default):

```bash
RUSTFLAGS="--cfg chio_iroh_transport_loom" cargo test -p chio-federation-transport-iroh --lib loom_ -- --nocapture
```

Every lane also has a runnable, deterministic example under `examples/`
(`cargo run -p chio-federation-transport-iroh --example <name>`); each one
doubles as a smoke test and exits non-zero if its fail-closed invariant is
violated.

## See also

- `chio-federation` - defines the wire protocols this crate transports
  (`pheromone_gossip`, `revocation_gossip`, `bilateral`) and the
  `BilateralCoSigningProtocol` trait it implements; the per-frame verifiers run
  unchanged above this transport.
- `chio-pheromone-relay` - lane a reuses its `RelayBatchReceiver` trait and
  `SqlitePheromoneRelayStore` outbox/inbox verbatim; this crate substitutes
  only the wire hop.
- `chio-revocation-oracle` - the pinned Ed25519 root verifier lane b and the
  blob catch-up path check every signed epoch root against.
- `chio-cli` - wires `DirectoryGate`, the directory reloader, and
  `mount_pheromone_lane` into the production pheromone dispatch path.
