# chio-federation-transport-iroh architecture

## Overview

This crate is a transport, not a trust authority. It sits strictly underneath
`chio-federation` (ADR-0014) and replaces no trust logic: the per-frame
verifiers `chio-federation` runs above the transport are unchanged, so this
crate's own trust surface is narrow and verified once, at load time. An
issuer-signed `TransportDirectoryBundleDocument` binds each operator's
long-term passport key to a rotatable iroh `EndpointId` (and, additively, to
oracle revocation-signer keys and per-treaty party sets), producing the one
`VerifiedDirectory` every lane resolves against. Four ALPN-mounted lanes carry
`chio-federation`'s wire protocols over iroh behind one shared accept-time
gate; a fifth substrate (iroh-blobs) carries bulk catch-up data
content-addressed rather than framed.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Crate doc and module declarations (`admission`, `catchup`, `identity`, `lanes`, `metrics`, `observability`). |
| `src/identity.rs` | Issuer-signed transport-directory bundle types, fail-closed `verify_bundle`, and the resulting `VerifiedDirectory`. |
| `src/admission.rs` | `DirectoryGate`: the accept-time `EndpointHooks` gate every lane shares. |
| `src/catchup.rs` | Content-addressed catch-up (lane e) over iroh-blobs: publish/fetch signed epoch roots, the `RevocationCatchupManifest` control shape. |
| `src/lanes.rs` | Declares the four lane submodules plus the cfg-gated loom test module. |
| `src/lanes/limits.rs` | `AcceptLimiter` / `AcceptLimitConfig`: shared per-phase timeouts and concurrency caps for the three direct lanes. |
| `src/lanes/limits_loom.rs` | Loom concurrency models for the per-peer counter and the directory `ArcSwap`; `#[cfg(all(test, chio_iroh_transport_loom))]`, off by default. |
| `src/lanes/pheromone.rs` | Lane a: directed batches over a direct QUIC stream; reuses `chio-pheromone-relay`'s receiver, store, and outbox verbatim. |
| `src/lanes/revocation.rs` | Lane b: pushed signed epoch roots plus the catch-up control envelope over a direct QUIC stream. |
| `src/lanes/fanout.rs` | Lane c: cross-operator fan-out over iroh-gossip, one topic per treaty, with a treaty-party join/receive gate. |
| `src/lanes/bilateral.rs` | Lane d: DSSE co-signing over a dedicated-ALPN bidirectional QUIC RPC; implements `chio_federation::bilateral::BilateralCoSigningProtocol`. |
| `src/metrics.rs` | Hand-rolled `AtomicU64` counters/histogram and `render_iroh_transport_metrics_prometheus`. |
| `src/observability.rs` | `tracing` span/target helpers shared by the lanes. |

## Lane lifecycle

1. **Load time.** A `TransportDirectoryBundleDocument` is verified
   (`verify_bundle`) against a pinned issuer set and rollback floor, producing
   a `VerifiedDirectory`. It is wrapped in a `DirectoryGate`
   (`Arc<ArcSwap<VerifiedDirectory>>`) so a reloader can publish a freshly
   verified successor without reconstructing the gate.
2. **Accept time.** The gate is installed via
   `Endpoint::builder(..).hooks(gate)`. `after_handshake` resolves the
   authenticated `EndpointId` and returns `Accept` or `Reject` (403) before
   any `ProtocolHandler::accept` runs.
3. **Direct-lane accept (a/b/d).** Each handler re-resolves `conn.remote_id()`
   through the same gate (defense in depth), then runs bounded `accept_bi` ->
   bounded frame read -> `chio-federation` per-frame verification -> bounded
   response write -> bounded linger, all under the lane's `AcceptLimiter`.
4. **Fan-out (c).** Instead of accepting a connection, a node joins a gossip
   topic derived from the treaty id (`blake3(label || 0x00 || treaty_id)`),
   gated by treaty-party membership at join and again at receive; every
   payload is origin-verified from its own embedded signature, never from
   `Message::delivered_from`.
5. **Catch-up (e).** A follower fetches signed roots addressed by their BLAKE3
   hash over iroh-blobs, then re-checks both content integrity and
   pinned-signer authenticity per blob before merging, all-or-nothing.

## Invariants and failure modes

- The gate resolves only through a `VerifiedDirectory` that passed every
  `verify_bundle` check; no constructor skips verification.
- A removed (tombstoned) directory entry never resolves, inbound (`authorize`)
  or outbound (`resolve_transport_endpoint`).
- Every direct-lane accept step is bounded by `AcceptLimitConfig`; a stalled
  peer is reset rather than left to hang a task, and concurrency is capped
  both lane-wide and per-peer.
- Revocation and catch-up authenticity is independent of transport identity: a
  `SignedEpochRoot` must verify against its pinned `Ed25519RootVerifier`, and
  BLAKE3 integrity is re-checked even though iroh-blobs already verifies it in
  transit (integrity is not authenticity).
- Fan-out never trusts `delivered_from`: every payload is verified from its
  own self-signature plus `chio-federation`'s transport-independent frame
  verifier.
- Fan-out's inbound gossip join is not gated at the protocol level
  (iroh-gossip 0.101 exposes no admission hook); the treaty-party gate at join
  and receive stops a non-party from injecting an accepted frame, but a
  bypassing client can still observe forwarded swarm traffic. This is a
  documented residual, not a silent gap.
- Bilateral co-sign verifies Org B's signature against the passport key the
  same verified directory snapshot binds for that peer, so a rotated-away or
  revoked passport is never accepted.
- Every verification failure and admission reject increments a
  bounded-cardinality Prometheus counter and emits a `tracing::warn!`
  additively, without changing the returned `Result`.

## Dependencies

- `chio-core-types` - canonical JSON, hashing, and the algorithm-agnostic
  `PublicKey` / `Signature` / `Keypair` types the directory bundle and every
  lane sign and verify against.
- `chio-federation` - defines the wire protocols this crate transports
  (`pheromone_gossip`, `revocation_gossip`, `bilateral`) and the
  `BilateralCoSigningProtocol` / `RevocationCatchupHistory` traits this crate
  implements; its per-frame verifiers run unchanged above the transport.
- `chio-pheromone-relay` - lane a reuses its `RelayBatchReceiver` trait and
  `SqlitePheromoneRelayStore` outbox/inbox verbatim.
- `chio-revocation-oracle` - `Ed25519RootVerifier` / `EpochRootVerifier` /
  `SignedEpochRoot`, the pinned signature check for lane b and blob catch-up.
- `chio-metrics-spec` - registered Prometheus metric-name and bucket
  constants; adds no runtime dependency.
- `iroh` (`tls-ring` only, default features off) - the QUIC/TLS endpoint,
  `EndpointHooks`, `ProtocolHandler`, and `Router` every lane mounts on.
- `iroh-gossip` - the per-treaty swarm lane c joins.
- `iroh-blobs` - the content-addressed store and downloader lane e uses.
- `arc-swap` - lock-free directory reads on the hot admission path behind the
  reloader's single-writer swap.
- `tokio`, `serde` / `serde_json`, `thiserror`, `tracing`, `blake3`, `bytes`,
  `n0-future` - async runtime, wire codec, typed errors, structured logging,
  gossip topic derivation, and the `Stream` driving `GossipReceiver`.

## Extension points

- `lanes::revocation::RevocationRootSink` - caller-provided cache-update hook
  for verified pushed roots; must stage-then-commit a batch atomically (the
  default fails closed rather than risk a partial merge).
- `chio_federation::revocation_gossip::RevocationCatchupHistory` - implemented
  by `catchup::BlobBackedHistory`; a caller may supply its own history source.
- `lanes::fanout::TreatyMembership` - the treaty-party oracle the fan-out lane
  gates join and receive on: membership, local-endpoint-to-kernel resolution
  (for the join gate), and origin-key resolution (for receive).
  `identity::VerifiedDirectory` implements it directly in production;
  `StaticTreatyMembership` is an in-memory double for tests and examples.
- `lanes::fanout::OriginKeyResolver` - fallback origin-key resolution when a
  `TreatyMembership` backend binds no keys of its own; `StaticOriginKeys` is
  the in-memory double.
- `lanes::bilateral::{OrgAddressBook, PinnedPassportKeys}` - pluggable
  peer-address and passport-key resolution for the bilateral co-signer and
  handler.
- `chio_federation::bilateral::BilateralCoSigningProtocol` - implemented by
  `lanes::bilateral::IrohBilateralCoSigner`, so a networked co-signer can
  substitute for `chio-federation`'s `InProcessCoSigner`.
