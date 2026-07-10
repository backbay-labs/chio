# ADR-0014: Iroh As Federation Transport (Deferred To Year-2)

- Status: Accepted; implemented 2026-07-03 on `feat/iroh-federation-transport` (originally "Accepted" as a Year-2 deferral; see the Status update below)
- Decision owner: trust and federation lane
- Related plan items: Year-2 neutrality and federation mesh
- Companion: Year-2 implementation plan at [../research/iroh/ADAPTER-SPEC.md](../research/iroh/ADAPTER-SPEC.md)

## Status update 2026-07-03 - BUILT in-tree

This ADR was written to ratify a Year-2 deferral (the original body below is
retained verbatim for history). That deferral has since been **overridden**: the
adapter was pulled forward and built as launch scope. This section records what
was decided and shipped; it does not revise the original design rationale.

- **Crate (source of truth):** `chio-federation-transport-iroh`
  ([../../crates/trust/chio-federation-transport-iroh/](../../crates/trust/chio-federation-transport-iroh/)),
  on branch `feat/iroh-federation-transport`. Where this ADR's forward-looking
  body and the built crate disagree, the crate wins.
- **What shipped:** the full drop-in seam (issuer-signed transport directory +
  accept-time `EndpointHooks` admission gate: `identity.rs`, `admission.rs`), all
  four lanes (pheromone directed batches, revocation epoch roots, bilateral DSSE
  co-sign, gossip fan-out: `lanes/{pheromone,revocation,bilateral,fanout}.rs`),
  and content-addressed anti-entropy catch-up (`catchup.rs`, iroh-blobs). The
  `chio-federation` contracts crate is untouched, as the Drop-In Seam predicted.
- **Key model:** Option B was built (a rotatable ed25519 transport `EndpointId`
  bound to the long-term passport by an issuer-signed directory entry plus a
  passport-over-transport endorsement). Transport-key rotation is verified
  end-to-end (`identity.rs` `transport_key_rotation_end_to_end`).
- **Verification:** 64 in-crate tests, workspace-green, adversarially reviewed
  with 4 findings fixed. Built against **iroh 1.0.1, iroh-gossip 0.101,
  iroh-blobs 0.103**, slimmed per the deps guidance (`default-features = false`,
  `tls-ring` only, no `test-utils`).
- **Open decisions resolved / still open:** the per-item status is recorded in
  [ADAPTER-SPEC section 7](../research/iroh/ADAPTER-SPEC.md). In brief, four
  resolved: migrate-vs-dual = DUAL behind `--iroh-enable`; the revocation
  `signer_id -> EndpointId` binding home = the crate's own issuer-signed transport
  directory (NOT `KernelTrustExchange`, which carries the kernel key not the
  oracle root, has no `EndpointId`, and is a TOFU self-claim); Option A vs B = B
  built; blobs-vs-direct-QUIC = iroh-blobs for bulk roots with the control
  envelope on the direct-QUIC lane. Three stay open and operational: topic
  eviction latency, the gossip ~4 KiB budget, and ongoing iroh-version
  re-verification (iroh-gossip / iroh-blobs are still pre-1.0).
- **New open item surfaced by the build:** a passport-endorsement
  domain-separation gap. The per-entry endorsement signs the bare 32
  `transport_endpoint_id` bytes with no domain tag (`identity.rs`), and the
  planned oracle-key endorsement would sign another bare 32-byte ed25519 value
  with the same passport key. Without domain separation a signature over one could
  be replayed as the other (cross-protocol signature-confusion). Domain-separate
  both (commit to a distinct context plus `signer_id`) before the oracle
  endorsement is added.

## Context

The cross-operator federation mesh (`chio-federation`: open admission, quorum,
bilateral co-signing, pheromone and revocation gossip, shared reputation
clearing) is described in the strategy brief as a Year-2/Year-3 asset and "the
actual wall." It is the one part of the system that is an inherently
distributed-systems problem: independent operators, behind their own NATs and
firewalls, need to reach each other to exchange signed trust artifacts.

[iroh](https://www.iroh.computer/) (`n0-computer/iroh`, dual Apache-2.0/MIT) was
raised as "an important thing to consider." This ADR records what was found, the
decision reached, and the concept-to-primitive mapping, so the question does not
get re-opened from scratch every time the federation lane is discussed.

Two facts established by reading the tree drive the decision:

1. **The `chio-federation` contracts crate carries no transport, but the two
   gossip lanes differ, and one already ships a transport in a separate crate.**
   `chio-federation/Cargo.toml` carries zero networking dependencies (no
   reqwest, tonic/gRPC, libp2p, quinn, nor tokio); it is, by its own package
   description, a set of "contracts" that drain per-peer FIFO queues into
   per-recipient batch frames and leave delivery to a caller. The lanes then
   split:
   - **Revocation gossip: no transport exists.** The doc comment on
     [`RevocationGossipPushQueue`](../../crates/trust/chio-federation/src/revocation_gossip.rs)
     states it directly: "The transport layer is then responsible for delivering
     each batch to its recipient." Nothing implements that layer; peers are
     addressed by an opaque `peer_kernel_id: String`.
   - **Pheromone gossip: a full transport already ships.** The separate
     [`chio-pheromone-relay`](../../crates/trust/chio-pheromone-relay/src/service.rs)
     crate is a deployable `axum` HTTP server plus `reqwest` client with a SQLite
     store-and-forward outbox/inbox, and it transports the very same
     `PheromoneGossipBatch` artifacts the contracts crate emits
     (`service.rs:27`, `store.rs:10` import the federation type verbatim). So the
     federation layer as shipped is not transport-free: one lane has a complete,
     working HTTP transport.

   That shipped transport is the architectural *opposite* of iroh (opaque
   `kernel_id` named, `https://` URL addressed, authenticated by an
   application-layer envelope signature rather than the connection, with id, URL,
   and key glued together by an issuer-signed `PeerDirectory`). That makes it a
   concrete reference point for the comparison below, not a reason to adopt iroh
   now. See "Existing Transport Versus Iroh."

2. **The identity model is already public-key-native, but not uniformly
   ed25519.** Operators are identified by a `did:chio:...` `kernel_id` string at
   the federation layer
   ([`bilateral_dsse.rs`](../../crates/trust/chio-federation/src/bilateral_dsse.rs),
   [`bilateral.rs`](../../crates/trust/chio-federation/src/bilateral.rs)) and sign
   with a `PublicKey` from
   [`chio-core-types/src/crypto.rs`](../../crates/core/chio-core-types/src/crypto.rs)
   (`crypto.rs` defines the key types, not the DID convention). The DSSE
   bilateral co-signing path binds `keyid` to a sha256 of the passport public key
   (over the raw 32 bytes for Ed25519, but over the hex string for non-Ed25519
   keys; `bilateral_dsse.rs:112-124`). An iroh `EndpointId` (named `NodeId` before
   iroh 1.0) is a 32-byte ed25519 public key, so for an **Ed25519** passport the
   building block is identical on both sides. It is **not** identical for the
   P256 / P384 / ed25519+ML-DSA-65 hybrid keys `crypto.rs` also supports; see
   Identity Alignment.

The v1 product (the "spend control plane" wedge) is a single-host topology: a
bundled, loopback, token-authed `chio-api-protect` sidecar mediating an agent
fleet on one developer machine. There is no peer-to-peer connectivity problem in
v1 at all.

## Decision

1. **iroh is the presumptive transport for the federation mesh**, adopted at the
   Year-2 boundary when multi-operator mesh work actually starts. It is the
   leading candidate, not a committed dependency.

2. **Do not add iroh (or any P2P transport) to the dependency tree now.** v1 has
   no transport gap to fill, and the Phase-0 gating work is elsewhere (atomic
   reserve-then-charge ledger, brief Risk 1; fork-rebase tax, Risk 3).

3. **iroh sits strictly underneath `chio-federation` as transport and replaces
   no trust logic.** It authenticates the transport peer's key; it does not
   authorize. Every existing check (signature verification, treaty scope,
   quorum, open-admission stake gate, and the explicit local-activation step
   that `lib.rs` calls out as keeping federation "evidence-referential and
   fail-closed") stays exactly where it is, above the transport. iroh upgrades
   sender authentication of the pipe from "opaque string we trust" to
   "cryptographically proven EndpointId," and nothing more.

What is ratified here is the deferral plus the recorded direction below. This
ADR exists so the team stops re-litigating whether to reach for iroh now.

## Why Defer

- **No problem to solve in v1.** NAT traversal and hole-punching between
  distributed peers is meaningless in a single-host, loopback sidecar topology.
- **Opportunity cost.** The disqualifying-if-unfixed item is the non-atomic
  budget ledger under concurrent fan-out, not networking. Transport work now is
  scope added against a working tree that is itself mid-extraction.
- **A working transport already ships for the live lane.** Pheromone gossip
  already moves between operators over the `chio-pheromone-relay` HTTP service,
  so federation is not blocked on new networking. iroh would be a later
  unification and hardening (collapsing URL addressing into key addressing, and
  bringing the revocation lane under the same transport), not an enabler. That
  lowers its urgency further.
- **Stable core, churning edges.** The core `iroh` crate reached **1.0.0 on
  2026-06-15** with an API and wire-stability promise across 1.x, which removes
  the old "pre-1.0 core" objection. But the higher-level crates a mesh actually
  needs are still pre-1.0 and not covered by that promise: `iroh-gossip` (0.101)
  for topic broadcast and `iroh-blobs` (0.103) for content-addressed transfer,
  whose README calls the current line not production-quality. Binding a Year-2
  design to those surfaces now still buys churn. Because the trust model is
  wholly transport-independent (see Drop-In Seam), swapping transports later is a
  contained change, so waiting costs little.

## What Iroh Is (And Is Not)

iroh reached a stable **1.0.0 on 2026-06-15**, with n0 committing to wire and
language-API stability across the 1.x line. (Verified in this investigation,
against iroh 1.0.0: a dial-by-key plus custom-ALPN round-trip, an accept-time
admission gate that rejects an unauthorized peer with a 403 before any
`ProtocolHandler::accept` runs, an `iroh-gossip` 0.101 multi-hop topic broadcast,
and a self-hosted custom-relay round-trip all build and run; see the integration
log.) It is a modular connectivity stack in Rust. You dial an
`EndpointId` (a 32-byte ed25519 public key; this type and `EndpointAddr` were
named `NodeId` / `NodeAddr` before 1.0, and the discovery module was renamed
`address_lookup`) instead of an IP; it establishes an end-to-end-encrypted QUIC
connection, performs NAT traversal and hole-punching, and falls back to relays
when a direct path fails.

The core `iroh` 1.0 crate is connectivity only. The higher-level protocols this
ADR leans on are separate crates that are **still pre-1.0 and not covered by the
1.0 stability promise**: `iroh-gossip` (0.101) for topic broadcast and
`iroh-blobs` (0.103) for content-addressed transfer, whose README points
production users at the older 0.35 line. `iroh-docs` (CRDT sync) exists but is
de-emphasized. Plan for churn above the stable core.

iroh is **not** an authorization, identity, or trust system. The QUIC session
proves the remote holds the private key for a given EndpointId. It says nothing
about whether that operator is admitted, staked, unrevoked, or whether any
artifact it sends is valid. That judgment is, and remains, Chio's job.

## Mapping: Federation Concept To Iroh Primitive

| `chio-federation` concept (today) | iroh primitive (at Year-2) |
| --- | --- |
| Operator identity: `did:chio:...` kernel_id + `PublicKey`; `keyid = sha256(passport pubkey)` | `EndpointId` = ed25519 public key; bound to the operator in a signed record (see Identity Alignment) |
| `peer_kernel_id: String` addressing in the gossip push queues | Resolved to an `EndpointId`; dial-by-key replaces the opaque string |
| Pheromone gossip + revocation-root gossip + cross-operator trust gossip | Directed per-recipient batches (the shipped contract keys on `recipient_kernel_id` and (recipient, treaty)) map most naturally to direct per-peer QUIC streams; reserve `iroh-gossip` topic broadcast for genuine fan-out. On iroh-gossip the authenticated sender is the forwarding neighbor, not the originating EndpointId (`Message::delivered_from` is the relay hop, confirmed empirically), so multi-hop gossip breaks the EndpointId -> `authenticated_sender_kernel_id` equality the verifier relies on; broadcast also exposes a shared topic across treaties, so commit to a topic-per-treaty derivation |
| Operators behind NATs reaching each other without shared infra | Endpoint + hole-punching + self-hosted relay fallback |
| Signed epoch roots / registries as content-addressed signed artifacts | `iroh-blobs` verifiable, resumable, hash-addressed fetch |
| `RevocationCatchupHistory` anti-entropy / catch-up trait | Backed by blob fetch of missed signed roots by content hash |

## Per-Lane Identity Bindings Differ

The mapping table abstracts over a real asymmetry: the "collapse the directory
entry" shortcut applies to only one of the three transport surfaces.

- **Pheromone** has an issuer-signed `PeerDirectory` binding `(kernel_id,
  public_key, endpoint)` and verifies an envelope signature against the pinned
  `public_key` (`directory.rs:60-73`, `http_signing.rs:78-86`). Under iroh it can
  reuse that signed directory to map `kernel_id -> EndpointId`.
- **Revocation gossip has no directory, no endpoint, and no public_key in its
  wire types at all.** `RevocationGossipBatch` / `RevocationRootGossip` carry only
  `recipient_kernel_id` and an opaque `signer_id: String`, verified against an
  out-of-band pinned signer key the receiver already holds
  (`revocation_gossip.rs`; `KernelTrustExchange` is the source of truth for who
  may participate). It must acquire a brand-new `signer_id -> EndpointId` (and
  `signer_id -> verifying-key`) binding; there is no directory to collapse.
- **Bilateral DSSE co-signing is not a gossip lane at all.** `bilateral_dsse.rs`
  defines a standalone in-toto `DsseEnvelope` with no push queue, no recipient
  field, and no transport, driven by a request/response handshake
  (`DsseCoSigningRequest`, `BilateralCoSigningProtocol`, `bilateral.rs`).

So there are effectively three transport cases, not one: pheromone (migrate an
existing HTTP transport, reuse its directory), revocation (first implementation,
new signer binding), and bilateral co-signing (first implementation, interactive
stream, not gossip).

## Identity Alignment

The current model keys signing off public keys, so for Ed25519 operators the
alignment with EndpointId is structural rather than aspirational. The genuine
design fork, to be decided at adoption time (not now), is:

- **Option A - same key.** The operator's passport signing key *is* its iroh
  EndpointId. One ed25519 key is both the signing identity and the dial address.
  An authenticated inbound connection then directly proves "this stream is from
  operator X." Simplest, but couples long-term identity to the transport key and
  fights key rotation, and an EndpointId is per-endpoint (an operator may run
  several endpoints and relays). Option A is moreover **impossible for any
  operator with a non-Ed25519 passport**: Chio supports P256 / P384 and
  ed25519+ML-DSA-65 hybrid keys (`SigningAlgorithm`, `PublicKeyMaterial` in
  `crypto.rs`; the `pq` feature in `chio-federation/Cargo.toml`), and an iroh
  EndpointId is a 32-byte ed25519 key (`PublicKey::as_bytes` panics for
  non-Ed25519, `crypto.rs:546-562`). A would force every federating operator onto
  Ed25519 passports and abandon the post-quantum-hybrid posture.

- **Option B - separate bound keys (recommended starting position).** The
  passport signing key stays the long-term operator identity; a rotatable ed25519
  transport EndpointId is bound to the operator in the **issuer-signed** directory
  bundle (verified against the pinned `TrustedPeerDirectoryIssuer` set,
  `directory.rs:108-116,322-338`), not by a subject self-claim. The binding MUST
  additionally carry a passport-signed endorsement of the transport EndpointId
  (the long-term, possibly-PQ passport key signing the ephemeral ed25519 transport
  key, plus transport-key proof-of-possession). Without that
  passport-over-transport signature, an issuer-only or PoP-only binding lets the
  transport key float free of the long-term identity, which defeats the
  separation. Verification: an inbound connection authenticated to EndpointId N is
  accepted as operator X only if X's issuer-signed, in-window, non-rolled-back
  record binds N and X's passport endorses N. This keeps transport keys rotatable,
  lets one identity front multiple endpoints, avoids leaking the long-term key
  into relay-visible metadata, and (decisively) works for PQ-hybrid / P256 / P384
  operators whose passport key cannot be an ed25519 EndpointId (their non-ed25519
  algorithm is used in the passport endorsement, entirely above iroh). The issuer-signed binding and its
  fail-closed verification are now PoC-validated end-to-end (signed_admission.rs,
  iroh 1.0.0, real handshake): a load-time verifier rejects on body-hash mismatch,
  unknown or invalid issuer signature, out-of-window validity, version_floor or
  previous_version_sha256 rollback, and a missing or wrong passport-over-transport
  endorsement, and the accept-time gate is built only from a bundle that passed
  all five. The cross-algorithm property itself remains asserted, not validated:
  the PoC models the passport as a tagged ed25519 key, so a genuine P256 / P384 /
  ML-DSA passport endorsement above iroh is the next step.

This ADR does not globally pick A or B, but records that **B is mandatory for any
post-quantum-hybrid / P256 / P384 operator** (A cannot represent their key as an
EndpointId) and is the default for Ed25519 operators unless evidence favors A.
The remaining choice is the first Year-2 design decision.

## Existing Transport Versus Iroh

The pheromone lane already ships a transport, and it is the architectural
inverse of iroh on every axis. This is the most useful concrete comparison
available, because it shows precisely what an iroh migration would change.

| Axis | `chio-pheromone-relay` today | iroh |
| --- | --- | --- |
| Peer identity | opaque `kernel_id: String` | `EndpointId` = the ed25519 public key |
| Network address | a DNS `https://...` URL (`endpoint`) | derived from the key; no URL |
| Identity-to-address binding | none; glued by an issuer-signed `PeerDirectory` | intrinsic (the key is the address) |
| Peer authentication | application-layer envelope signature over canonical JSON, verified against the directory's pinned `public_key` | the QUIC/TLS session itself proves possession of the EndpointId key |
| Reachability / discovery | static signed directory document; no live resolution | hole-punching plus relay-assisted resolution of the key |
| Reliability | SQLite store-and-forward outbox/inbox; at-least-once with nonce dedup | QUIC streams; reliability stays the outbox's job |

Two consequences follow:

- **The passport key is retained; the URL is replaced by a transport
  EndpointId.** Under iroh a directory entry carries `(kernel_id, passport
  public_key, transport EndpointId)`: the passport `public_key` stays (it is the
  long-term identity and the algorithm-agnostic auth key), the `https://` URL and
  its plumbing go away (`validate_endpoint`, the HTTPS/loopback profile rules, the
  direct-`reqwest` egress carve-out), and an ed25519 transport `EndpointId` is
  added. Reusing the passport key directly as the EndpointId (Option A) is even
  possible only for Ed25519 passports: `PublicKey` also admits P256/P384/Hybrid
  (`crypto.rs`) and an iroh EndpointId is ed25519-only (`PublicKey::as_bytes`
  panics for non-Ed25519, `crypto.rs:546-562`), so a non-Ed25519 operator must
  carry a separate ed25519 transport key (Option B). The issuer-signed directory
  does not disappear: it stops being an address book and keeps doing
  *authorization*, which is multi-dimensional (presence in the directory plus
  relay role, treaty subscriptions, namespace allow-lists, and per-peer rate caps;
  `directory.rs:62-73`, `service.rs:420-447`), not a single allow bit. iroh dials
  the key; the directory says whether that key is allowed.

- **A Chio "relay hub" is not an iroh "relay" (kill this confusion on sight).**
  Chio's transit hub (`PheromoneTransitChain`, `accepted_hubs`, ladder-pinned
  hops in `pheromone_gossip.rs`) is a trust-and-policy-bearing node that
  re-gossips deposits across treaties under hop caps and pinned ladders. An iroh
  relay is a content-blind packet bouncer for NAT traversal. They sit at
  different layers: iroh relays would carry bytes between operators, and Chio
  transit hubs would still exist above them as a policy construct. The hub set is
  itself address-affected: `PheromoneTransitPolicy.accepted_hubs` is a
  `Vec<String>` of `kernel_id`s (`pheromone_gossip.rs:137`), so it inherits the
  same `kernel_id -> EndpointId` resolution as ordinary peers. What disappears
  under iroh is the URL-bound substrate (the relay-supervisor and reverse-proxy
  profile documents and `validate_endpoint`'s loopback/https rules), not the
  policy-bearing hub set.

## Drop-In Seam

"How cleanly does it drop in" differs by lane. For **revocation gossip**, iroh
would be the first concrete implementation of an already-abstracted seam: there
is no transport to replace. For **pheromone gossip**, iroh would replace or sit
beneath the shipped `chio-pheromone-relay` HTTP transport, which already proves
the contracts carry cleanly over a real wire and whose SQLite store-and-forward
layer is transport-agnostic and would be reused. Either way the contracts crate
is untouched. It already:

- produces per-recipient, addressed batch frames (`flush_batches_at` ->
  `RevocationGossipBatch`) and states delivery is the transport's job;
- bounds and coalesces messages before handoff, so back-pressure and
  storm-control live above the wire and are transport-agnostic;
- defines `RevocationCatchupHistory` as the anti-entropy seam for peers that
  fell behind.

The adoption work is therefore an adapter crate (provisionally
`chio-federation-transport-iroh`), not surgery on `chio-federation`:

1. Bind `peer_kernel_id` to a transport `EndpointId` (Option B). For the
   pheromone lane the directory entry becomes `(kernel_id, passport public_key,
   EndpointId)`: the passport key is RETAINED (long-term identity and
   algorithm-agnostic auth key), only the `endpoint` URL is dropped. The binding
   is an ISSUER attestation in the signed directory bundle (verified against the
   pinned `TrustedPeerDirectoryIssuer` set), not a subject self-claim, and should
   also carry a passport-signed endorsement of the EndpointId. Because the
   rotatable transport EndpointId lives inside that issuer-signed directory,
   rotation becomes a bundle re-issue plus promotion and must respect the
   directory's monotone versioning, `previous_version_sha256` chaining, and
   `version_floor` rollback gate (`directory.rs:302-307,452-534`); transport-key
   rotation cadence is thus coupled to directory issuance cadence.
2. Open an iroh `Endpoint` with an ALPN per surface (revocation roots, pheromone
   deposits, bilateral co-sign exchange).
3. Gate admission at accept time, before any `ProtocolHandler::accept` runs, on
   the cryptographically verified peer EndpointId. iroh authenticates the peer key
   during the QUIC/TLS handshake and exposes an accept-time hook for exactly this
   (in iroh 1.0, `EndpointHooks::after_handshake`, which sees `conn.remote_id()`
   and can reject with a QUIC close code and reason; reference
   `iroh/examples/auth-hook.rs`). Reject any EndpointId not bound to an admitted,
   non-removed kernel_id in the current directory; `before_connect` gives the
   symmetric outbound allowlist. This is a cheap DoS-rejection layer and defense
   in depth, NOT a replacement for the per-frame batch verifier above it; keep
   both.
4. Drain the existing push-queue batches over the wire, preferring direct
   per-peer QUIC streams for the directed per-recipient batch contract and
   reserving `iroh-gossip` topic broadcast for genuine fan-out signals. Reuse the
   `chio-pheromone-relay` SQLite outbox for store-and-forward.
5. Back `RevocationCatchupHistory` (and the relay catch-up path) with
   `iroh-blobs` content-addressed fetch.
6. Self-host relays (see Open Q4 on keeping the trust root operated, not merely
   compiled); iroh ships a self-hostable relay server (`iroh-relay`, with
   built-in ACME), so do not depend on n0's public relays for a production trust
   mesh. Full n0 independence also requires self-hosting or pinning discovery
   (own pkarr/DNS or static `EndpointAddr`), since `RelayMode::Custom` alone still
   leaves default DNS discovery touching n0.

Note: the "bilateral co-sign exchange" ALPN in step 2 is a different shape from
the gossip lanes. As recorded under Per-Lane Identity Bindings Differ, bilateral
co-signing is an interactive request/response handshake with no push queue, so it
is a separate bidirectional QUIC stream, not a drained batch, and is a third
"first implementation" case rather than a migration.

Crucially, the fail-closed invariant is preserved by construction. The batch
verifier already takes the authenticated sender as an explicit input:
`PheromoneGossipBatchVerificationContext { authenticated_sender_kernel_id, .. }`
is checked against every frame's `gossiping_peer_kernel_id`
([`pheromone_gossip.rs`](../../crates/trust/chio-federation/src/pheromone_gossip.rs)).
Today the HTTP envelope signature establishes that sender identity, and it works
for P256 / P384 / hybrid passports because envelope-signing is algorithm-agnostic.
Under iroh the authenticated QUIC peer supplies an authenticated *EndpointId*, not
a kernel_id: the transport supplies one half (an authenticated EndpointId) and the
issuer-signed, in-window, non-rolled-back directory binding supplies the other (the
EndpointId -> kernel_id resolution) before the verifier context is populated. Everything that makes an artifact trusted
(deposit signature, agent-passport resolution, treaty-scope, freshness and
replay, scarcity caps, quorum, and the explicit local-activation gate) is
transport-independent and stays untouched.

## Consequences

### Positive

- The decision is recorded once; the federation lane stops re-deriving it.
- Because the trust model is transport-independent and the contracts are already
  abstracted from delivery, deferral costs little in rework: the adapter slots in
  later (replacing the pheromone HTTP transport, implementing the revocation and
  bilateral lanes) without disturbing the contracts.
- Same-language (Rust), permissively licensed, no FFI; for Ed25519 operators the
  identity model lines up, so the eventual integration is low-friction.
- No impact on the custody-neutral posture: iroh is pure transport and touches
  no money path.

### Negative

- A future reader could misread "iroh is the transport" as "iroh provides
  trust." This ADR states explicitly that it does not; reviewers must hold that
  line.
- The core iroh crate is 1.0/stable, but the higher-level crates named here
  (iroh-gossip, iroh-blobs) are still 0.x and may shift before Year-2; they must
  be re-verified at adoption (iroh-blobs is not yet production-quality). The
  iroh-blobs content-addressed fetch substrate for catch-up (mapping rows above,
  Drop-In Seam step 5) is now PoC-validated for transport and integrity (blobslab,
  iroh-blobs 0.103.0): stable BLAKE3 content-address, download-by-hash with
  verified streaming and byte-equality, dedup, and a HashSeq transitive walk. What
  makes it a faithful RevocationCatchupHistory remains unvalidated and is the next
  step: signature-verifying each SignedEpochRoot against the pinned signer, strict
  monotone epoch ordering / gap detection, durable FsStore persistence, and gating
  the download behind the accept-time EndpointHooks.
- The ed25519-only EndpointId does not cover PQ-hybrid / P256 / P384 passports,
  forcing the separate-transport-key model (Option B) and the rotation-coupling
  it implies for those operators.
- Self-hosting relays is real operational work that the brief's trust-root
  stance (Open Q4) implies but does not yet budget. It is now PoC-validated
  end-to-end: a self-hosted `iroh_relay::server::Server` (self-signed cert, no
  n0), two endpoints forced relay-only via `clear_ip_transports()` plus
  `RelayMode::Custom`, round-trip confirmed via `Connection::paths_stream()`
  (relay path, never IP). A production deployment uses `CertConfig::Manual` with a
  real or own-CA cert, not the dev-only self-signed path. An iroh relay is
  content-blind (it sees only EndpointId pairs and byte counts, and only until a
  direct path forms), so relay self-hosting is about availability and
  metadata-minimization, not trust; Open Q4 should be scoped accordingly. Full n0
  independence also needs self-hosted or pinned discovery. n0's free public relays
  end 2026-12-31, a hard deadline for a durable mesh to run its own.

## Required Follow-up

- **Revisit trigger:** when multi-operator mesh work begins (brief Phase 2,
  Year-2), not before. No action until then.
- **At adoption, decide the key model** (Option A vs B above) as the first
  design step, remembering B is already forced for non-Ed25519 operators.
- **Decide migrate-versus-dual-transport.** Either migrate the existing
  `chio-pheromone-relay` HTTP transport to iroh and unify all surfaces under one
  P2P transport, or run iroh only for the revocation and bilateral lanes and
  leave pheromone on HTTP. Migrating unifies addressing and auth; keeping HTTP
  avoids disturbing a working, shipped service.
- **Resolve the design decisions iteration 2 surfaced:** commit to a
  topic-to-treaty derivation for any gossip use; adopt accept-time admission
  (`EndpointHooks::after_handshake` on the verified peer EndpointId) plus the
  per-frame verifier as defense in depth; and bound transport-key compromise
  blast-radius with short transport-key validity / fast re-issue, distinct from the
  long-term passport.
- **Re-verify iroh status at adoption time:** core 1.x stability, the then-current
  iroh-gossip / iroh-blobs versions and production-readiness, relay self-hosting
  story, license unchanged, maintenance health.
- **Keep the relay/trust-root as Chio-operated infrastructure**, consistent with
  Open Q4 in the brief.
