# Iroh Federation-Transport Adapter: Implementation Spec

Capstone implementation spec for the iroh federation-transport adapter. It
consolidates a build-validated investigation into a single Year-2 build plan,
and is governed by the decision record at
[ADR-0014](../../adr/ADR-0014-iroh-federation-transport.md). Where this spec and
ADR-0014 appear to differ, ADR-0014 wins; nothing here is intended to contradict
it.

Status legend used throughout: **VALIDATED** = a PoC outside this repo built AND
ran against the real crate and the property was observed at runtime;
**ASSERTED** = argued from the API/source but not yet exercised end-to-end.

## 1. Purpose and Scope

This is a **forward-looking implementation plan**, not a description of current
state. It describes an adapter crate (provisional name
`chio-federation-transport-iroh`) that sits **strictly underneath**
`chio-federation` as a transport and replaces no trust logic.

The division of responsibility is the whole point and must be held on sight:

- **iroh authenticates the peer key.** A completed QUIC/TLS handshake proves the
  remote holds the private key for a given `EndpointId` (a 32-byte ed25519
  public key). That is all it proves.
- **Chio authorizes above it.** Every existing check stays exactly where it is:
  deposit/root signature verification, agent-passport resolution, treaty scope,
  quorum, the open-admission stake gate, scarcity caps, freshness/replay, and the
  explicit local-activation step. The adapter upgrades sender authentication of
  the pipe from "opaque `kernel_id` string we trust" to "cryptographically proven
  `EndpointId`," and nothing more. See ADR-0014 Decision item 3.

The verifier seam this must feed is already explicit in the contracts crate:
`PheromoneGossipBatchVerificationContext.authenticated_sender_kernel_id`
([pheromone_gossip.rs:99](../../../crates/trust/chio-federation/src/pheromone_gossip.rs))
is checked against every frame's `gossiping_peer_kernel_id`
([:236](../../../crates/trust/chio-federation/src/pheromone_gossip.rs)) and, for
direct frames, `origin_kernel_id`
([:244](../../../crates/trust/chio-federation/src/pheromone_gossip.rs)). The
adapter's job is to populate that one field from a cryptographically
authenticated `EndpointId`, resolved through a verified directory; the per-frame
check stays untouched above it.

**Scope boundary: v1 does not need this.** The v1 product (the spend-control-plane
wedge) is a single-host, loopback, token-authed sidecar topology mediating an
agent fleet on one machine. There is no peer-to-peer connectivity problem in v1
at all (ADR-0014 Context). This adapter is a **Year-2** asset, adopted at the
multi-operator-mesh boundary (ADR-0014 Decision item 1, Required Follow-up
"Revisit trigger"). Nothing here authorizes adding iroh to the dependency tree
now (ADR-0014 Decision item 2).

Out of scope for this spec: the trust logic itself (lives in `chio-federation`
and is transport-independent), the money/custody path (iroh touches no money
path; custody-neutral posture is unaffected), and any change to the contracts
crate's wire types.

## 2. Validated Foundation

What the validation work proved, separated honestly from what is still only
argued. The validation programs are intentionally not vendored in this repo. All
validation ran on iroh 1.0.0 / iroh-gossip 0.101 / iroh-blobs 0.103 /
iroh-relay 1.0.0.

### 2.1 Status table

| Capability | Status | PoC | Validated API / note |
| --- | --- | --- | --- |
| Dial-by-key + custom ALPN round-trip | VALIDATED | `poc/main.rs` | `ep.connect(addr: impl Into<EndpointAddr>, ALPN)`; dialed by full `EndpointAddr` with zero discovery; `ProtocolHandler::accept` + `Router`. `EndpointId` alone needs a discovery service. |
| iroh-gossip multi-hop topic broadcast | VALIDATED | `poc2/src/bin/gossip.rs` | iroh-gossip 0.101; `Gossip::builder().spawn(ep)`, `subscribe_and_join(TopicId, Vec<EndpointId>)`, `GossipTopic::split()`; 3-node chain, C received A's message relayed through B. |
| Accept-time admission gate (reject before `ProtocolHandler::accept`) | VALIDATED | `poc2/src/bin/admission.rs` | `EndpointHooks::after_handshake(&self, &Connection) -> AfterHandshakeOutcome`; `Reject { error_code: 403u32.into(), reason }`; rejected `EndpointId` never entered the handler's seen-set (4/4 runs). |
| Issuer-signed directory: body-hash pin | VALIDATED | `poc2/src/bin/signed_admission.rs` | `canonical_sha256(body) == body_sha256` else reject; canonicalization = recursive object-key sort, compact bytes. Mirrors `directory.rs` sign/verify. |
| Issuer-signed directory: issuer signature | VALIDATED | `signed_admission.rs` | find pinned issuer by `issuer_id`, then `issuer.public.verify(canonical_bytes(body), sig)`; maps to pinned `TrustedPeerDirectoryIssuer` ([directory.rs:108-116](../../../crates/trust/chio-pheromone-relay/src/directory.rs)). |
| Issuer-signed directory: validity window | VALIDATED | `signed_admission.rs` | `now_ms in [valid_from_ms, valid_until_ms)` else reject; out-of-window bundle rejected at runtime. |
| Issuer-signed directory: rollback gate | VALIDATED | `signed_admission.rs` | `version > version_floor` AND `previous_version_sha256 == expected_prev`; both `version <= floor` and wrong-prev-hash reject at runtime. Maps to [directory.rs:481-516](../../../crates/trust/chio-pheromone-relay/src/directory.rs). |
| Passport-over-transport endorsement | VALIDATED | `signed_admission.rs` | per entry, `passport_pk.verify(transport_endpoint_id.as_bytes(), &passport_endorsement)` else reject whole bundle; endorsing a different transport id rejects. Real non-ed25519 endorsement signatures over the transport-key bytes (P-256 + P-384 real DER, plus ML-DSA-65 / Hybrid) are now demonstrated above iroh (`xalgo_endorsement.rs`, `algo_matrix.rs`); here exercised as the signing/verify shape, not yet inside a full directory bundle. |
| All five directory checks gate the live accept hook | VALIDATED | `signed_admission.rs` | `verify_bundle` runs at LOAD; the `SignedGate` is constructed ONLY from the resulting `Arc<VerifiedDirectory>`, so the gate never runs over an unverified bundle. |
| iroh-blobs content-addressed catch-up (transport + integrity) | VALIDATED | `blobslab/src/main.rs` | iroh-blobs 0.103; stable BLAKE3 address (`add_bytes(..).hash == Hash::new(&snap)`), download-by-hash with BLAKE3 verified streaming + byte-equality, natural dedup, `HashSeq` transitive walk on a fresh follower. |
| Self-hosted relay (relay-only forced) | VALIDATED | `relaylab/src/main.rs` | iroh-relay 1.0.0; `Server::spawn`, `RelayMode::Custom(RelayMap)`, `clear_ip_transports()`; `Connection::paths_stream()` reported `is_relay()` true and `is_ip()` never true. Dev self-signed cert (`insecure_skip_verify`), not prod. |
| Cross-ALGORITHM passport endorsement (P256 / P384 / ed25519+ML-DSA-65) | VALIDATED | `poc2/src/bin/xalgo_endorsement.rs` + `realtypes/src/bin/algo_matrix.rs` | A genuine NIST P-256 ECDSA passport (`p256` crate, OS entropy) signs the 32 ed25519 transport-`EndpointId` bytes, verified above iroh, fail-closed. Deterministic exit 0 (8/8 runs, clippy clean): accept plus rejections for wrong-subject, swapped-id, forged-sig, and valid-sig-by-different-key. Now extended: `algo_matrix.rs` exercises the REAL P-384 (aws-lc-rs DER), ML-DSA-65 (FIPS 204 PQ), and ed25519+ML-DSA-65 Hybrid (per-half AND-semantics) backends, each real-signing canonical JSON, round-tripped over iroh-blobs with far-side re-verify and fail-closed tamper matrices. All five chio algorithms (ed25519, P-256, P-384, ML-DSA-65, Hybrid) now exercised above iroh. |
| Full `RevocationCatchupHistory` semantics over blobs | VALIDATED (real `Ed25519RootSigner`/`EpochRoot`/canonical-JSON now linked over iroh, `oraclelink.rs`) | `blobslab/src/bin/signed_catchup.rs` | The two previously-ASSERTED sub-items are now observed at runtime over the real iroh-blobs 0.103 fetch (deterministic exit 0, 3/3 runs, clippy clean): (1) signature-verify against a PINNED ed25519 signer rejects a tampered root (`BadSignature`) and a forged/wrong-signer root (`WrongSigner`); (2) strict monotone epoch ordering raises `CatchupGap{expected:3,observed:4}` on a dropped epoch, byte-identical to `validate_response` ([revocation_gossip.rs:459-475](../../../crates/trust/chio-federation/src/revocation_gossip.rs)). Rejected ranges leave history EMPTY (all-or-nothing). `FsStore` persistence + gating were VALIDATED separately by `gated_catchup` (row 82). Now CLOSED: the real chio-revocation-oracle `Ed25519RootSigner`/`Ed25519RootVerifier` over RFC-8785 `canonical_json_bytes(EpochRoot)` + `DOMAIN_SEPARATION_CONTEXT` (signer.rs:49,92-99; `EpochRoot` at api.rs:86-91) is now linked (path dep, zero arc-side cascade beyond chio-core-types) and round-tripped over iroh-blobs with a full fail-closed tamper matrix (`realtypes/src/bin/oraclelink.rs`). The big-endian-framing model is retired. |
| Gate + blobs composed | VALIDATED | `blobslab/src/bin/gated_catchup.rs` | The same gated endpoint mounts `BlobsProtocol` AND the `EndpointHooks` allowlist (`.hooks(gate)`); ran deterministically (exit 0). Authorized follower ADMITTED -> pulls the snapshot (bytes match, verified streaming); unauthorized `EndpointId` is `Reject{403}`-ed at `after_handshake` BEFORE the blobs handler runs and never obtains the hash (proven server-side via `gate.rejected`, client-side via download Err, and its own `FsStore` lacking the hash). Caveat: the follower set is allowlist membership, NOT the full issuer-signed `VerifiedDirectory` (the directory half is VALIDATED separately, rows above); the full three-way signed-directory -> gate -> blobs pipeline is now VALIDATED separately (`three_way.rs`, row below). |
| Authorization richness (multi-dimensional entry) | VALIDATED (relay-role/treaty/cap mirror `enforce_peer_batch_directory_scope`; namespace + ladder-pin now modeled on the federation transit-policy layer, `ladder_admission.rs`) | `poc2/src/bin/multidim_admission.rs` | Over a real iroh 1.0 loopback handshake (deterministic exit 0, 3/3 runs, clippy clean), a two-layer split enforces four dimensions fail-closed, each with a DISTINCT typed deny reason observed over the wire: `relay_role` -> `WrongRelayRole`, `treaty_subscriptions` -> `TreatyNotSubscribed`, namespace -> `SubjectNamespaceNotAllowed`, frame-cap -> `FrameCountOverCap`. Layer 1 (`after_handshake`) 403-rejects unknown + removed peers before the handler; only admitted peers reach Layer 2. Role + treaty + cap map line-for-line to `enforce_peer_batch_directory_scope` ([service.rs:421-447](../../../crates/trust/chio-pheromone-relay/src/service.rs)). Caveat: that function never reads `allowed_subject_class_namespaces` (grep-confirmed: directory.rs:68 declares the field, no enforcement in chio-pheromone-relay); the namespace dimension is actually enforced by chio-federation `enforce_pheromone_gossip_transit` ([pheromone_gossip.rs:170-175](../../../crates/trust/chio-federation/src/pheromone_gossip.rs)), so the PoC mirrors the transit-policy layer, not the named relay function; the real 4th dimension (`accepted_ladder_refs` ladder-pins) is unmodeled by THAT PoC. Both are now closed in `poc2/src/bin/ladder_admission.rs`: the namespace gate checks `PheromoneTransitPolicy.allowed_subject_class_namespaces` against `deposit.body.subject_class_namespace` (the correct layer, pheromone_gossip.rs:169-177) and the full 5-field ladder-pin mirrors `transit_hop_is_pinned` (pheromone_gossip.rs:397-406), fail-closed over a live iroh 1.0 handshake, each with a distinct typed deny mapped to the real `PheromoneGossipError::code()`. Link-fidelity now closed: `fedlink/src/main.rs` LINKS the real `chio-federation` (zero arc cascade, 8 crates auto-resolved) and drives the real `verify_pheromone_gossip_frame` -> `verify_relay_frame` over iroh-blobs, exercising those previously-omitted structural checks (9 of 13 rejection cases) against the real verifier. |
| Three-way pipeline composed (signed-directory verify -> admission gate -> signed catch-up) | VALIDATED | `blobslab/src/bin/three_way.rs` | One process, one endpoint/Router: `start_gated_authority` runs `verify_bundle` FIRST and builds `DirectoryGate::new(Arc<VerifiedDirectory>)` ONLY on success; the gate admits via `directory.authorize(remote)` (the admit-set IS the issuer-signed, version-stamped, rollback-resistant directory, not a `HashSet`). Deterministic exit 0, 23 PASS/0 FAIL, clippy clean. Tampered/rolled-back directory fails closed at LOAD (gate never built); unauthorized `EndpointId` `Reject{403}`-ed at `after_handshake` before any blob byte; authorized follower admitted + full in-order catch-up [1,2,3,4]; `BadSignature`/`WrongSigner`/`CatchupGap` still bite downstream (history left EMPTY). |
| Real `chio-core-types` linked + exercised over iroh | VALIDATED (ed25519 + P-256 + P-384 + ML-DSA-65 + Hybrid) | `realtypes/src/main.rs` + `realtypes/src/bin/algo_matrix.rs` | The REAL workspace crate (path dep, proven via depfile + `Cargo.lock` no-`source` signature, zero cascade) compiled + linked + ran GREEN over iroh-blobs for ed25519 (default) AND P-256 (`--features fips`, aws-lc-rs, real DER). Exercises real `canonical_json_bytes` (RFC-8785/JCS), `Keypair`/`Ed25519Backend`/`P256Backend`, `PublicKey::{from_hex,verify_canonical}`; byte-for-byte agreement between two real signing entrypoints; fail-closed tamper test; BLAKE3-addressed transport + far-side re-verify. Caveat: links `chio-core-types` (crypto + canonical JSON); the revocation-oracle `Ed25519RootSigner`/`EpochRoot` types are now ALSO linked + round-tripped over iroh-blobs (`oraclelink.rs`, row 81). |

### 2.2 Residual caveats on the validated rows

These are called out because the spec must not overclaim:

- **Cross-algorithm (the decisive property, now closed).** `PublicKey::as_bytes()` panics for any
  non-Ed25519 key
  ([crypto.rs:551-562](../../../crates/core/chio-core-types/src/crypto.rs)) and an
  iroh `EndpointId` is ed25519-only, so a P256 / P384 / ed25519+ML-DSA-65 passport
  cannot be an `EndpointId`. That is exactly why Option B (a separate transport
  key, passport-endorsed) is mandatory for those operators. A real non-ed25519
  signature over the ed25519 transport key, verified entirely above iroh, is now
  demonstrated for the REAL P-256, P-384 (aws-lc-rs DER), ML-DSA-65 (FIPS 204), and
  ed25519+ML-DSA-65 Hybrid backends end-to-end over iroh-blobs
  (xalgo_endorsement.rs, algo_matrix.rs), each with far-side re-verify and
  fail-closed tamper matrices. The decisive gap is closed.
- **Catch-up authenticity vs integrity.** BLAKE3 verified streaming gives
  integrity (bytes match the hash) but NOT authenticity (who signed the root).
  The real contract requires more: `RevocationCatchupResponse::validate_response`
  walks `[from_epoch, to_epoch]` in strict increasing order and raises
  `CatchupGap` on holes
  ([revocation_gossip.rs:459](../../../crates/trust/chio-federation/src/revocation_gossip.rs)),
  and callers MUST signature-verify every `SignedEpochRoot` against the pinned
  signer before merging
  ([revocation_gossip.rs:45,111](../../../crates/trust/chio-federation/src/revocation_gossip.rs)).
  Both are now demonstrated at runtime (`signed_catchup.rs`, deterministic, 3/3
  runs): pinned-signer verify rejects tampered and forged roots, and strict
  ordering raises `CatchupGap{expected:3,observed:4}` on a dropped epoch, rejected
  ranges leaving history empty (row 81). Now CLOSED: the real `Ed25519RootSigner`
  over RFC-8785 canonical JSON of the real `EpochRoot` is exercised end-to-end over
  iroh-blobs (`oraclelink.rs`, row 81), with a full fail-closed tamper matrix; the
  big-endian-framing model is retired. (DER for non-ed25519 remains via the
  cross-algorithm row.)
- **The full three-way pipeline is now composed.** `three_way.rs` runs
  signed-directory verify -> admission gate -> signed blob catch-up as ONE pipeline
  on one endpoint (gate built only from a verified bundle; unauthorized `EndpointId`
  rejected at `after_handshake` before any blob byte; `BadSignature` / `WrongSigner`
  / `CatchupGap` still bite downstream), exit 0, 23 PASS/0 FAIL. Narrowed open
  caveat: the catch-up leg's signer is modeled (iroh ed25519 + big-endian framing),
  not the real revocation-oracle `Ed25519RootSigner` / `EpochRoot`; but the real
  `chio-core-types` crypto + canonical JSON IS now linked over iroh
  (`realtypes.rs`, ed25519 + P-256).

## 3. Adapter Module Structure

Four modules, each naming the iroh 1.0 types it stands on. The contracts crate is
untouched; this is all new code in the adapter crate.

### 3.1 `identity` (directory + key binding)

Resolves `kernel_id <-> EndpointId` and verifies the issuer-signed directory at
load time.

- iroh types: `iroh::EndpointId` (= `iroh_base::PublicKey`, ed25519),
  `iroh_base::{SecretKey, PublicKey, Signature}`. `EndpointId` is `Copy`, 32
  bytes, `Eq + Hash`, so it is a convenient map key; `fmt_short()` is `impl
  Display` (not `Debug`) for logging.
- Holds a `VerifiedDirectory { by_endpoint: HashMap<EndpointId, (kernel_id,
  removed)>, version, body_sha256 }` produced by a `verify_bundle` step that
  mirrors `PeerDirectoryBundleDocument::verify`. Four checks are VALIDATED (ed25519
  bundle, all proven to reject at runtime): body-hash pin, pinned-issuer signature,
  validity window, and `version > version_floor` AND `previous_version_sha256`
  chaining. The fifth, the per-entry passport-over-transport endorsement, was
  VALIDATED only with a tagged ed25519 passport; real cross-algorithm endorsement
  signatures are now VALIDATED over iroh for P-256, P-384, ML-DSA-65, and Hybrid
  (rows 76, 80, 85; `algo_matrix.rs`). The gate is
  constructed ONLY from a bundle that passed all checks.
- Option B keys live here: the long-term passport `PublicKey` (any algorithm) and
  the separate rotatable ed25519 transport `EndpointId`, cross-linked by a
  passport-signed endorsement of the transport key.

### 3.2 `admission` (accept-time gate)

The fail-closed connection gate, shared by every lane.

- iroh types: `iroh::endpoint::EndpointHooks`. Both methods are async (RPITIT
  returning `impl Future`); shown here in shorthand, but implement them as `async
  fn` (a plain `async fn` satisfies the provided default - do NOT write a sync fn):
  `after_handshake(&self, &Connection) -> AfterHandshakeOutcome` and optionally
  `before_connect(&self, &EndpointAddr, &[u8]) -> BeforeConnectOutcome` (the real
  trait carries explicit `<'a>` lifetimes on the borrowed args, elided here).
  `iroh::endpoint::Connection` (`remote_id() -> EndpointId`, infallible after
  handshake; `alpn()`, `side()`); `AfterHandshakeOutcome::Reject { error_code:
  VarInt, reason: Vec<u8> }`.
- Resolves `conn.remote_id()` through the `identity` module's `VerifiedDirectory`
  and Rejects (403) any `EndpointId` not bound to an admitted, non-removed
  `kernel_id`. On Accept, hands the resolved `kernel_id` to the lane handler to
  populate `authenticated_sender_kernel_id`.
- Both outcome enums are `#[non_exhaustive]` (asserted from the 1.0.0-rc.0 release
  notes; a docs.rs HTML read disagreed and was not independently reconciled in the
  PoCs - log iter-3 (c) UNCERTAINTY FLAG). The defensive coding is correct
  regardless: match with a trailing `_` arm, never exhaustively. Registered once via
  `Endpoint::builder(..).hooks(gate)`; applies to both connect and accept side.
  Reject happens-before any `ProtocolHandler::accept`.

### 3.3 `lanes` (per-lane transports)

One submodule per surface, each mounting on a `Router` keyed by a distinct ALPN.

- iroh types: `iroh::protocol::{Router, ProtocolHandler, AcceptError}`;
  `iroh::endpoint::Connection` with `open_bi()` / `accept_bi()` for the direct and
  bilateral lanes; `iroh_gossip::{Gossip, GossipTopic, GossipSender,
  GossipReceiver, TopicId, Event, Message}` (ALPN `iroh_gossip::ALPN`) for the
  fan-out lane.
- Lane mapping is fixed in section 4. The directed lanes (pheromone, revocation)
  drain the existing per-recipient push-queue batches over direct per-peer QUIC
  streams; the fan-out lane uses gossip; bilateral co-sign is an interactive bidi
  stream; catch-up bulk uses blobs.

### 3.4 `catchup` (content-addressed anti-entropy)

Backs `RevocationCatchupHistory` with iroh-blobs; the design gates the downloader
behind `admission` (ASSERTED - `signed_admission` and `blobslab` were validated in
isolation, now composed end-to-end in `three_way.rs`; see table row 82 and the three-way row).

- iroh-blobs 0.103 types and signatures:
  - PUT: `Blobs::add_bytes(impl Into<Bytes>) -> AddProgress`, which is
    `IntoFuture<Output = RequestResult<TagInfo>>`, where `TagInfo { name, format,
    hash }`. (NOT a bare `Hash`.)
  - DOWNLOAD: `Store::downloader(&Endpoint) -> Downloader`; then
    `Downloader::download(request: impl SupportedRequest, providers: impl
    ContentDiscovery) -> DownloadProgress`. `Hash` impls `SupportedRequest`; the
    provider is idiomatically `Shuffled::new(vec![authority_endpoint_id:
    EndpointId])`. The download fetches INTO the follower store and yields `()`;
    THEN call `get_bytes(hash)`. (Two-step; NOT `download(hash,
    Some(authority_id))`.)
  - Format enum is `BlobFormat` (`Raw` | `HashSeq`), NOT `HashFormat`.
  - Serve: `BlobsProtocol::new(&store, None)` mounted via
    `Router::builder(ep).accept(iroh_blobs::ALPN, blobs).spawn()`.
  - Store: production `FsStore::load(path).await?` (NOT `MemStore`) so history is
    INTENDED to survive restart (ASSERTED - `blobslab` ran on `MemStore`; `FsStore`
    restart-survival was comment-only / not exercised, table row 81); `fs-store` is
    a default feature.
- Error surface is irpc/`n0_error`, not anyhow: `add` -> `RequestResult`,
  `get_bytes` -> `ExportBaoResult`, `download` -> `n0_error::Result`; bridge at
  call sites.

## 4. Per-Lane Transport Mapping

The DECIDED table from iteration 4 (ADR-0014's mapping table already hedges
"direct per-peer QUIC streams ... reserve `iroh-gossip` ... for genuine
fan-out"; this commits the choice per lane).

| Lane | Transport | Rationale |
| --- | --- | --- |
| (a) pheromone directed batches (recipient + treaty keyed) | **direct per-peer QUIC stream** | The shipped contract is DIRECTED (`PheromoneGossipBatch` keys on `recipient_kernel_id` + `treaty_id`); the verifier requires `frame.gossiping_peer_kernel_id == authenticated_sender` ([pheromone_gossip.rs:236](../../../crates/trust/chio-federation/src/pheromone_gossip.rs)), which a direct stream's authenticated `EndpointId` satisfies. Reuse the `chio-pheromone-relay` SQLite outbox for store-and-forward. iroh migration of the existing HTTP transport. |
| (b) revocation epoch roots | **direct per-peer QUIC stream** | Same directed shape (`RevocationGossipBatch` keys on `recipient_kernel_id`, per-peer FIFO with intra-tick epoch coalescing). Receiver verifies each `SignedEpochRoot` against a pinned signer; the transport need only guarantee origin + ordering + reliability. Requires a NEW `signer_id -> EndpointId` binding (revocation carries no directory, endpoint, or pubkey in its wire types; [revocation_gossip.rs:65,206](../../../crates/trust/chio-federation/src/revocation_gossip.rs)). |
| (c) cross-operator trust / pheromone fan-out signals | **iroh-gossip** (per-treaty topic) | The one genuinely many-to-many lane (reputation clearing, transit-hub re-gossip). **Payloads MUST be self-signed and origin-verified from the payload alone**, never relying on transport-sender == author, because `Message::delivered_from` is the forwarding NEIGHBOR, not the author (empirically observed: node C reported `delivered_from = B`). Honor `max_message_size` (~4 KiB working cap; chunk or reference-by-hash). Best-effort; durability via the catch-up / blob lanes. |
| (d) bilateral DSSE co-sign | **dedicated-ALPN bidirectional QUIC RPC** (the integration-log table line 233 labels this lane "direct per-peer QUIC stream (own ALPN)"; this is the same transport, refined to name its bidirectional request/response use, matching ADR-0014's "separate bidirectional QUIC stream") | Interactive request/response, categorically NOT gossip (`request_dsse_cosignature(&DsseCoSigningRequest) -> Result<DsseCoSigningResponse, BilateralCoSigningError>`). Needs exactly-one authenticated counterparty + a correlated reply; broadcasting would leak the in-flight statement to non-parties. |
| (e) catch-up history | **iroh-blobs** | Anti-entropy gap-fill over content-addressed immutable roots (`RevocationCatchupHistory::signed_root_at(epoch)`, capped at `REVOCATION_CATCHUP_MAX_EPOCHS = 4096`, [revocation_gossip.rs:191,492](../../../crates/trust/chio-federation/src/revocation_gossip.rs)). The control envelope (`RevocationCatchupRequest` / `Response`) rides the lane-(b) QUIC stream; blobs carries the bulk root bytes. `blobslab` VALIDATED only content-addressed transport + integrity (BLAKE3); wrapping each blob as a `SignedEpochRoot` and signature-verifying it against the pinned signer is ASSERTED (table row 81, mirrors gating item 3) - BLAKE3 gives integrity, not authenticity. CAVEAT: iroh-blobs is pre-1.0 (README not production-quality) - keep a direct-QUIC fallback as v1 if blobs is not ready at Year-2. |

### 4.1 Topic derivation (lanes using gossip)

Deterministic, one-topic-per-treaty, no coordination round-trip:

```
TopicId = blake3("chio-<lane>/v1\x00" || treaty_id_bytes)
```

The 32-byte BLAKE3 digest is used verbatim as the iroh-gossip `TopicId`. Use a
distinct domain-separation label per gossip surface so lanes never collide on the
same id, for example `chio-pheromone-gossip/v1`, `chio-revocation-root-gossip/v1`,
`chio-trust-fanout/v1\x00 || clearing_scope_id`; the label is versioned `/v1`.
`treaty_id_bytes` is canonical UTF-8 of the existing `String treaty_id` (no new
identifier type); blake3 is already a workspace primitive.

**One-topic-per-treaty is MANDATORY for confidentiality.** A gossip topic is one
swarm (HyParView / PlumTree) where every member sees every other member's wire
traffic; the membership set IS the confidentiality boundary. Binding `TopicId`
one-to-one to a treaty makes that boundary exactly the treaty's subscription set,
and cross-treaty leakage is structurally impossible (different swarm, different
`TopicId`). A deterministic `TopicId` is not a secret and grants no access by
itself; membership must still be gated to the treaty's admitted, non-revoked
participants by the accept-time `EndpointId` gate plus the issuer-signed
directory. (Rejected alternatives: one-federation-topic-with-in-payload-filtering,
which is a receive-side courtesy not access control; topic-per-(treaty,recipient),
which degenerates a swarm to ~2 endpoints and should just be a direct stream.)

### 4.2 Bilateral co-sign flow (lane d)

One iroh BIDIRECTIONAL QUIC stream on a dedicated ALPN
`b"chio/federation/bilateral-dsse-cosign/1"`. The bidi stream gives
request-on-send / response-on-recv correlation with no app-level request IDs.

1. Org B resolves Org A's `EndpointId` from `kernel_id` via the issuer-signed
   directory and dials it; the QUIC/TLS handshake authenticates both
   `EndpointId`s.
2. Org A's `after_handshake` Rejects if Org B's `EndpointId` is not bound to an
   admitted, non-revoked, in-rotation-window `kernel_id`, BEFORE any
   `ProtocolHandler::accept` (DoS rejection / defense in depth, not a replacement
   for signature checks).
3. Org B `open_bi()`, writes one length-delimited canonical
   `DsseCoSigningRequest { schema, org_a_kernel_id, org_b_kernel_id, pae_bytes,
   org_b_signature }`, then half-closes the send half (`finish()`).
4. Org A asserts its directory-resolved `EndpointId == org_b_kernel_id`, verifies
   `org_b_signature` over `pae_bytes` against Org B's pinned passport key
   (algorithm-agnostic, above iroh), re-checks the rotation window (`PeerExpired`)
   and trust (`UnknownPeer`); on any failure it writes a typed error mirroring
   `BilateralCoSigningError` and resets WITHOUT signing.
5. On success Org A signs the SAME `pae_bytes` and writes `DsseCoSigningResponse {
   schema, org_a_signature }` on the recv half of the same stream.

An iroh-stream impl of this replaces the in-process co-signer; the
`BilateralCoSigningProtocol` request/response contract
([bilateral.rs](../../../crates/trust/chio-federation/src/bilateral.rs)) is
unchanged above the transport.

## 5. Admission and Binding Design

The accept-time gate is the load-bearing seam. Its shape is fixed by what the
PoCs validated:

- **Accept-time `EndpointHooks` gate over a LOAD-time-verified directory.**
  `verify_bundle` runs once at load and the gate is built only from the resulting
  `Arc<VerifiedDirectory>`; the gate never resolves against an unverified bundle.
  Inside `after_handshake`, resolve `conn.remote_id() -> kernel_id`, Reject (403,
  reason) on unbound / unknown / removed `EndpointId`. This fires before any
  `ProtocolHandler::accept` runs (VALIDATED, `admission.rs` / `signed_admission.rs`).
- **Binding resolution feeds the verifier, not replaces it.** The transport
  supplies one half (an authenticated `EndpointId`); the issuer-signed, in-window,
  non-rolled-back directory supplies the other (the `EndpointId -> kernel_id`
  resolution). Only then is `authenticated_sender_kernel_id` populated. The
  per-frame verifier stays above it (`pheromone_gossip.rs:236,244`). **Keep
  both** - the accept-time gate is a cheap DoS-rejection / defense-in-depth layer,
  NOT a replacement for the per-frame batch verifier (ADR-0014 Drop-In Seam step
  3).
- **Option B is MANDATORY for non-ed25519 passports.** The passport signing key
  (any algorithm) stays the long-term operator identity; a rotatable ed25519
  transport `EndpointId` is bound to the operator in the issuer-signed directory
  bundle (verified against the pinned `TrustedPeerDirectoryIssuer` set,
  [directory.rs:108-116](../../../crates/trust/chio-pheromone-relay/src/directory.rs)),
  not by a subject self-claim. The binding MUST additionally carry a
  passport-signed endorsement of the transport `EndpointId` plus transport-key
  proof-of-possession (this in-directory PoP artifact is ASSERTED - the PoC did not
  model it and leans on the live QUIC/TLS handshake for PoP at accept time; see log
  iter-4 (d) residual #4); without that passport-over-transport signature the
  transport key floats free of the long-term identity. Verification: an inbound
  connection authenticated to `EndpointId` N is accepted as operator X only if X's
  issuer-signed, in-window, non-rolled-back record binds N AND X's passport
  endorses N. This is the only model that works for P256 / P384 / ed25519+ML-DSA-65
  operators, whose passport key cannot be an `EndpointId`
  ([crypto.rs:551-562](../../../crates/core/chio-core-types/src/crypto.rs)). The
  non-ed25519 algorithm is used only in the passport endorsement, entirely above
  iroh. ADR-0014 records B as mandatory for those operators and the default for
  Ed25519 unless evidence favors A.

The issuer-signed binding and its five fail-closed checks are PoC-validated
end-to-end (`signed_admission.rs`, real handshake). Two prescribed elements remain
asserted-not-validated: the cross-ALGORITHM property (the passport was modeled as a
tagged ed25519 key, not a real non-ed25519 key), and the in-directory transport-key
proof-of-possession artifact (line 284) - the PoC leans on the live QUIC/TLS
handshake for transport-key PoP rather than modeling an in-directory PoP (log
iter-4 (d) residual #4).

## 6. Phased Build Order (Year-2)

Numbered milestones, gating items first. Each cites which PoC de-risks it and
what remains. None of this starts before the multi-operator-mesh boundary.

**Lead (gating) items - close the asserted gaps that the design rests on:**

1. **Compose the gate with blobs.** Put the `catchup` downloader behind the
   `admission` `EndpointHooks` gate so only an admitted, directory-bound,
   non-removed follower can pull catch-up roots; prove an unadmitted `EndpointId`
   is rejected at `after_handshake` before any blob byte transfers. De-risked by:
   `signed_admission.rs` (gate) + `blobslab/src/main.rs` (download) individually.
   DONE in iteration 8: composed end-to-end in `three_way.rs` (exit 0, 23 PASS/0 FAIL).

2. **Real non-ed25519 passport endorsement.** Carry a genuine P256 / P384 /
   ed25519+ML-DSA-65 passport keypair in the issuer-signed entry, have it sign the
   ed25519 transport `EndpointId` entirely above iroh, and verify the endorsement
   against the pinned passport key for the non-ed25519 case (the real
   algorithm-agnostic envelope path). De-risked by: `signed_admission.rs` proved
   the endorsement check shape. Remains: it only ever used a tagged ed25519 key;
   this is the single most load-bearing unvalidated property and the reason Option
   B exists.

3. **Signed-root, epoch-ordered catch-up on `FsStore`.** Wrap each blob as a
   `SignedEpochRoot`, signature-verify every fetched root against the pinned signer
   before merging, walk a strict monotone epoch range raising `CatchupGap` on holes
   (mirroring `validate_response`,
   [revocation_gossip.rs:459](../../../crates/trust/chio-federation/src/revocation_gossip.rs)),
   and run on `FsStore` so history survives a restart. De-risked by: `blobslab`
   proved transport + integrity (BLAKE3 address, download-by-hash, dedup,
   HashSeq). Remains: authenticity (signed root), ordering / gap detection, and
   persistence are all unmodeled.

**Then, the lane build-out:**

4. **Pheromone lane (migration).** Drain the existing per-recipient batches over a
   direct per-peer QUIC stream (lane a), reusing the `chio-pheromone-relay` SQLite
   outbox. De-risked by: `poc/main.rs` (dial + ALPN + bidi). Remains: wire the
   real outbox and the `authenticated_sender_kernel_id` population.

5. **Revocation lane (first implementation).** Direct per-peer QUIC stream (lane
   b) plus the NEW `signer_id -> EndpointId` (and `signer_id -> verifying-key`)
   binding that revocation lacks a directory for. De-risked by: same dial PoC.
   Remains: decide where the binding lives (see Open Decisions).

6. **Bilateral co-sign lane (first implementation).** The
   `bilateral-dsse-cosign/1` ALPN bidi RPC (section 4.2) behind the accept-time
   gate; prove the typed-error / no-signature path on a failed `org_b_signature` or
   out-of-window peer. De-risked by: the dial PoC + the gate PoC. Remains: build
   the interactive exchange.

7. **Fan-out lane.** iroh-gossip per-treaty topics (lane c) for the genuinely
   many-to-many signals, with self-signed origin-verified payloads only. De-risked
   by: `gossip.rs` (multi-hop broadcast, `delivered_from`-is-neighbor confirmed).
   Remains: topic-membership admission and per-payload origin verification.

8. **Authorization richness.** Carry `relay_role` + `treaty_subscriptions` +
   `allowed_subject_class_namespaces` + `accepted_ladder_refs` + rate caps in the
   verified entry and run `enforce_peer_batch_directory_scope` above the gate, so
   authorization is multi-dimensional rather than a single membership bit
   ([directory.rs:62-69](../../../crates/trust/chio-pheromone-relay/src/directory.rs)).
   De-risked by: the entry shape is known. Remains: every gate PoC reduced this to
   set membership.

9. **Relay + discovery hardening.** Move from the dev self-signed path to
   `CertConfig::Manual` + own-CA / ACME, pin discovery (own pkarr/DNS or static
   `EndpointAddr`). De-risked by: `relaylab/src/main.rs` proved relay-only
   connectivity. Remains: production certs and discovery independence (see section
   8).

## 7. Open Decisions

Carried from ADR-0014 Required Follow-up and the iteration logs; to be resolved at
adoption, not now.

- **Migrate-vs-dual-transport (pheromone).** Either migrate the shipped
  `chio-pheromone-relay` HTTP transport to iroh and unify all surfaces under one
  P2P transport, or run iroh only for the revocation and bilateral lanes and leave
  pheromone on HTTP. Migrating unifies addressing and auth; keeping HTTP avoids
  disturbing a working, shipped service.
- **`signer_id -> EndpointId` binding home (revocation).** Revocation gossip has
  no directory, no endpoint, and no public_key in its wire types
  ([revocation_gossip.rs:65,206](../../../crates/trust/chio-federation/src/revocation_gossip.rs));
  `KernelTrustExchange` is named as the source of truth for who may participate.
  The net-new `signer_id -> EndpointId` (and `signer_id -> verifying-key`) binding
  needs a home - likely anchored at `KernelTrustExchange` - distinct from the
  pheromone directory.
- **Blobs-vs-direct-QUIC default for catch-up.** iroh-blobs is pre-1.0 and its
  README is not production-quality. Decide whether blobs is the default catch-up
  substrate at Year-2 or whether the direct-QUIC fallback ships as v1 until blobs
  is ready.
- **Topic-membership admission + revocation eviction latency.** A deterministic
  `TopicId` grants no access; membership must be gated by the accept-time
  `EndpointId` gate. Open: how a compromised / revoked transport `EndpointId` is
  evicted from a live topic before the next directory bundle propagates. A leaked
  ed25519 transport secret is dialable until the directory re-issues and every
  receiver promotes the new version; favor short transport-key validity / fast
  re-issue, distinct from the long-term passport. Blast radius is bounded by
  directory propagation latency.
- **Gossip `max_message_size` budget.** iroh-gossip's
  `DEFAULT_MAX_MESSAGE_SIZE = 4096` bytes (floor 512). Decide the per-lane payload
  budget and the chunk-or-reference-by-hash policy for anything larger (bulk goes
  out-of-band via blobs).

Also open from ADR-0014: the global Option A vs B choice for Ed25519 operators (B
is already forced for non-ed25519), and re-verifying iroh status at adoption
(core 1.x stability, then-current iroh-gossip / iroh-blobs versions and
production-readiness, relay self-hosting story, license, maintenance health).

## 8. Slim Build and Ops

**Dependency surface.** iroh 1.0 defaults pull a large set (409 locked crates in
the PoC; defaults `["metrics", "fast-apple-datapath", "portmapper",
"tls-ring"]`). Slim it:

```toml
iroh = { version = "1.0", default-features = false, features = ["tls-ring"] }
```

Keep exactly one of `tls-ring` / `tls-aws-lc-rs` (wires crypto into the `noq`
QUIC backend + iroh-relay + iroh-dns; the only feature needed for a working
relay+TLS endpoint). Drop `metrics`, `portmapper` (UPnP; relay traversal does not
need it), and `fast-apple-datapath` (Apple-only). **Never ship `test-utils`** (it
pulls axum + a relay SERVER and the `insecure_skip_verify` dev path). `iroh-relay`
/ `iroh-base` are required non-optional deps; there is no separate "relay"
feature; the QUIC backend is `noq`, not direct quinn. Verify with `cargo tree -e
features -p iroh` and `cargo tree --duplicates` (catch a ring + aws-lc-rs
double-pull).

**Relays and discovery (self-host the trust root).** Self-host relays
(`iroh-relay` 1.0.0, lib `server` module behind the `server` feature + CLI). Use
`CertConfig::Manual` with a real or own-CA cert (ACME / Let's Encrypt in prod),
NOT the dev-only self-signed `insecure_skip_verify` path the PoC used. Point
clients with `RelayMode::Custom(RelayMap)` using only your own URLs; all endpoints
in a federation share the same relay map. An iroh relay is **content-blind** (it
sees only `EndpointId` pairs and byte counts, and only until a direct path forms),
so relay self-hosting is about availability and metadata-minimization, NOT trust;
ADR-0014 Open Q4 should be scoped accordingly.

**Full n0 independence also needs discovery handling.** `RelayMode::Custom`
removes n0 relays but n0's default DNS discovery still touches n0; self-host or pin
discovery (own pkarr/DNS or a static `EndpointAddr`) alongside the self-hosted
relay so a dial-by-`EndpointId` path also touches zero n0 infra. The PoC achieved
independence by pinning a relay-only `EndpointAddr`; production must pin discovery
too.

**Hard deadline.** n0's free public relays end **2026-12-31**, so a durable Year-2
mesh must run its own relays (or pay for n0 Iroh Services) by then.

## References

- Decision record: [ADR-0014](../../adr/ADR-0014-iroh-federation-transport.md)
- Validation summary: dial + ALPN, gossip broadcast, admission gating, signed
  directory checks, iroh-blobs catch-up, and self-hosted relay behavior were
  exercised outside this repo and are summarized in section 2.
