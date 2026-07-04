//! Lane c: cross-operator fan-out over iroh-gossip per-treaty topics.
//!
//! ADAPTER-SPEC section 4 row (c) + 4.1. This is the one genuinely many-to-many
//! surface (reputation clearing, transit-hub re-gossip). It carries
//! [`PheromoneDepositGossip`] frames over an iroh-gossip swarm, one swarm per
//! treaty.
//!
//! ## Topic derivation (one-topic-per-treaty gives ROUTING separation)
//!
//! `TopicId = blake3("chio-pheromone-gossip/v1\x00" || treaty_id_bytes)`, where
//! `treaty_id_bytes` is the canonical UTF-8 of the existing `String` treaty id
//! (ADAPTER-SPEC 4.1). A gossip topic is one swarm where every member sees every
//! other member's wire traffic. Binding `TopicId` one-to-one to a treaty means
//! each treaty's traffic rides its OWN swarm: this is ROUTING separation
//! (different treaty, different swarm, different `TopicId`), which keeps one
//! treaty's frames off another treaty's wire by default.
//!
//! Topic-per-treaty ROUTING separation is one layer; ACCESS CONTROL is the other
//! and is now ENFORCED (below). The `TopicId` is deterministic and therefore NOT a
//! secret; it grants no access on its own. The accept-time
//! [`DirectoryGate`](crate::admission::DirectoryGate) is FEDERATION-GLOBAL: it
//! admits an operator to the federation, not to a specific treaty. So a
//! globally-admitted operator that is NOT a party to a treaty could still compute
//! that treaty's (non-secret) `TopicId`. That gap is closed by a PER-TREATY
//! membership gate layered on top of federation admission.
//!
//! ## Treaty-party membership gate (federation admission + treaty party set)
//!
//! Membership is sourced from the SAME issuer-signed, anti-rollback substrate the
//! transport keys use: the per-treaty PARTY SET carried in the
//! [`VerifiedDirectory`](crate::identity::VerifiedDirectory) (an issuer-signed
//! `treaty_id -> {party kernel_ids}` map, body-hash-pinned, validity-windowed,
//! monotone-versioned). The gate is enforced FAIL-CLOSED in two places (defense in
//! depth), so this is no longer routing separation alone but enforced
//! treaty-scoped access control:
//!
//! 1. JOIN side: [`FanoutLane::subscribe_treaty`] /
//!    [`subscribe_treaty_with_timeout`](FanoutLane::subscribe_treaty_with_timeout)
//!    reject with [`FanoutError::TreatyMembershipDenied`] BEFORE joining the swarm
//!    if the LOCAL operator's `kernel_id` is not a party to `treaty_id`.
//! 2. RECEIVE side: the frame-verification path
//!    ([`verify_fanout_frame`] / [`FanoutTopic::recv_verified`]) additionally
//!    rejects (same variant) a frame whose ORIGIN kernel is not a party to the
//!    frame's `treaty_id`, so a non-party that joins the swarm anyway cannot inject
//!    an accepted frame.
//!
//! The DELIVERED guarantee is therefore: (1) routing separation (above), (2) the
//! treaty-party membership gate at JOIN and RECEIVE (this section), and (3) a
//! receive-side swarm/treaty binding, so a frame carrying a foreign `treaty_id` is
//! rejected on this swarm even if its deposit self-signature is valid (see
//! [`FanoutTopic::recv_verified`] and [`FanoutError::TreatyMismatch`]). This is
//! federation admission AND treaty-party membership, not one standing in for the
//! other.
//!
//! ## The load-bearing correctness property: `delivered_from` is NOT the author
//!
//! In gossip, [`Message::delivered_from`](iroh_gossip::api::Message) is the
//! forwarding NEIGHBOR that relayed the frame, NOT the original author
//! (empirically observed: node C reports `delivered_from = B` for a message A
//! authored, ADAPTER-SPEC 4 row (c)). Therefore this lane MUST NOT reuse the
//! `authenticated_sender == author` equality the direct lanes (a/b) rely on, and
//! MUST NOT call
//! [`verify_pheromone_gossip_frame_for_batch`](chio_federation::pheromone_gossip)
//! (which would demand `gossiping_peer_kernel_id == authenticated_sender`, false
//! over any relay hop).
//!
//! Instead, every received payload is origin-verified FROM THE PAYLOAD ALONE:
//! 1. the transport-independent
//!    [`verify_pheromone_gossip_frame`] (namespace, policy liveness, origin ==
//!    deposit author, transit-chain integrity), and
//! 2. the embedded deposit's OWN self-signature, verified against the origin
//!    operator's passport key resolved from a trusted directory (NEVER from
//!    `delivered_from`).
//!
//! Neither step consults the transport sender. `delivered_from` is never an input
//! to verification (see [`verify_fanout_frame`] and
//! [`decode_and_verify_fanout_frame`], whose signatures do not even accept it).

use std::collections::HashMap;
use std::collections::HashSet;
use std::time::Duration;

use bytes::Bytes;
use chio_core_types::canonical_json_bytes;
use chio_core_types::PublicKey;
use chio_federation::pheromone_gossip::verify_pheromone_gossip_frame;
use chio_federation::pheromone_gossip::PheromoneDepositGossip;
use chio_federation::pheromone_gossip::PheromoneGossipError;
use chio_federation::pheromone_gossip::PheromoneTransitPolicy;
use iroh::EndpointId;
use iroh_gossip::api::Event;
use iroh_gossip::api::GossipReceiver;
use iroh_gossip::api::GossipSender;
use iroh_gossip::api::Message;
use iroh_gossip::Gossip;
use iroh_gossip::TopicId;
use n0_future::StreamExt;

/// Domain-separation label for the pheromone fan-out gossip surface (ADAPTER-SPEC
/// 4.1). Versioned `/v1`; distinct from other gossip surfaces so lanes never
/// collide on the same `TopicId`.
pub const PHEROMONE_FANOUT_TOPIC_LABEL: &str = "chio-pheromone-gossip/v1";

/// Working cap on a single gossip payload. Mirrors iroh-gossip's
/// `DEFAULT_MAX_MESSAGE_SIZE` (ADAPTER-SPEC 7). A [`PheromoneDepositGossip`] with
/// a long transit chain can exceed this; such payloads must be referenced
/// out-of-band (bulk over the blob lane), never squeezed past the cap.
pub const MAX_GOSSIP_MESSAGE_SIZE: usize = 4096;

/// Client-side liveness bound on a swarm JOIN. `subscribe_and_join` blocks until a
/// neighbor is up, so an empty, unreachable, or hostile bootstrap set would hang the
/// join forever. After this bound the join fails closed (mirrors the direct lanes'
/// `client_bounded` and the blob catch-up client bounds). Generous for cross-continent
/// neighbor discovery; tune via [`FanoutLane::subscribe_treaty_with_timeout`].
pub const FANOUT_JOIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Derive the per-surface gossip topic for a treaty (ADAPTER-SPEC 4.1):
/// `TopicId = blake3(label || 0x00 || treaty_id_bytes)`. Deterministic and
/// coordination-free; the 32-byte BLAKE3 digest is used verbatim as the
/// `TopicId`.
#[must_use]
pub fn topic_for_treaty(label: &str, treaty_id: &str) -> TopicId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(label.as_bytes());
    hasher.update(b"\x00");
    hasher.update(treaty_id.as_bytes());
    TopicId::from_bytes(*hasher.finalize().as_bytes())
}

/// The pheromone fan-out topic for a treaty, under
/// [`PHEROMONE_FANOUT_TOPIC_LABEL`]. This is the one-topic-per-treaty binding that
/// is the confidentiality boundary.
#[must_use]
pub fn pheromone_topic_for_treaty(treaty_id: &str) -> TopicId {
    topic_for_treaty(PHEROMONE_FANOUT_TOPIC_LABEL, treaty_id)
}

/// Errors raised by the fan-out lane. Every payload-verification variant is a hard
/// reject; over best-effort gossip a rejected frame is DROPPED, not answered
/// (ADAPTER-SPEC 4 row (c)). Fail-closed: verification yields the frame only when
/// every check passes.
#[derive(Debug, thiserror::Error)]
pub enum FanoutError {
    /// A serialized frame exceeded [`MAX_GOSSIP_MESSAGE_SIZE`]; caught BEFORE
    /// broadcast so an oversized frame never hits the wire.
    #[error("gossip payload of {size} bytes exceeds the {max}-byte max_message_size")]
    MessageTooLarge {
        /// Serialized size of the offending payload.
        size: usize,
        /// The enforced cap.
        max: usize,
    },
    /// JSON encode/decode of a gossip frame failed.
    #[error("gossip frame json codec error: {0}")]
    Codec(String),
    /// No verifying key is bound to the payload's origin kernel id in the trusted
    /// resolver. Fail-closed: an unresolvable author is rejected, never trusted.
    #[error("no verifying key is bound to origin kernel {0}")]
    UnknownOrigin(String),
    /// The embedded deposit's OWN self-signature did not verify against the
    /// origin operator's resolved passport key. This is the check that makes
    /// `delivered_from` irrelevant to authorship.
    #[error("deposit self-signature is invalid")]
    DepositSignatureInvalid,
    /// A received frame's `treaty_id` did not match the treaty this swarm
    /// carries. Fail-closed: a frame minted for a different treaty is rejected on
    /// this swarm even if its deposit self-signature is valid, binding swarm
    /// delivery to the treaty the topic promises (the routing-separation property
    /// in the module docs).
    #[error("frame treaty_id `{got}` does not match this swarm's treaty `{expected}`")]
    TreatyMismatch {
        /// The treaty this swarm (topic) is bound to.
        expected: String,
        /// The `treaty_id` carried by the received frame.
        got: String,
    },
    /// The local operator (at JOIN) or a frame's origin kernel (at RECEIVE) is
    /// NOT a party to `treaty_id` per the issuer-signed per-treaty party set.
    /// Fail-closed: federation admission alone does not admit a non-party to a
    /// treaty's swarm, and a non-party origin frame is rejected on receive.
    #[error("kernel `{kernel_id}` is not a party to treaty `{treaty_id}`")]
    TreatyMembershipDenied {
        /// The treaty whose party set was consulted.
        treaty_id: String,
        /// The kernel id that is not a party (the local operator at join, or the
        /// frame origin at receive).
        kernel_id: String,
    },
    /// Canonical JSON serialization failed while reconstructing the deposit
    /// signing preimage.
    #[error("canonical json error: {0}")]
    Canonical(String),
    /// Transport-independent frame verification failed
    /// ([`verify_pheromone_gossip_frame`]).
    #[error(transparent)]
    Frame(PheromoneGossipError),
    /// The underlying iroh-gossip subscribe/join/broadcast/receive failed.
    #[error("gossip transport error: {0}")]
    Gossip(String),
}

impl FanoutError {
    /// Stable, bounded metric/log reason for this fan-out failure. Feeds the
    /// `reason` label on `chio_federation_transport_verify_failures_total`.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::MessageTooLarge { .. } => "message-too-large",
            Self::Codec(_) => "codec",
            Self::UnknownOrigin(_) => "unknown-origin",
            Self::DepositSignatureInvalid => "deposit-signature-invalid",
            Self::TreatyMismatch { .. } => "treaty-mismatch",
            Self::TreatyMembershipDenied { .. } => "treaty-membership-denied",
            Self::Canonical(_) => "canonical-json",
            Self::Frame(_) => "frame-invalid",
            Self::Gossip(_) => "gossip-transport",
        }
    }
}

/// OBSERVE-ONLY: count + log a fan-out frame rejection alongside the unchanged
/// fail-closed drop. The receive path previously delegated logging away ("the
/// caller can log-and-drop it") and did none itself, so a `TreatyMismatch`
/// cross-treaty injection campaign or a `DepositSignatureInvalid` flood produced
/// zero local signal.
fn note_fanout_failure(error: &FanoutError) {
    let reason = error.code();
    crate::metrics::record_verify_failure(crate::metrics::SEAM_FANOUT, reason);
    tracing::warn!(
        target: crate::observability::TARGET_VERIFY,
        seam = crate::metrics::SEAM_FANOUT,
        reason = reason,
        "fan-out frame rejected"
    );
}

/// Resolves an origin operator's passport verifying key from its `kernel_id`.
///
/// The fan-out lane verifies the embedded deposit's OWN signature against this
/// key. The key MUST come from a trusted directory (the passport admission set,
/// mirroring `PheromoneValidationContext.passports`), and is resolved by the
/// payload's `origin_kernel_id`. It is NEVER derived from the gossip transport:
/// `Message::delivered_from` is the forwarding neighbor, not the author.
pub trait OriginKeyResolver {
    /// The origin operator's passport verifying key, or `None` (fail-closed) when
    /// no admitted operator is bound to `origin_kernel_id`.
    fn verifying_key(&self, origin_kernel_id: &str) -> Option<PublicKey>;
}

/// A simple in-memory [`OriginKeyResolver`] backed by a `kernel_id -> PublicKey`
/// map. Callers populate it from the trusted passport admission set for the
/// treaty's swarm.
#[derive(Debug, Clone, Default)]
pub struct StaticOriginKeys {
    keys: HashMap<String, PublicKey>,
}

impl StaticOriginKeys {
    /// An empty resolver (resolves nothing; every origin is unknown/rejected).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind `kernel_id` to its passport verifying key (builder style).
    #[must_use]
    pub fn with(mut self, kernel_id: impl Into<String>, key: PublicKey) -> Self {
        self.keys.insert(kernel_id.into(), key);
        self
    }

    /// Bind `kernel_id` to its passport verifying key.
    pub fn insert(&mut self, kernel_id: impl Into<String>, key: PublicKey) {
        self.keys.insert(kernel_id.into(), key);
    }
}

impl OriginKeyResolver for StaticOriginKeys {
    fn verifying_key(&self, origin_kernel_id: &str) -> Option<PublicKey> {
        self.keys.get(origin_kernel_id).cloned()
    }
}

/// Decides whether a `kernel_id` is a party to a `treaty_id`.
///
/// This is the treaty-scoped ACCESS-CONTROL oracle the fan-out lane consults at
/// JOIN (is the LOCAL operator a party?) and at RECEIVE (is the frame ORIGIN a
/// party?). It MUST be backed by trusted, anti-rollback data: the production
/// implementation is [`crate::identity::VerifiedDirectory`] (the issuer-signed
/// per-treaty party set), never the (non-secret) topic id or the gossip transport.
/// Fail-closed: an unknown treaty or a non-party kernel returns `false`.
pub trait TreatyMembership {
    /// Whether `kernel_id` is a party to `treaty_id` (fail-closed on unknown).
    fn is_party(&self, treaty_id: &str, kernel_id: &str) -> bool;
}

impl TreatyMembership for crate::identity::VerifiedDirectory {
    fn is_party(&self, treaty_id: &str, kernel_id: &str) -> bool {
        self.is_treaty_party(treaty_id, kernel_id)
    }
}

/// A simple in-memory [`TreatyMembership`] backed by a `treaty_id -> {kernel_id}`
/// map. Callers populate it from the trusted per-treaty party set (mirroring
/// [`StaticOriginKeys`] for the origin-key resolver); production wiring should
/// prefer the issuer-signed [`crate::identity::VerifiedDirectory`].
#[derive(Debug, Clone, Default)]
pub struct StaticTreatyMembership {
    parties: HashMap<String, HashSet<String>>,
}

impl StaticTreatyMembership {
    /// An empty membership set (every kernel is a non-party; fail-closed).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind `treaty_id` to a party set (builder style).
    #[must_use]
    pub fn with(
        mut self,
        treaty_id: impl Into<String>,
        party_kernel_ids: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        let entry = self.parties.entry(treaty_id.into()).or_default();
        for kernel_id in party_kernel_ids {
            entry.insert(kernel_id.into());
        }
        self
    }

    /// Add a single `kernel_id` to a treaty's party set.
    pub fn insert_party(&mut self, treaty_id: impl Into<String>, kernel_id: impl Into<String>) {
        self.parties
            .entry(treaty_id.into())
            .or_default()
            .insert(kernel_id.into());
    }
}

impl TreatyMembership for StaticTreatyMembership {
    fn is_party(&self, treaty_id: &str, kernel_id: &str) -> bool {
        self.parties
            .get(treaty_id)
            .is_some_and(|parties| parties.contains(kernel_id))
    }
}

/// Origin-verify a fan-out frame FROM THE PAYLOAD ALONE. This is the whole point
/// of the lane: it never consults the gossip transport sender.
///
/// Order (fail-closed; authenticate, THEN authorize):
/// 1. [`verify_pheromone_gossip_frame`]: schema, `origin_kernel_id ==
///    deposit.body.kernel_id`, subject namespace, policy liveness, and
///    transit-chain integrity. It takes NO transport-sender identity. Running it
///    first also PINS the origin to the deposit author, so the key resolved next
///    is bound to the deposit's own signer.
/// 2. Resolve the AUTHOR key from `frame.origin_kernel_id` (the signed payload),
///    NEVER from `delivered_from`.
/// 3. Verify the deposit's OWN self-signature against that key.
/// 4. TREATY-PARTY AUTHORIZATION: the (now-authenticated) origin kernel MUST be a
///    party to the frame's own `treaty_id` per `membership`. A non-party origin is
///    rejected even with a valid self-signature, so a non-party that joins a swarm
///    anyway cannot inject an accepted frame.
///
/// # Errors
/// Returns [`FanoutError::Frame`] on frame verification failure,
/// [`FanoutError::UnknownOrigin`] when the origin has no bound key,
/// [`FanoutError::DepositSignatureInvalid`] when the self-signature does not
/// verify, and [`FanoutError::TreatyMembershipDenied`] when the origin is not a
/// party to the frame's treaty.
pub fn verify_fanout_frame<R, M>(
    frame: &PheromoneDepositGossip,
    origin_keys: &R,
    membership: &M,
    policy: &PheromoneTransitPolicy,
    now_unix_ms: u64,
) -> Result<(), FanoutError>
where
    R: OriginKeyResolver + ?Sized,
    M: TreatyMembership + ?Sized,
{
    // OBSERVE-ONLY wrapper: the origin-verification logic is unchanged in
    // `verify_fanout_frame_inner`; here we count + log a rejection and return the
    // SAME `Result`.
    let result = verify_fanout_frame_inner(frame, origin_keys, membership, policy, now_unix_ms);
    if let Err(error) = &result {
        note_fanout_failure(error);
    }
    result
}

fn verify_fanout_frame_inner<R, M>(
    frame: &PheromoneDepositGossip,
    origin_keys: &R,
    membership: &M,
    policy: &PheromoneTransitPolicy,
    now_unix_ms: u64,
) -> Result<(), FanoutError>
where
    R: OriginKeyResolver + ?Sized,
    M: TreatyMembership + ?Sized,
{
    // (1) Transport-independent frame verification. Pins origin == deposit author.
    verify_pheromone_gossip_frame(frame, policy, now_unix_ms).map_err(FanoutError::Frame)?;

    // (2) Resolve the author key from the PAYLOAD origin, never `delivered_from`.
    let origin_key = origin_keys
        .verifying_key(&frame.origin_kernel_id)
        .ok_or_else(|| FanoutError::UnknownOrigin(frame.origin_kernel_id.clone()))?;

    // (3) Verify the deposit's OWN self-signature against that key.
    verify_deposit_self_signature(frame, &origin_key)?;

    // (4) Authorize the authenticated origin against the frame's treaty party set.
    // Fail-closed: a non-party origin is rejected even with a valid self-signature.
    if !membership.is_party(&frame.treaty_id, &frame.origin_kernel_id) {
        return Err(FanoutError::TreatyMembershipDenied {
            treaty_id: frame.treaty_id.clone(),
            kernel_id: frame.origin_kernel_id.clone(),
        });
    }
    Ok(())
}

/// Decode a raw gossip payload and origin-verify it via [`verify_fanout_frame`].
///
/// This is what a receive loop calls on `Message::content`. Note the signature
/// takes only the payload bytes: `delivered_from` is structurally absent, so it
/// cannot leak into the authorship decision.
///
/// # Errors
/// Returns [`FanoutError::Codec`] on malformed JSON, else any error from
/// [`verify_fanout_frame`] (including [`FanoutError::TreatyMembershipDenied`] when
/// the frame origin is not a party to the frame's treaty).
pub fn decode_and_verify_fanout_frame<R, M>(
    content: &[u8],
    origin_keys: &R,
    membership: &M,
    policy: &PheromoneTransitPolicy,
    now_unix_ms: u64,
) -> Result<PheromoneDepositGossip, FanoutError>
where
    R: OriginKeyResolver + ?Sized,
    M: TreatyMembership + ?Sized,
{
    let frame: PheromoneDepositGossip =
        serde_json::from_slice(content).map_err(|error| FanoutError::Codec(error.to_string()))?;
    verify_fanout_frame(&frame, origin_keys, membership, policy, now_unix_ms)?;
    Ok(frame)
}

/// Decode a raw gossip payload, ENFORCE the swarm/treaty binding against
/// `expected_treaty`, then origin-verify it. This is the pure core of
/// [`FanoutTopic::recv_verified`], factored out so the swarm/treaty binding is
/// unit-testable without a live swarm.
///
/// Fail-closed order: decode, then reject with [`FanoutError::TreatyMismatch`]
/// BEFORE any signature work if the frame's `treaty_id` is not `expected_treaty`
/// (a frame minted for a different treaty is rejected on this swarm even if its
/// deposit self-signature is valid), then run [`verify_fanout_frame`].
///
/// # Errors
/// [`FanoutError::Codec`] on malformed JSON, [`FanoutError::TreatyMismatch`]
/// when the frame is bound to a different treaty, else any error from
/// [`verify_fanout_frame`].
fn decode_bind_treaty_and_verify<R, M>(
    content: &[u8],
    expected_treaty: &str,
    origin_keys: &R,
    membership: &M,
    policy: &PheromoneTransitPolicy,
    now_unix_ms: u64,
) -> Result<PheromoneDepositGossip, FanoutError>
where
    R: OriginKeyResolver + ?Sized,
    M: TreatyMembership + ?Sized,
{
    let frame: PheromoneDepositGossip =
        serde_json::from_slice(content).map_err(|error| FanoutError::Codec(error.to_string()))?;
    if frame.treaty_id != expected_treaty {
        // OBSERVE-ONLY: the cross-treaty injection signal (a foreign-treaty frame
        // on this swarm) is counted before the unchanged fail-closed reject. The
        // verify_fanout_frame call below already self-counts its own failures.
        let error = FanoutError::TreatyMismatch {
            expected: expected_treaty.to_string(),
            got: frame.treaty_id,
        };
        note_fanout_failure(&error);
        return Err(error);
    }
    verify_fanout_frame(&frame, origin_keys, membership, policy, now_unix_ms)?;
    Ok(frame)
}

/// Serialize a frame for broadcast, enforcing the [`MAX_GOSSIP_MESSAGE_SIZE`] cap
/// BEFORE it reaches the wire.
///
/// # Errors
/// Returns [`FanoutError::Codec`] on serialization failure and
/// [`FanoutError::MessageTooLarge`] when the serialized frame exceeds the cap.
pub fn encode_fanout_frame(frame: &PheromoneDepositGossip) -> Result<Bytes, FanoutError> {
    let bytes = serde_json::to_vec(frame).map_err(|error| FanoutError::Codec(error.to_string()))?;
    if bytes.len() > MAX_GOSSIP_MESSAGE_SIZE {
        return Err(FanoutError::MessageTooLarge {
            size: bytes.len(),
            max: MAX_GOSSIP_MESSAGE_SIZE,
        });
    }
    Ok(Bytes::from(bytes))
}

/// Reconstruct the exact preimage `chio-pheromone` signs and verify the deposit's
/// own signature against `origin_key`.
///
/// The normative signing/verification lives in
/// `chio_pheromone::validation::{verify_deposit_signature, deposit_signature_body}`
/// (validation.rs:154-171), which are `pub(crate)` and so cannot be called from
/// here. The preimage is the deposit body with `cost_commitment` cleared, encoded
/// as canonical JSON; this reproduces that byte-for-byte. It MUST stay in step
/// with the canonical functions. The guard test
/// `lane_verifies_a_real_chio_pheromone_deposit_signature` pins this copy to the
/// normative signer: it signs a real deposit with `chio_pheromone::sign_deposit`
/// and asserts this function accepts it, so a canonicalization change in
/// `chio_pheromone` fails loudly here instead of silently diverging.
fn verify_deposit_self_signature(
    frame: &PheromoneDepositGossip,
    origin_key: &PublicKey,
) -> Result<(), FanoutError> {
    let mut signed_body = frame.deposit.body.clone();
    signed_body.cost_commitment = None;
    let canonical = canonical_json_bytes(&signed_body)
        .map_err(|error| FanoutError::Canonical(error.to_string()))?;
    if origin_key.verify(&canonical, &frame.deposit.signature) {
        Ok(())
    } else {
        Err(FanoutError::DepositSignatureInvalid)
    }
}

/// The fan-out lane: a handle to the shared iroh-gossip protocol.
///
/// The gossip protocol is spawned once
/// (`Gossip::builder().spawn(endpoint.clone())`, which implements
/// `ProtocolHandler`) and mounted on the router under `iroh_gossip::ALPN`
/// (`Router::builder(ep).accept(iroh_gossip::ALPN, gossip.clone()).spawn()`);
/// gossip owns its ALPN, so this lane does not invent one. Membership of every
/// topic swarm is gated UPSTREAM by the accept-time
/// [`DirectoryGate`](crate::admission::DirectoryGate) installed via
/// `Endpoint::builder(..).hooks(gate)`.
#[derive(Debug, Clone)]
pub struct FanoutLane {
    gossip: Gossip,
}

impl FanoutLane {
    /// Wrap an already-spawned, router-mounted [`Gossip`] handle.
    #[must_use]
    pub fn new(gossip: Gossip) -> Self {
        Self { gossip }
    }

    /// The underlying gossip handle.
    #[must_use]
    pub fn gossip(&self) -> &Gossip {
        &self.gossip
    }

    /// Subscribe to and join the per-treaty topic swarm, returning the split
    /// sender/receiver handle.
    ///
    /// `bootstrap` are already-admitted `EndpointId`s to dial into the swarm (the
    /// directory gate rejects any unadmitted endpoint at handshake, so bootstraps
    /// that are not directory-bound simply fail to connect). The topic is derived
    /// deterministically from `treaty_id` via [`pheromone_topic_for_treaty`].
    ///
    /// TREATY-PARTY JOIN GATE (fail-closed): the swarm is joined ONLY if
    /// `local_kernel_id` is a party to `treaty_id` per `membership` (the
    /// issuer-signed per-treaty party set). A globally-admitted operator that is
    /// NOT a party is rejected with [`FanoutError::TreatyMembershipDenied`] BEFORE
    /// the (non-secret, deterministic) topic is computed or any neighbor is dialed,
    /// so federation admission alone never leaks a treaty's traffic to a non-party.
    ///
    /// # Errors
    /// Returns [`FanoutError::TreatyMembershipDenied`] when the local operator is
    /// not a party to `treaty_id`, or [`FanoutError::Gossip`] if the subscribe/join
    /// fails.
    pub async fn subscribe_treaty<M>(
        &self,
        treaty_id: &str,
        local_kernel_id: &str,
        membership: &M,
        bootstrap: Vec<EndpointId>,
    ) -> Result<FanoutTopic, FanoutError>
    where
        M: TreatyMembership + ?Sized,
    {
        self.subscribe_treaty_with_timeout(
            treaty_id,
            local_kernel_id,
            membership,
            bootstrap,
            FANOUT_JOIN_TIMEOUT,
        )
        .await
    }

    /// Same as [`subscribe_treaty`](Self::subscribe_treaty), with an explicit join
    /// bound. `subscribe_and_join` blocks until a neighbor is up; an empty or
    /// unreachable `bootstrap` would otherwise hang the join forever, so it fails
    /// closed to [`FanoutError::Gossip`] after `join_timeout` (client-side liveness
    /// defense, mirroring the direct lanes' `client_bounded`). `next_payload`'s wait
    /// is deliberately NOT bounded: a receive loop is meant to block until the next
    /// gossip message.
    ///
    /// The treaty-party JOIN gate (see [`subscribe_treaty`](Self::subscribe_treaty))
    /// is enforced here, fail-closed, BEFORE the topic is derived or joined.
    ///
    /// # Errors
    /// Returns [`FanoutError::TreatyMembershipDenied`] when the local operator is
    /// not a party to `treaty_id`, or [`FanoutError::Gossip`] if the join times out
    /// or the subscribe/join fails.
    pub async fn subscribe_treaty_with_timeout<M>(
        &self,
        treaty_id: &str,
        local_kernel_id: &str,
        membership: &M,
        bootstrap: Vec<EndpointId>,
        join_timeout: Duration,
    ) -> Result<FanoutTopic, FanoutError>
    where
        M: TreatyMembership + ?Sized,
    {
        // TREATY-PARTY JOIN GATE (fail-closed): a non-party local operator is
        // rejected before the (non-secret) topic is even computed, so it never
        // joins the swarm. Federation admission is necessary but not sufficient.
        if !membership.is_party(treaty_id, local_kernel_id) {
            let error = FanoutError::TreatyMembershipDenied {
                treaty_id: treaty_id.to_string(),
                kernel_id: local_kernel_id.to_string(),
            };
            note_fanout_failure(&error);
            return Err(error);
        }
        let topic_id = pheromone_topic_for_treaty(treaty_id);
        let joined = tokio::time::timeout(
            join_timeout,
            self.gossip.subscribe_and_join(topic_id, bootstrap),
        )
        .await
        .map_err(|_elapsed| {
            FanoutError::Gossip(format!(
                "swarm join timed out after {}ms (no neighbor from bootstrap)",
                u64::try_from(join_timeout.as_millis()).unwrap_or(u64::MAX)
            ))
        })?
        .map_err(|error| FanoutError::Gossip(error.to_string()))?;
        let (sender, receiver) = joined.split();
        Ok(FanoutTopic {
            treaty_id: treaty_id.to_string(),
            topic_id,
            sender,
            receiver,
        })
    }
}

/// A joined per-treaty gossip topic: one swarm = one treaty = the confidentiality
/// boundary (ADAPTER-SPEC 4.1).
#[derive(Debug)]
pub struct FanoutTopic {
    treaty_id: String,
    topic_id: TopicId,
    sender: GossipSender,
    receiver: GossipReceiver,
}

impl FanoutTopic {
    /// The treaty this swarm carries.
    #[must_use]
    pub fn treaty_id(&self) -> &str {
        &self.treaty_id
    }

    /// The deterministic topic id for this swarm.
    #[must_use]
    pub fn topic_id(&self) -> TopicId {
        self.topic_id
    }

    /// A cheap-clone CHECKED concurrent sender, for broadcasting concurrently with a
    /// receive loop (the receiver borrows `&mut self`).
    ///
    /// Unlike a raw [`GossipSender`], every [`CheckedFanoutSender::broadcast`] runs the
    /// SAME send-side treaty binding and [`MAX_GOSSIP_MESSAGE_SIZE`] cap that
    /// [`FanoutTopic::broadcast`] enforces, so a concurrent send path cannot bypass the
    /// treaty pin or inject an oversized frame onto the swarm.
    #[must_use]
    pub fn concurrent_sender(&self) -> CheckedFanoutSender {
        CheckedFanoutSender {
            treaty_id: self.treaty_id.clone(),
            sender: self.sender.clone(),
        }
    }

    /// Broadcast a self-signed frame to the treaty swarm, enforcing the
    /// [`MAX_GOSSIP_MESSAGE_SIZE`] cap first.
    ///
    /// The frame MUST already carry a valid deposit self-signature: peers verify
    /// it origin-only on receive and DROP anything that fails.
    ///
    /// Fail-closed: a frame whose `treaty_id` does not match this swarm's treaty is
    /// REJECTED before it reaches the wire (send-side treaty binding, mirroring the
    /// receive-side check), so a mis-addressed frame cannot leak to another treaty's
    /// swarm members.
    ///
    /// # Errors
    /// Returns [`FanoutError::TreatyMismatch`] for a wrong-treaty frame,
    /// [`FanoutError::MessageTooLarge`] / [`FanoutError::Codec`] from encoding, or
    /// [`FanoutError::Gossip`] if the broadcast fails.
    pub async fn broadcast(&self, frame: &PheromoneDepositGossip) -> Result<(), FanoutError> {
        checked_broadcast(&self.sender, &self.treaty_id, frame).await
    }

    /// Await the next gossip PAYLOAD from the swarm, mapping the membership
    /// (`NeighborUp`/`NeighborDown`) and `Lagged` events away.
    ///
    /// Returns the raw [`Message`]. The caller MUST verify it with
    /// [`decode_and_verify_fanout_frame`] and MUST NOT treat
    /// [`Message::delivered_from`] (the forwarding NEIGHBOR) as the author.
    /// Returns `None` when the topic stream is closed.
    pub async fn next_payload(&mut self) -> Option<Result<Message, FanoutError>> {
        loop {
            match self.receiver.next().await {
                Some(Ok(Event::Received(message))) => return Some(Ok(message)),
                // NeighborUp / NeighborDown / Lagged are not payloads.
                Some(Ok(_)) => continue,
                Some(Err(error)) => return Some(Err(FanoutError::Gossip(error.to_string()))),
                None => return None,
            }
        }
    }

    /// Await the next payload AND verify it end-to-end: decode, ENFORCE the
    /// swarm/treaty binding (reject a frame whose `treaty_id` is not this swarm's
    /// treaty, even if its deposit self-signature is valid), run the
    /// transport-independent frame verifier, verify the deposit's OWN
    /// self-signature against the origin's resolved key, and ENFORCE the
    /// treaty-party gate (reject a frame whose ORIGIN kernel is not a party to the
    /// treaty per `membership`, so a non-party that joined the swarm anyway cannot
    /// inject an accepted frame). `delivered_from` is never consulted. `now_unix_ms`
    /// is supplied by the caller per receive.
    ///
    /// The swarm/treaty binding is what turns topic-per-treaty ROUTING separation
    /// into a hard receive-side check: a globally-admitted operator can compute a
    /// foreign treaty's (non-secret) `TopicId` and inject frames onto this swarm,
    /// but any frame carrying a different `treaty_id` is rejected here with
    /// [`FanoutError::TreatyMismatch`] (see the module docs).
    ///
    /// Returns `None` when the topic stream is closed; otherwise the verified
    /// frame or the verification error (a rejected frame over best-effort gossip
    /// is surfaced so the caller can log-and-drop it).
    pub async fn recv_verified<R, M>(
        &mut self,
        origin_keys: &R,
        membership: &M,
        policy: &PheromoneTransitPolicy,
        now_unix_ms: u64,
    ) -> Option<Result<PheromoneDepositGossip, FanoutError>>
    where
        R: OriginKeyResolver + ?Sized,
        M: TreatyMembership + ?Sized,
    {
        let message = match self.next_payload().await? {
            Ok(message) => message,
            Err(error) => return Some(Err(error)),
        };
        Some(decode_bind_treaty_and_verify(
            &message.content,
            &self.treaty_id,
            origin_keys,
            membership,
            policy,
            now_unix_ms,
        ))
    }
}

/// Broadcast `frame` on `sender` after enforcing the send-side treaty binding and the
/// [`MAX_GOSSIP_MESSAGE_SIZE`] cap. Shared by [`FanoutTopic::broadcast`] and
/// [`CheckedFanoutSender::broadcast`] so NO broadcast path (including a concurrent one)
/// can reach the raw [`GossipSender`] and skip the checks. Fail-closed: a wrong-treaty
/// frame is [`FanoutError::TreatyMismatch`] and an oversized/unencodable frame is
/// [`FanoutError::MessageTooLarge`] / [`FanoutError::Codec`], both BEFORE the frame
/// reaches the wire.
async fn checked_broadcast(
    sender: &GossipSender,
    expected_treaty_id: &str,
    frame: &PheromoneDepositGossip,
) -> Result<(), FanoutError> {
    if frame.treaty_id != expected_treaty_id {
        return Err(FanoutError::TreatyMismatch {
            expected: expected_treaty_id.to_string(),
            got: frame.treaty_id.clone(),
        });
    }
    let payload = encode_fanout_frame(frame)?;
    sender
        .broadcast(payload)
        .await
        .map_err(|error| FanoutError::Gossip(error.to_string()))
}

/// A cheap-clone concurrent broadcast handle for one treaty swarm that ENFORCES the
/// same send-side checks as [`FanoutTopic::broadcast`].
///
/// Returned by [`FanoutTopic::concurrent_sender`] so a broadcast path running
/// alongside a `&mut self` receive loop cannot reach the raw [`GossipSender`] and
/// bypass the treaty binding or the [`MAX_GOSSIP_MESSAGE_SIZE`] cap. This closes the
/// send-side treaty-pin bypass: there is no accessor that hands out the unchecked
/// sender.
#[derive(Debug, Clone)]
pub struct CheckedFanoutSender {
    treaty_id: String,
    sender: GossipSender,
}

impl CheckedFanoutSender {
    /// The treaty this sender is pinned to.
    #[must_use]
    pub fn treaty_id(&self) -> &str {
        &self.treaty_id
    }

    /// Broadcast a self-signed frame to the pinned treaty swarm, enforcing the treaty
    /// binding and the [`MAX_GOSSIP_MESSAGE_SIZE`] cap first (identical semantics to
    /// [`FanoutTopic::broadcast`]).
    ///
    /// # Errors
    /// Returns [`FanoutError::TreatyMismatch`] for a wrong-treaty frame,
    /// [`FanoutError::MessageTooLarge`] / [`FanoutError::Codec`] from encoding, or
    /// [`FanoutError::Gossip`] if the broadcast fails.
    pub async fn broadcast(&self, frame: &PheromoneDepositGossip) -> Result<(), FanoutError> {
        checked_broadcast(&self.sender, &self.treaty_id, frame).await
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use chio_core_types::Keypair;
    use chio_federation::pheromone_gossip::PheromoneDepositGossip;
    use chio_federation::pheromone_gossip::PheromoneTransitPolicy;
    use chio_federation::pheromone_gossip::PHEROMONE_GOSSIP_SCHEMA;
    use chio_federation::pheromone_gossip::PHEROMONE_TRANSIT_POLICY_SCHEMA;
    use chio_pheromone::sign_deposit;
    use chio_pheromone::PheromoneDeposit;
    use chio_pheromone::PheromoneDepositBody;
    use chio_pheromone::Severity;
    use chio_pheromone::PHEROMONE_DEPOSIT_SCHEMA;
    use iroh::endpoint::presets;
    use iroh::protocol::Router;
    use iroh::Endpoint;
    use iroh::RelayMode;
    use iroh::SecretKey;
    use iroh_gossip::api::Message;
    use iroh_gossip::proto::DeliveryScope;
    use std::net::Ipv4Addr;

    const NOW: u64 = 1_700_000_000_000;
    const NAMESPACE: &str = "chio/agents";
    const TREATY_ALPHA: &str = "treaty-alpha";
    const AUTHOR: &str = "did:chio:author";

    fn endpoint_from_seed(seed: u8) -> EndpointId {
        SecretKey::from_bytes(&[seed; 32]).public()
    }

    fn deposit_body(kernel_id: &str, treaty: &str, namespace: &str) -> PheromoneDepositBody {
        PheromoneDepositBody {
            schema: PHEROMONE_DEPOSIT_SCHEMA.to_string(),
            kernel_id: kernel_id.to_string(),
            agent_passport_key_hash: "passport-key-hash".to_string(),
            agent_passport_jwk_thumbprint: "passport-thumbprint".to_string(),
            subject_class: "malicious-tool".to_string(),
            subject_class_namespace: namespace.to_string(),
            indicator: serde_json::json!({ "kind": "observation" }),
            severity: Severity::High,
            confidence: 0.8,
            timestamp_unix_ms: NOW,
            decay_half_life_secs: 3600.0,
            evaporation_floor: None,
            nonce: "nonce-1".to_string(),
            treaty_scope: vec![treaty.to_string()],
            cost_commitment: None,
            workflow_context: None,
        }
    }

    /// A direct (non-relay) frame authored + self-signed by `author`.
    fn signed_direct_frame(
        author: &Keypair,
        author_kernel: &str,
        gossiping_peer: &str,
        treaty: &str,
        namespace: &str,
    ) -> PheromoneDepositGossip {
        let deposit = sign_deposit(deposit_body(author_kernel, treaty, namespace), author).unwrap();
        frame_over(deposit, author_kernel, gossiping_peer, treaty)
    }

    fn frame_over(
        deposit: PheromoneDeposit,
        origin: &str,
        gossiping_peer: &str,
        treaty: &str,
    ) -> PheromoneDepositGossip {
        PheromoneDepositGossip {
            schema: PHEROMONE_GOSSIP_SCHEMA.to_string(),
            deposit,
            origin_kernel_id: origin.to_string(),
            gossiping_peer_kernel_id: gossiping_peer.to_string(),
            treaty_id: treaty.to_string(),
            ts_unix_ms: NOW,
            transit_chain: None,
        }
    }

    /// A membership admitting `AUTHOR` to both treaties the tests exercise, so the
    /// treaty-party gate is a no-op for the pre-existing authenticity tests (which
    /// isolate signature / origin / binding failures). The dedicated membership
    /// tests below use a membership that does NOT admit the author.
    fn party_membership() -> StaticTreatyMembership {
        StaticTreatyMembership::new()
            .with(TREATY_ALPHA, [AUTHOR])
            .with("treaty-beta", [AUTHOR])
    }

    fn live_policy(namespace: &str) -> PheromoneTransitPolicy {
        PheromoneTransitPolicy {
            schema: PHEROMONE_TRANSIT_POLICY_SCHEMA.to_string(),
            accepted_hubs: Vec::new(),
            allowed_ingress_treaties: Vec::new(),
            allowed_egress_treaties: Vec::new(),
            allowed_subject_class_namespaces: vec![namespace.to_string()],
            valid_from_unix_ms: NOW - 1,
            valid_until_unix_ms: NOW + 1_000_000,
            max_hops: 4,
            required_action_class_id: "action".to_string(),
            pinned_ladder_refs: Vec::new(),
        }
    }

    #[test]
    fn valid_self_signed_frame_is_accepted() {
        let author = Keypair::from_seed(&[7; 32]);
        // gossiping_peer is deliberately a re-gossiping HUB, not the author: the
        // fan-out lane does not require gossiping_peer == author (unlike lanes a/b).
        let frame = signed_direct_frame(&author, AUTHOR, "did:chio:hub", TREATY_ALPHA, NAMESPACE);
        let policy = live_policy(NAMESPACE);
        let keys = StaticOriginKeys::new().with(AUTHOR, author.public_key());
        let membership = party_membership();

        verify_fanout_frame(&frame, &keys, &membership, &policy, NOW)
            .expect("valid self-signed frame accepted");

        // And through the full receive shape (mirrors the gossip PoC loop): the
        // frame arrives forwarded by some neighbor, then decode + verify accepts.
        let content = encode_fanout_frame(&frame).expect("encodes under cap");
        let neighbor = endpoint_from_seed(42);
        let event = Event::Received(Message {
            content,
            scope: DeliveryScope::Neighbors,
            delivered_from: neighbor,
        });
        match event {
            Event::Received(message) => {
                let verified = decode_and_verify_fanout_frame(
                    &message.content,
                    &keys,
                    &membership,
                    &policy,
                    NOW,
                )
                .expect("received frame verifies");
                assert_eq!(verified.origin_kernel_id, AUTHOR);
            }
            other => panic!("expected Received, got {other:?}"),
        }
    }

    #[test]
    fn bad_deposit_signature_rejected_even_from_admitted_neighbor() {
        let author = Keypair::from_seed(&[7; 32]);
        // A fully-trusted, admitted neighbor: it has its own passport key in the
        // resolver and its own admitted transport endpoint. It forwards A's frame.
        let neighbor = Keypair::from_seed(&[8; 32]);
        let neighbor_endpoint = endpoint_from_seed(43);

        let mut frame = signed_direct_frame(
            &author,
            AUTHOR,
            "did:chio:neighbor",
            TREATY_ALPHA,
            NAMESPACE,
        );
        // Tamper a signed-but-frame-irrelevant field AFTER signing: the frame-level
        // checks still pass, but the deposit self-signature no longer matches.
        frame.deposit.body.confidence = 0.123_456;

        let policy = live_policy(NAMESPACE);
        let keys = StaticOriginKeys::new()
            .with(AUTHOR, author.public_key())
            .with("did:chio:neighbor", neighbor.public_key());
        let membership = party_membership();

        // Delivered by the admitted neighbor. `delivered_from` is a genuine,
        // trusted swarm member, yet it does NOT launder the tampered payload.
        let content = encode_fanout_frame(&frame).expect("encodes under cap");
        let event = Event::Received(Message {
            content,
            scope: DeliveryScope::Neighbors,
            delivered_from: neighbor_endpoint,
        });
        match event {
            Event::Received(message) => {
                let result = decode_and_verify_fanout_frame(
                    &message.content,
                    &keys,
                    &membership,
                    &policy,
                    NOW,
                );
                assert!(
                    matches!(result, Err(FanoutError::DepositSignatureInvalid)),
                    "tampered payload must be rejected regardless of the admitted forwarder, got {result:?}"
                );
            }
            other => panic!("expected Received, got {other:?}"),
        }
    }

    #[test]
    fn unknown_origin_is_rejected() {
        let author = Keypair::from_seed(&[7; 32]);
        let frame = signed_direct_frame(&author, AUTHOR, "did:chio:hub", TREATY_ALPHA, NAMESPACE);
        let policy = live_policy(NAMESPACE);
        // Empty resolver: the origin has no bound key, so authorship is unresolvable.
        let keys = StaticOriginKeys::new();
        let membership = party_membership();

        let result = verify_fanout_frame(&frame, &keys, &membership, &policy, NOW);
        assert!(matches!(result, Err(FanoutError::UnknownOrigin(_))));
    }

    #[test]
    fn unknown_origin_bumps_verify_failure_counter_and_is_still_rejected() {
        // OBSERVE-ONLY proof: an unresolvable author still fails closed AND bumps
        // verify_failures{fanout,unknown-origin}; the returned Err is unchanged.
        let author = Keypair::from_seed(&[7; 32]);
        let frame = signed_direct_frame(&author, AUTHOR, "did:chio:hub", TREATY_ALPHA, NAMESPACE);
        let policy = live_policy(NAMESPACE);
        let keys = StaticOriginKeys::new();
        let membership = party_membership();

        let before =
            crate::metrics::verify_failures_total(crate::metrics::SEAM_FANOUT, "unknown-origin");
        let result = verify_fanout_frame(&frame, &keys, &membership, &policy, NOW);
        assert!(matches!(result, Err(FanoutError::UnknownOrigin(_))));
        assert!(
            crate::metrics::verify_failures_total(crate::metrics::SEAM_FANOUT, "unknown-origin")
                > before,
            "the fan-out verify failure must be counted (observe-only)"
        );
    }

    #[test]
    fn treaty_mismatch_bumps_verify_failure_counter_and_is_still_rejected() {
        // OBSERVE-ONLY proof for the cross-treaty injection signal: a valid-signature
        // frame minted for a foreign treaty is still rejected on this swarm AND is
        // counted (verify_failures{fanout,treaty-mismatch}).
        let author = Keypair::from_seed(&[7; 32]);
        let beta_frame =
            signed_direct_frame(&author, AUTHOR, "did:chio:hub", "treaty-beta", NAMESPACE);
        let policy = live_policy(NAMESPACE);
        let keys = StaticOriginKeys::new().with(AUTHOR, author.public_key());
        let membership = party_membership();
        let content = encode_fanout_frame(&beta_frame).expect("encodes under cap");

        let before =
            crate::metrics::verify_failures_total(crate::metrics::SEAM_FANOUT, "treaty-mismatch");
        let result =
            decode_bind_treaty_and_verify(&content, TREATY_ALPHA, &keys, &membership, &policy, NOW);
        assert!(matches!(result, Err(FanoutError::TreatyMismatch { .. })));
        assert!(
            crate::metrics::verify_failures_total(crate::metrics::SEAM_FANOUT, "treaty-mismatch")
                > before,
            "the cross-treaty injection must be counted (observe-only)"
        );
    }

    #[test]
    fn topic_derivation_is_deterministic_and_distinct_per_treaty() {
        let alpha_1 = pheromone_topic_for_treaty(TREATY_ALPHA);
        let alpha_2 = pheromone_topic_for_treaty(TREATY_ALPHA);
        let beta = pheromone_topic_for_treaty("treaty-beta");

        // Deterministic for the same treaty, distinct across treaties.
        assert_eq!(alpha_1, alpha_2);
        assert_ne!(alpha_1, beta);

        // A different domain-separation label yields a different topic for the same
        // treaty (no cross-surface collision).
        let other_surface = topic_for_treaty("chio-trust-fanout/v1", TREATY_ALPHA);
        assert_ne!(alpha_1, other_surface);

        // Exact digest: blake3(label || 0x00 || treaty) used verbatim.
        let mut hasher = blake3::Hasher::new();
        hasher.update(PHEROMONE_FANOUT_TOPIC_LABEL.as_bytes());
        hasher.update(b"\x00");
        hasher.update(TREATY_ALPHA.as_bytes());
        let expected = TopicId::from_bytes(*hasher.finalize().as_bytes());
        assert_eq!(alpha_1, expected);
    }

    #[test]
    fn oversized_frame_is_rejected_before_broadcast() {
        let author = Keypair::from_seed(&[7; 32]);
        let mut body = deposit_body(AUTHOR, TREATY_ALPHA, NAMESPACE);
        // A large indicator pushes the serialized frame past the ~4 KiB cap.
        body.indicator = serde_json::json!({ "blob": "x".repeat(5_000) });
        let deposit = sign_deposit(body, &author).unwrap();
        let frame = frame_over(deposit, AUTHOR, "did:chio:hub", TREATY_ALPHA);

        let result = encode_fanout_frame(&frame);
        assert!(matches!(result, Err(FanoutError::MessageTooLarge { .. })));
    }

    #[test]
    fn frame_from_a_foreign_treaty_is_rejected_on_this_swarm() {
        // F2 (fail-open fix): a frame minted for treaty-beta, carrying a fully
        // VALID deposit self-signature, is injected onto the alpha swarm. Routing
        // separation alone does not stop this (a globally-admitted operator can
        // compute the non-secret beta TopicId), so the RECEIVE side must bind the
        // swarm to its treaty and reject the foreign frame.
        let author = Keypair::from_seed(&[7; 32]);
        let beta_frame =
            signed_direct_frame(&author, AUTHOR, "did:chio:hub", "treaty-beta", NAMESPACE);
        let policy = live_policy(NAMESPACE);
        let keys = StaticOriginKeys::new().with(AUTHOR, author.public_key());
        let membership = party_membership();
        let content = encode_fanout_frame(&beta_frame).expect("encodes under cap");

        // Sanity: bound to its OWN treaty (beta), the frame's signature, origin, and
        // treaty-party membership all verify, so the rejection below is purely the
        // swarm/treaty binding to a DIFFERENT treaty, not a bad sig or a non-party.
        decode_bind_treaty_and_verify(&content, "treaty-beta", &keys, &membership, &policy, NOW)
            .expect("beta frame verifies when bound to the beta swarm");

        // Received on the alpha swarm (self.treaty_id = TREATY_ALPHA): rejected.
        let result =
            decode_bind_treaty_and_verify(&content, TREATY_ALPHA, &keys, &membership, &policy, NOW);
        assert!(
            matches!(
                result,
                Err(FanoutError::TreatyMismatch { ref expected, ref got })
                    if expected == TREATY_ALPHA && got == "treaty-beta"
            ),
            "a valid-signature frame bound to treaty-beta must be rejected on the alpha swarm, got {result:?}"
        );

        // And a matching-treaty frame on the same swarm still passes the binding.
        let alpha_frame =
            signed_direct_frame(&author, AUTHOR, "did:chio:hub", TREATY_ALPHA, NAMESPACE);
        let alpha_content = encode_fanout_frame(&alpha_frame).expect("encodes under cap");
        decode_bind_treaty_and_verify(
            &alpha_content,
            TREATY_ALPHA,
            &keys,
            &membership,
            &policy,
            NOW,
        )
        .expect("an alpha-treaty frame is accepted on the alpha swarm");
    }

    #[test]
    fn lane_verifies_a_real_chio_pheromone_deposit_signature() {
        // F3 guard: pin this lane's hand-copied signing preimage (clear
        // cost_commitment + canonical JSON) to the NORMATIVE signer. We build a
        // real deposit with chio_pheromone::sign_deposit and assert this lane's
        // verify_deposit_self_signature accepts it. If chio_pheromone changes its
        // canonicalization (deposit_signature_body / canonical_json), this test
        // fails loudly here instead of the copy silently diverging and rejecting
        // otherwise-valid deposits.
        let author = Keypair::from_seed(&[7; 32]);
        let deposit = sign_deposit(deposit_body(AUTHOR, TREATY_ALPHA, NAMESPACE), &author).unwrap();
        let frame = frame_over(deposit, AUTHOR, "did:chio:hub", TREATY_ALPHA);

        verify_deposit_self_signature(&frame, &author.public_key())
            .expect("lane preimage matches chio_pheromone::sign_deposit canonicalization");

        // A one-byte tamper of a signed field must then fail closed, proving the
        // acceptance above is the real signature check and not a no-op.
        let mut tampered = frame;
        tampered.deposit.body.confidence = 0.123_456;
        assert!(matches!(
            verify_deposit_self_signature(&tampered, &author.public_key()),
            Err(FanoutError::DepositSignatureInvalid)
        ));
    }

    #[test]
    fn small_frame_encodes_under_cap() {
        let author = Keypair::from_seed(&[7; 32]);
        let frame = signed_direct_frame(&author, AUTHOR, "did:chio:hub", TREATY_ALPHA, NAMESPACE);
        let payload = encode_fanout_frame(&frame).expect("encodes");
        assert!(payload.len() <= MAX_GOSSIP_MESSAGE_SIZE);
        // Round-trips back to an equal frame.
        let decoded: PheromoneDepositGossip = serde_json::from_slice(&payload).unwrap();
        assert_eq!(decoded, frame);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn subscribe_join_fails_closed_on_timeout() {
        // An empty bootstrap has no neighbor to join, so subscribe_and_join would
        // block forever; the client join bound fails it closed rather than hanging.
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&[73u8; 32]))
            .relay_mode(RelayMode::Disabled)
            .bind_addr((Ipv4Addr::LOCALHOST, 0))
            .expect("valid loopback bind addr")
            .bind()
            .await
            .expect("endpoint binds on loopback");
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let _router = Router::builder(endpoint)
            .accept(iroh_gossip::ALPN, gossip.clone())
            .spawn();
        let lane = FanoutLane::new(gossip);
        // Local operator IS a party, so it passes the membership gate and reaches
        // the (empty-bootstrap) join, which then fails closed on the client bound.
        let membership = StaticTreatyMembership::new().with(TREATY_ALPHA, [AUTHOR]);
        let result = lane
            .subscribe_treaty_with_timeout(
                TREATY_ALPHA,
                AUTHOR,
                &membership,
                vec![],
                Duration::from_millis(50),
            )
            .await;
        assert!(
            matches!(result, Err(FanoutError::Gossip(ref msg)) if msg.contains("timed out")),
            "empty-bootstrap join must fail closed on the client bound, got {result:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn broadcast_rejects_wrong_treaty_frame_before_send() {
        // Send-side treaty binding (mirrors the receive-side check): a fully
        // valid, self-signed frame minted for treaty-beta is rejected BEFORE it
        // reaches the wire when broadcast on the alpha swarm, so a mis-addressed
        // frame cannot leak onto another treaty's swarm members.
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&[71u8; 32]))
            .relay_mode(RelayMode::Disabled)
            .bind_addr((Ipv4Addr::LOCALHOST, 0))
            .expect("valid loopback bind addr")
            .bind()
            .await
            .expect("endpoint binds on loopback");
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let router = Router::builder(endpoint)
            .accept(iroh_gossip::ALPN, gossip.clone())
            .spawn();

        // subscribe (NOT join): returns immediately without a neighbor, which is
        // enough to exercise broadcast's pre-send treaty check on a single node
        // (the check returns before the sender is ever used).
        let topic_id = pheromone_topic_for_treaty(TREATY_ALPHA);
        let (sender, receiver) = gossip
            .subscribe(topic_id, vec![])
            .await
            .expect("subscribe to the alpha topic")
            .split();
        let alpha_topic = FanoutTopic {
            treaty_id: TREATY_ALPHA.to_string(),
            topic_id,
            sender,
            receiver,
        };

        // A frame with a fully VALID deposit self-signature, but minted for a
        // DIFFERENT treaty than this swarm carries.
        let author = Keypair::from_seed(&[7; 32]);
        let beta_frame =
            signed_direct_frame(&author, AUTHOR, "did:chio:hub", "treaty-beta", NAMESPACE);

        let result = alpha_topic.broadcast(&beta_frame).await;
        assert!(
            matches!(
                result,
                Err(FanoutError::TreatyMismatch { ref expected, ref got })
                    if expected == TREATY_ALPHA && got == "treaty-beta"
            ),
            "a treaty-beta frame must be rejected before the alpha swarm broadcast, got {result:?}"
        );

        drop(alpha_topic);
        router.shutdown().await.ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_sender_enforces_treaty_and_size_checks() {
        // The advertised concurrent sender (for broadcasting alongside a `&mut self`
        // receive loop) must run the SAME send-side checks as `FanoutTopic::broadcast`:
        // there is no raw-`GossipSender` escape hatch. Both a wrong-treaty frame and an
        // oversized frame are rejected BEFORE they reach the wire.
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&[74u8; 32]))
            .relay_mode(RelayMode::Disabled)
            .bind_addr((Ipv4Addr::LOCALHOST, 0))
            .expect("valid loopback bind addr")
            .bind()
            .await
            .expect("endpoint binds on loopback");
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let router = Router::builder(endpoint)
            .accept(iroh_gossip::ALPN, gossip.clone())
            .spawn();

        // subscribe (NOT join): returns immediately without a neighbor, enough to
        // exercise the pre-send checks (they return before the sender is ever used).
        let topic_id = pheromone_topic_for_treaty(TREATY_ALPHA);
        let (sender, receiver) = gossip
            .subscribe(topic_id, vec![])
            .await
            .expect("subscribe to the alpha topic")
            .split();
        let alpha_topic = FanoutTopic {
            treaty_id: TREATY_ALPHA.to_string(),
            topic_id,
            sender,
            receiver,
        };

        let concurrent = alpha_topic.concurrent_sender();
        assert_eq!(concurrent.treaty_id(), TREATY_ALPHA);

        // Wrong treaty: a fully valid, self-signed treaty-beta frame is rejected on
        // the alpha concurrent sender before any broadcast.
        let author = Keypair::from_seed(&[7; 32]);
        let beta_frame =
            signed_direct_frame(&author, AUTHOR, "did:chio:hub", "treaty-beta", NAMESPACE);
        let wrong_treaty = concurrent.broadcast(&beta_frame).await;
        assert!(
            matches!(
                wrong_treaty,
                Err(FanoutError::TreatyMismatch { ref expected, ref got })
                    if expected == TREATY_ALPHA && got == "treaty-beta"
            ),
            "the concurrent sender must reject a wrong-treaty frame, got {wrong_treaty:?}"
        );

        // Oversized: a correctly-addressed alpha frame past the ~4 KiB cap is rejected
        // too (the size check the raw sender would have skipped).
        let mut body = deposit_body(AUTHOR, TREATY_ALPHA, NAMESPACE);
        body.indicator = serde_json::json!({ "blob": "x".repeat(5_000) });
        let deposit = sign_deposit(body, &author).unwrap();
        let oversized = frame_over(deposit, AUTHOR, "did:chio:hub", TREATY_ALPHA);
        let too_large = concurrent.broadcast(&oversized).await;
        assert!(
            matches!(too_large, Err(FanoutError::MessageTooLarge { .. })),
            "the concurrent sender must reject an oversized frame, got {too_large:?}"
        );

        drop(alpha_topic);
        router.shutdown().await.ok();
    }

    #[test]
    fn receive_rejects_a_non_party_origin_frame() {
        // ITEM 1 receive side: a frame with a fully VALID deposit self-signature and
        // a resolvable origin key is still rejected if the origin kernel is NOT a
        // party to the frame's treaty, so a non-party that joined the swarm anyway
        // cannot inject an accepted frame.
        let author = Keypair::from_seed(&[7; 32]);
        let frame = signed_direct_frame(&author, AUTHOR, "did:chio:hub", TREATY_ALPHA, NAMESPACE);
        let policy = live_policy(NAMESPACE);
        let keys = StaticOriginKeys::new().with(AUTHOR, author.public_key());
        // Membership admits a DIFFERENT kernel to alpha, so AUTHOR is a non-party.
        let membership = StaticTreatyMembership::new().with(TREATY_ALPHA, ["did:chio:other"]);

        let result = verify_fanout_frame(&frame, &keys, &membership, &policy, NOW);
        assert!(
            matches!(
                result,
                Err(FanoutError::TreatyMembershipDenied { ref treaty_id, ref kernel_id })
                    if treaty_id == TREATY_ALPHA && kernel_id == AUTHOR
            ),
            "a non-party origin frame must be rejected on receive, got {result:?}"
        );

        // Same rejection through the raw decode entry.
        let content = encode_fanout_frame(&frame).expect("encodes under cap");
        let decoded = decode_and_verify_fanout_frame(&content, &keys, &membership, &policy, NOW);
        assert!(matches!(
            decoded,
            Err(FanoutError::TreatyMembershipDenied { .. })
        ));
    }

    #[test]
    fn receive_accepts_a_party_origin_frame() {
        // Control: with the origin admitted as a party to alpha, the same frame
        // verifies. The membership gate is the ONLY difference from the reject above.
        let author = Keypair::from_seed(&[7; 32]);
        let frame = signed_direct_frame(&author, AUTHOR, "did:chio:hub", TREATY_ALPHA, NAMESPACE);
        let policy = live_policy(NAMESPACE);
        let keys = StaticOriginKeys::new().with(AUTHOR, author.public_key());
        let membership = StaticTreatyMembership::new().with(TREATY_ALPHA, [AUTHOR]);

        verify_fanout_frame(&frame, &keys, &membership, &policy, NOW)
            .expect("a party origin frame verifies");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn subscribe_rejects_a_non_party_local_operator() {
        // ITEM 1 join side: a globally-admitted operator that is NOT a party to the
        // treaty is rejected BEFORE the swarm is joined, so treaty traffic never
        // reaches a non-party even though it can compute the (non-secret) topic id.
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&[75u8; 32]))
            .relay_mode(RelayMode::Disabled)
            .bind_addr((Ipv4Addr::LOCALHOST, 0))
            .expect("valid loopback bind addr")
            .bind()
            .await
            .expect("endpoint binds on loopback");
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let router = Router::builder(endpoint)
            .accept(iroh_gossip::ALPN, gossip.clone())
            .spawn();
        let lane = FanoutLane::new(gossip);

        // Membership admits a DIFFERENT operator to alpha; the local operator is a
        // non-party, so the join is rejected before any neighbor dial.
        let membership = StaticTreatyMembership::new().with(TREATY_ALPHA, ["did:chio:party"]);
        let result = lane
            .subscribe_treaty(TREATY_ALPHA, "did:chio:non-party", &membership, vec![])
            .await;
        assert!(
            matches!(
                result,
                Err(FanoutError::TreatyMembershipDenied { ref treaty_id, ref kernel_id })
                    if treaty_id == TREATY_ALPHA && kernel_id == "did:chio:non-party"
            ),
            "a non-party local operator must be rejected at join, got {result:?}"
        );
        router.shutdown().await.ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn subscribe_admits_a_party_past_the_membership_gate() {
        // A genuine party passes the membership gate and proceeds to the join; with
        // an empty bootstrap the join then times out, proving the gate let it
        // through (the error is the client join bound, NOT a membership denial).
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&[76u8; 32]))
            .relay_mode(RelayMode::Disabled)
            .bind_addr((Ipv4Addr::LOCALHOST, 0))
            .expect("valid loopback bind addr")
            .bind()
            .await
            .expect("endpoint binds on loopback");
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let router = Router::builder(endpoint)
            .accept(iroh_gossip::ALPN, gossip.clone())
            .spawn();
        let lane = FanoutLane::new(gossip);

        let membership = StaticTreatyMembership::new().with(TREATY_ALPHA, ["did:chio:party"]);
        let result = lane
            .subscribe_treaty_with_timeout(
                TREATY_ALPHA,
                "did:chio:party",
                &membership,
                vec![],
                Duration::from_millis(50),
            )
            .await;
        assert!(
            matches!(result, Err(FanoutError::Gossip(ref msg)) if msg.contains("timed out")),
            "a party must pass the membership gate and reach the empty-bootstrap join, got {result:?}"
        );
        router.shutdown().await.ok();
    }
}
