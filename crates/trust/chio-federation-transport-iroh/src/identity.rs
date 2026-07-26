//! Directory + key binding (ADAPTER-SPEC sections 3.1 and 5).
//!
//! Resolves `kernel_id <-> EndpointId` and verifies the issuer-signed directory
//! bundle at load time. The verified gate is built ONLY from a bundle that
//! passed every check (fail-closed): a tampered, out-of-window, rolled-back, or
//! wrongly-endorsed bundle produces no [`VerifiedDirectory`] at all.
//!
//! ## Relationship to the real `chio-pheromone-relay` type
//!
//! This mirrors [`chio_pheromone_relay::PeerDirectoryBundleDocument::verify`]'s
//! five fail-closed checks (body-hash pin, pinned-issuer signature, validity
//! window, `version`/`previous_version_sha256` rollback gate, and, added here,
//! the per-entry passport-over-transport endorsement). It is an ADAPTER-LOCAL
//! type rather than a direct reuse of the real `PeerDirectoryBundleDocument`
//! because that type binds `(kernel_id, passport public_key, https:// endpoint)`
//! and has neither an iroh `EndpointId` field nor a per-entry
//! passport-over-transport endorsement (ADR-0014 "Existing Transport Versus
//! Iroh"). Option B (ADAPTER-SPEC section 5) requires both.

use std::collections::HashMap;
use std::collections::HashSet;

use chio_core_types::canonical_json_bytes;
use chio_core_types::sha256_hex;
use chio_core_types::PublicKey;
use chio_core_types::Signature;
use chio_core_types::SigningAlgorithm;
use chio_revocation_oracle::Ed25519RootVerifier;
use iroh::EndpointId;
use serde::Deserialize;
use serde::Serialize;

use crate::lanes::revocation::SignerBinding;
use crate::lanes::revocation::VerifiedSignerDirectory;

/// Schema pin for the adapter's issuer-signed transport-directory bundle.
///
/// Bumped to `v2` for the domain-separated endorsement preimages
/// ([`transport_endorsement_preimage`], [`revocation_signer_endorsement_preimage`])
/// and the additive [`TransportDirectoryEntry::revocation_signers`] binding. Both
/// are pre-deployment wire-format changes (there is no v1 deployment to migrate),
/// and the bump keeps the rollback / version story honest.
pub const TRANSPORT_DIRECTORY_BUNDLE_SCHEMA: &str =
    "chio.federation.transport.iroh.peer-directory-bundle.v2";

/// Domain-separation context for the passport-over-transport endorsement. The
/// passport signs [`transport_endorsement_preimage`] (this tag, the entry
/// `kernel_id`, and the transport `EndpointId`, each length-prefixed), so an
/// endorsement commits to WHICH operator owns WHICH endpoint. Distinct from
/// [`REVOCATION_SIGNER_ENDORSEMENT_CONTEXT`] so the two endorsement kinds can
/// NEVER cross-replay (a signature valid as one is rejected as the other).
pub const TRANSPORT_ENDORSEMENT_CONTEXT: &[u8] = b"chio.iroh.transport-endorsement.v1";

/// Domain-separation context for the passport-over-oracle (revocation signer)
/// endorsement. The passport signs [`revocation_signer_endorsement_preimage`]
/// (this tag, the entry `kernel_id`, the opaque `signer_id`, and the oracle root
/// public key, each length-prefixed), so it commits to WHICH operator vouches for
/// WHICH oracle key under a DISTINCT tag from the transport endorsement.
pub const REVOCATION_SIGNER_ENDORSEMENT_CONTEXT: &[u8] =
    b"chio.iroh.revocation-signer-endorsement.v1";

/// Append `segment` to `buf` as an 8-byte big-endian length followed by the
/// segment bytes. Every field of a preimage is length-delimited, so the
/// concatenation is an injective (collision-free) encoding of the field tuple: no
/// two distinct `(context, fields...)` tuples can serialize to the same bytes,
/// which is what makes the two endorsement domains non-cross-replayable.
fn push_length_prefixed(buf: &mut Vec<u8>, segment: &[u8]) {
    buf.extend_from_slice(&(segment.len() as u64).to_be_bytes());
    buf.extend_from_slice(segment);
}

/// The exact bytes a passport signs (and [`TransportDirectoryBundleDocument::verify_bundle`]
/// re-derives) for the passport-over-transport endorsement: the domain tag, the
/// entry `kernel_id`, and the transport `EndpointId`, each length-prefixed. This
/// is the single source of truth for the preimage; every construction site MUST
/// sign these exact bytes.
#[must_use]
pub fn transport_endorsement_preimage(
    kernel_id: &str,
    transport_endpoint_id: &EndpointId,
) -> Vec<u8> {
    let mut buf = Vec::new();
    push_length_prefixed(&mut buf, TRANSPORT_ENDORSEMENT_CONTEXT);
    push_length_prefixed(&mut buf, kernel_id.as_bytes());
    push_length_prefixed(&mut buf, transport_endpoint_id.as_bytes());
    buf
}

/// The exact bytes a passport signs (and [`TransportDirectoryBundleDocument::verify_bundle`]
/// re-derives) for the passport-over-oracle endorsement that anchors a revocation
/// signer: the domain tag, the entry `kernel_id`, the opaque `signer_id`, and the
/// canonical hex of the oracle root public key, each length-prefixed. The canonical
/// hex encodes the key algorithm and bytes faithfully (it round-trips through
/// [`PublicKey::from_hex`]), so the endorsement commits to the exact oracle key.
#[must_use]
pub fn revocation_signer_endorsement_preimage(
    kernel_id: &str,
    signer_id: &str,
    oracle_public_key: &PublicKey,
) -> Vec<u8> {
    let mut buf = Vec::new();
    push_length_prefixed(&mut buf, REVOCATION_SIGNER_ENDORSEMENT_CONTEXT);
    push_length_prefixed(&mut buf, kernel_id.as_bytes());
    push_length_prefixed(&mut buf, signer_id.as_bytes());
    push_length_prefixed(&mut buf, oracle_public_key.to_hex().as_bytes());
    buf
}

/// A single Option B binding: a long-term passport key cross-linked to a
/// rotatable ed25519 transport `EndpointId` by a passport-signed endorsement.
///
/// (ADAPTER-SPEC section 5: "the passport signing key stays the long-term
/// operator identity; a rotatable ed25519 transport `EndpointId` is bound to the
/// operator in the issuer-signed directory bundle ... plus a passport-signed
/// endorsement of the transport `EndpointId`".)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportDirectoryEntry {
    /// Operator identity string (`did:chio:...`) at the federation layer.
    pub kernel_id: String,
    /// Long-term operator passport key (any [`chio_core_types::SigningAlgorithm`]).
    /// Retained as the algorithm-agnostic auth key; NOT collapsed into the
    /// transport key (Option B is mandatory for non-Ed25519 passports).
    pub passport_public_key: PublicKey,
    /// Rotatable ed25519 transport `EndpointId` that iroh dials and authenticates.
    pub transport_endpoint_id: EndpointId,
    /// Passport signature over [`transport_endorsement_preimage`] (the domain tag,
    /// the `kernel_id`, and the transport `EndpointId`): the passport-over-transport
    /// endorsement that keeps the transport key from floating free of the long-term
    /// identity, domain-separated so it can never be replayed as an oracle
    /// endorsement.
    pub passport_endorsement: Signature,
    /// Additive per-entry oracle revocation-signer bindings (Option B for the
    /// revocation lane). Each binds `signer_id -> oracle_public_key` to this
    /// operator via a domain-separated passport endorsement; the transport origin
    /// is this entry's `transport_endpoint_id`, so the origin pin is structural.
    /// `#[serde(default)]` keeps a signer-less (v1-style) entry wire-compatible.
    #[serde(default)]
    pub revocation_signers: Vec<RevocationSignerEntry>,
    /// Issuer-signed tombstone. A removed entry never resolves (fail-closed),
    /// mirroring `PeerDirectory::peer` rejecting `removed_peer_ids`. A removed
    /// entry also suppresses its `revocation_signers` from the derived signer
    /// directory, so evicting an operator revokes its oracle signer in the same
    /// bundle.
    #[serde(default)]
    pub removed: bool,
}

/// Binds an oracle revocation root signer to the operator identity that owns the
/// enclosing [`TransportDirectoryEntry`]. The transport `EndpointId` that may
/// originate this signer's roots is the entry's `transport_endpoint_id`, so the
/// origin pin is STRUCTURAL (no separate endpoint field): signer and endpoint
/// live in one issuer-signed entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationSignerEntry {
    /// Opaque oracle signer id; equals the on-wire `RootSignature.signer_id` and
    /// the pinned [`chio_revocation_oracle::Ed25519RootVerifier`]'s `signer_id`.
    pub signer_id: String,
    /// Verify-only oracle root key (the Ed25519 root the epoch-root signatures are
    /// checked against). Holds no private material, so it can never forge a root.
    pub oracle_public_key: PublicKey,
    /// Passport signature over [`revocation_signer_endorsement_preimage`], binding
    /// the oracle key to the long-term operator identity under a DISTINCT domain
    /// tag from the transport endorsement. Verified against the entry's
    /// `passport_public_key` at load time.
    pub oracle_endorsement: Signature,
}

/// An issuer-signed per-treaty PARTY SET: the set of operator `kernel_id`s that
/// are parties to `treaty_id`.
///
/// This rides the SAME trusted, anti-rollback substrate as the transport keys
/// (the issuer-signed directory bundle, body-hash-pinned, validity-windowed, and
/// monotone-versioned), so the fan-out lane can gate a treaty's gossip swarm to
/// its actual party set rather than to federation-wide admission alone. Membership
/// is fail-closed: an operator absent from `party_kernel_ids` (or a treaty absent
/// from the directory) is NOT a party.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportTreatyEntry {
    /// The treaty this party set is bound to (the same `String` treaty id the
    /// fan-out topic derivation and pheromone frames carry).
    pub treaty_id: String,
    /// The operator `kernel_id`s that are parties to `treaty_id`. Verified
    /// non-empty and duplicate-free at bundle-load time.
    pub party_kernel_ids: Vec<String>,
}

/// The directory document that is canonical-hashed and pinned by the signed body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportDirectoryDocument {
    /// Schema pin for the directory document.
    pub schema: String,
    /// Kernel id of the operator that issued (owns) this directory view.
    pub local_kernel_id: String,
    /// The per-operator transport bindings.
    pub peers: Vec<TransportDirectoryEntry>,
    /// Additive per-treaty party sets (the treaty-membership substrate the
    /// fan-out lane gates on). `#[serde(default)]` keeps a treaty-less directory
    /// (the pre-existing shape) wire-compatible: a directory that binds no party
    /// sets simply admits nobody to any treaty (fail-closed).
    #[serde(default)]
    pub treaties: Vec<TransportTreatyEntry>,
}

/// The issuer-signed body. This is the value the pinned issuer signs; it pins
/// the directory by `directory_sha256` and carries the monotone version, the
/// rollback-chaining predecessor hash, and the validity window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportDirectoryBundleBody {
    /// Schema pin (must equal [`TRANSPORT_DIRECTORY_BUNDLE_SCHEMA`]).
    pub schema: String,
    /// Issuer identity, matched against the pinned trust set.
    pub issuer: String,
    /// Issuer key id, matched against the pinned trust set.
    pub key_id: String,
    /// Canonical sha256 of the pinned [`TransportDirectoryDocument`].
    pub directory_sha256: String,
    /// Monotone bundle version. Must be strictly greater than the trust floor.
    pub version: u64,
    /// Canonical sha256 of the predecessor bundle, or `None` for the first bundle.
    pub previous_version_sha256: Option<String>,
    /// Start of the validity window (inclusive), unix milliseconds.
    pub issued_at_unix_ms: u64,
    /// End of the validity window (exclusive), unix milliseconds.
    pub expires_at_unix_ms: u64,
}

/// The full signed bundle: `schema`, the signed `body`, the pinned `directory`,
/// and the issuer `signature` over `body`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportDirectoryBundleDocument {
    /// Schema pin (must equal [`TRANSPORT_DIRECTORY_BUNDLE_SCHEMA`]).
    pub schema: String,
    /// The issuer-signed body.
    pub body: TransportDirectoryBundleBody,
    /// The pinned directory document (bound to `body.directory_sha256`).
    pub directory: TransportDirectoryDocument,
    /// Issuer signature over the canonical JSON of `body`.
    pub signature: Signature,
}

/// A pinned directory issuer (mirrors
/// [`chio_pheromone_relay::TrustedPeerDirectoryIssuer`]).
#[derive(Debug, Clone)]
pub struct TrustedTransportDirectoryIssuer {
    /// Issuer identity.
    pub issuer: String,
    /// Issuer key id.
    pub key_id: String,
    /// Issuer public key used to verify the bundle body signature.
    pub public_key: PublicKey,
}

/// Load-time trust inputs for [`TransportDirectoryBundleDocument::verify_bundle`].
#[derive(Debug, Clone)]
pub struct TransportDirectoryBundleTrust {
    /// The set of pinned issuers; a bundle must be signed by one of these.
    pub issuers: Vec<TrustedTransportDirectoryIssuer>,
    /// Rollback floor: an accepted bundle's `version` MUST be strictly greater.
    pub version_floor: u64,
    /// The expected predecessor bundle hash the candidate must chain onto
    /// (`None` when promoting the first bundle). Mirrors the
    /// `previous_version_sha256` chaining in `promote_peer_directory_candidate`.
    pub expected_previous_version_sha256: Option<String>,
    /// Current time, unix milliseconds, for the validity-window check.
    pub now_unix_ms: u64,
}

/// Errors raised while verifying a transport-directory bundle. Every variant is
/// a hard reject: verification is fail-closed and yields no directory.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdentityError {
    /// A schema field did not match the pinned schema.
    #[error("unsupported schema: {0}")]
    UnsupportedSchema(String),
    /// The bundle version is not strictly above the trusted rollback floor.
    #[error("bundle version {version} is not above the trusted floor {floor}")]
    Rollback {
        /// The offending bundle version.
        version: u64,
        /// The trusted rollback floor.
        floor: u64,
    },
    /// The bundle's `previous_version_sha256` does not chain onto the expected
    /// predecessor bundle hash.
    #[error("bundle previous-version hash does not chain onto the expected predecessor")]
    PreviousVersionMismatch,
    /// `now` is outside `[issued_at, expires_at)`.
    #[error("bundle is outside its validity window")]
    OutsideValidityWindow,
    /// The recomputed directory hash does not match the signed `directory_sha256`.
    #[error("directory hash {actual} does not match signed hash {signed}")]
    BodyHashMismatch {
        /// The recomputed canonical directory hash.
        actual: String,
        /// The hash pinned by the signed body.
        signed: String,
    },
    /// No pinned issuer matched `(issuer, key_id)`.
    #[error("unknown or unpinned directory issuer: {0}")]
    UnknownIssuer(String),
    /// The issuer signature over the body did not verify.
    #[error("issuer signature is invalid")]
    SignatureInvalid,
    /// The per-entry passport-over-transport endorsement did not verify.
    #[error("passport-over-transport endorsement is invalid for kernel {0}")]
    EndorsementInvalid(String),
    /// A per-entry oracle revocation-signer endorsement did not verify against
    /// the entry's passport key (or a foreign-domain signature was replayed here).
    #[error(
        "oracle revocation-signer endorsement is invalid for kernel {kernel_id} signer {signer_id}"
    )]
    OracleEndorsementInvalid {
        /// The kernel whose passport failed to endorse the oracle key.
        kernel_id: String,
        /// The oracle signer id whose endorsement failed.
        signer_id: String,
    },
    /// A revocation-signer entry pinned a non-Ed25519 `oracle_public_key`. Lane-b
    /// epoch roots are verified by an [`Ed25519RootVerifier`], so a P-256 / P-384 /
    /// hybrid oracle key would be wrapped and then SILENTLY fail every root verify;
    /// reject it at bundle-verify time (fail-closed) instead of accept-then-fail.
    #[error(
        "oracle revocation-signer key for kernel {kernel_id} signer {signer_id} is not Ed25519 (algorithm {algorithm:?})"
    )]
    NonEd25519OracleKey {
        /// The kernel whose entry declared the non-Ed25519 oracle key.
        kernel_id: String,
        /// The oracle signer id whose key is not Ed25519.
        signer_id: String,
        /// The offending key's signing algorithm.
        algorithm: SigningAlgorithm,
    },
    /// A directory entry was structurally malformed.
    #[error("malformed directory entry: {0}")]
    MalformedEntry(String),
    /// A `kernel_id` or transport `EndpointId` appeared more than once.
    #[error("duplicate directory {0}")]
    Duplicate(String),
    /// The directory bound no peers.
    #[error("directory contains no peers")]
    EmptyDirectory,
    /// Canonical JSON serialization failed while hashing or verifying.
    #[error("canonical json error: {0}")]
    CanonicalJson(String),
}

impl IdentityError {
    /// Stable, log- and metric-friendly code for this bundle-verification failure.
    /// The values are bounded (one per variant), so they are safe as a Prometheus
    /// `reason` label on `chio_federation_transport_verify_failures_total`.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedSchema(_) => "unsupported-schema",
            Self::Rollback { .. } => "rollback",
            Self::PreviousVersionMismatch => "previous-version-mismatch",
            Self::OutsideValidityWindow => "outside-validity-window",
            Self::BodyHashMismatch { .. } => "body-hash-mismatch",
            Self::UnknownIssuer(_) => "unknown-issuer",
            Self::SignatureInvalid => "signature-invalid",
            Self::EndorsementInvalid(_) => "endorsement-invalid",
            Self::OracleEndorsementInvalid { .. } => "oracle-endorsement-invalid",
            Self::NonEd25519OracleKey { .. } => "non-ed25519-oracle-key",
            Self::MalformedEntry(_) => "malformed-entry",
            Self::Duplicate(_) => "duplicate",
            Self::EmptyDirectory => "empty-directory",
            Self::CanonicalJson(_) => "canonical-json",
        }
    }
}

/// A directory that passed every check. The gate is built ONLY from this type,
/// so it can never resolve against an unverified bundle (ADAPTER-SPEC section 5).
///
/// It carries three derived indices built in the SAME verified pass: `by_endpoint`
/// (`EndpointId -> kernel_id`), `by_kernel_passport` (`kernel_id -> passport key`
/// for non-removed entries), and the [`VerifiedSignerDirectory`] projection
/// (`signer_id -> (EndpointId, oracle verifier)`). Each inherits the body-hash pin,
/// issuer signature, validity window, and rollback machinery for free, so both the
/// revocation transport-origin pin and the bilateral lane's DSSE-verification key
/// are structural (directory-bound) rather than separately-fed maps that can lag.
#[derive(Debug, Clone)]
pub struct VerifiedDirectory {
    by_endpoint: HashMap<EndpointId, (String, bool)>,
    /// `kernel_id -> passport public key`, built in the same verified pass from the
    /// issuer-signed [`TransportDirectoryEntry::passport_public_key`] of NON-removed
    /// entries. This is the directory-bound source of the bilateral lane's Org B
    /// DSSE-verification key: binding co-sign verification to THIS snapshot means a
    /// rotated-away or revoked passport (absent from the current bundle) is never
    /// accepted, even if a separately-pinned map lags the signed directory.
    by_kernel_passport: HashMap<String, PublicKey>,
    signers: VerifiedSignerDirectory,
    /// `treaty_id -> set of party kernel_ids`, built in the same verified pass
    /// from the issuer-signed [`TransportTreatyEntry`] set. Fail-closed:
    /// membership is denied for any treaty or kernel absent from this index.
    treaty_parties: HashMap<String, HashSet<String>>,
    version: u64,
    body_sha256: String,
    expires_at_unix_ms: u64,
}

impl VerifiedDirectory {
    /// Resolve an authenticated `EndpointId` to its admitted `kernel_id`.
    ///
    /// Returns `None` (fail-closed) when the endpoint is unbound OR bound to a
    /// removed entry. This is the one resolution the admission gate and the lane
    /// handlers share; it feeds `authenticated_sender_kernel_id` above the
    /// transport, never replacing the per-frame verifier.
    #[must_use]
    pub fn authorize(&self, endpoint: &EndpointId) -> Option<&str> {
        match self.by_endpoint.get(endpoint) {
            Some((kernel_id, false)) => Some(kernel_id.as_str()),
            // Unbound (`None`) or removed (`Some((_, true))`) both deny.
            _ => None,
        }
    }

    /// Resolve an admitted `kernel_id` to its bound transport [`EndpointId`], the
    /// reverse of [`authorize`](Self::authorize).
    ///
    /// Returns `None` (fail-closed) when the kernel is unknown OR its entry is a
    /// removed tombstone, so an outbound drain (the relay tick) never dials a removed
    /// or unadmitted recipient over the transport. This is the outbound-address side
    /// of the same issuer-signed binding `authorize` reads on the inbound side.
    #[must_use]
    pub fn resolve_transport_endpoint(&self, kernel_id: &str) -> Option<EndpointId> {
        self.by_endpoint
            .iter()
            .find_map(|(endpoint, (bound_kernel_id, removed))| {
                (!*removed && bound_kernel_id == kernel_id).then_some(*endpoint)
            })
    }

    /// Resolve an admitted `kernel_id` to its issuer-signed, load-time-verified
    /// passport public key (the algorithm-agnostic long-term operator key the
    /// bundle binds, and that the passport-over-transport endorsement was checked
    /// against).
    ///
    /// Returns `None` (fail-closed) when the kernel is unknown OR its entry is a
    /// removed tombstone. The bilateral co-sign lane sources Org B's
    /// DSSE-verification key from HERE so verification is bound to the SAME
    /// verified snapshot the admission gate authorized on: a rotated-away or
    /// revoked passport (one the current directory no longer binds) can never be
    /// used to obtain a co-signature.
    #[must_use]
    pub fn resolve_passport_key(&self, kernel_id: &str) -> Option<&PublicKey> {
        self.by_kernel_passport.get(kernel_id)
    }

    /// The derived `signer_id -> (EndpointId, oracle verifier)` projection built
    /// from the same issuer-signed bundle. This is the production source of the
    /// revocation lane's [`VerifiedSignerDirectory`]: signer and endpoint
    /// originate from one issuer-signed entry, so the transport-origin pin is
    /// structural.
    #[must_use]
    pub fn signer_directory(&self) -> &VerifiedSignerDirectory {
        &self.signers
    }

    /// Resolve an opaque revocation `signer_id` to its issuer-signed binding, or
    /// `None` (fail-closed) when the signer is unbound or its operator is removed.
    #[must_use]
    pub fn resolve_signer(&self, signer_id: &str) -> Option<&SignerBinding> {
        self.signers.resolve(signer_id)
    }

    /// Whether `kernel_id` is a party to `treaty_id` per the issuer-signed
    /// per-treaty party set.
    ///
    /// Fail-closed: returns `false` when the treaty is unknown to this directory
    /// OR the kernel is not in that treaty's party set. This is the trusted,
    /// anti-rollback source the fan-out lane gates swarm join AND frame receive on
    /// (a treaty party set inherits the bundle's issuer signature, body-hash pin,
    /// validity window, and monotone-version rollback machinery).
    #[must_use]
    pub fn is_treaty_party(&self, treaty_id: &str, kernel_id: &str) -> bool {
        self.treaty_parties
            .get(treaty_id)
            .is_some_and(|parties| parties.contains(kernel_id))
    }

    /// The monotone version of the bundle this directory was built from.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The canonical sha256 of the bundle this directory was built from. A
    /// successor bundle pins this as its `previous_version_sha256`.
    #[must_use]
    pub fn body_sha256(&self) -> &str {
        &self.body_sha256
    }

    /// The bundle validity-window end this directory was verified against (the
    /// same field the load-time validity check reads). The reloader compares this
    /// against `now` BEFORE any unchanged fast path.
    #[must_use]
    pub fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    /// A deny-all directory: admits nothing, is party to no treaty. Used as the
    /// fail-closed terminal state when the running bundle expires with no valid
    /// successor. version 0, expiry 0, empty indices.
    #[must_use]
    pub fn empty_deny_all() -> Self {
        Self {
            by_endpoint: HashMap::new(),
            by_kernel_passport: HashMap::new(),
            signers: VerifiedSignerDirectory::from_verified_map(HashMap::new()),
            treaty_parties: HashMap::new(),
            version: 0,
            body_sha256: String::new(),
            expires_at_unix_ms: 0,
        }
    }

    /// Number of admitted (and removed) bindings held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_endpoint.len()
    }

    /// Whether the directory holds no bindings.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_endpoint.is_empty()
    }
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, IdentityError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| IdentityError::CanonicalJson(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

impl TransportDirectoryBundleDocument {
    /// Verify the bundle at load time and, only on success, build the
    /// [`VerifiedDirectory`] the admission gate is constructed from.
    ///
    /// Checks, in order, all fail-closed (mirrors
    /// `PeerDirectoryBundleDocument::verify` plus the Option B endorsements):
    /// 1. schema pins,
    /// 2. rollback gate: `version` strictly above the floor AND
    ///    `previous_version_sha256` chains onto the expected predecessor,
    /// 3. validity window `now in [issued_at, expires_at)`,
    /// 4. body-hash pin: recomputed directory hash equals the signed hash,
    /// 5. pinned-issuer signature over the body,
    /// 6. per-entry domain-separated passport-over-transport endorsement, and per
    ///    revocation-signer entry a domain-separated passport-over-oracle
    ///    endorsement, projected into the derived [`VerifiedSignerDirectory`]
    ///    (non-removed entries only; duplicate `signer_id` rejected fail-closed),
    /// 7. per-treaty party sets validated (non-empty, duplicate-free) and indexed
    ///    into the `treaty_id -> {party kernel_ids}` membership map the fan-out
    ///    lane gates on (additive; a treaty-less directory denies every treaty).
    pub fn verify_bundle(
        &self,
        trust: &TransportDirectoryBundleTrust,
    ) -> Result<VerifiedDirectory, IdentityError> {
        // Observe-only wrapper: `verify_bundle_inner` holds the fail-closed
        // verification logic; here we count and log a rejection alongside it and
        // return the same `Result`, so a tampered or rolled-back directory bundle
        // is distinguishable from a healthy load in the telemetry.
        let result = self.verify_bundle_inner(trust);
        if let Err(error) = &result {
            crate::metrics::record_verify_failure(crate::metrics::SEAM_IDENTITY, error.code());
            tracing::warn!(
                target: crate::observability::TARGET_VERIFY,
                seam = crate::metrics::SEAM_IDENTITY,
                reason = error.code(),
                issuer = %self.body.issuer,
                version = self.body.version,
                "directory bundle verification failed"
            );
        }
        result
    }

    fn verify_bundle_inner(
        &self,
        trust: &TransportDirectoryBundleTrust,
    ) -> Result<VerifiedDirectory, IdentityError> {
        // (1) schema pins.
        if self.schema != TRANSPORT_DIRECTORY_BUNDLE_SCHEMA {
            return Err(IdentityError::UnsupportedSchema(self.schema.clone()));
        }
        if self.body.schema != TRANSPORT_DIRECTORY_BUNDLE_SCHEMA {
            return Err(IdentityError::UnsupportedSchema(self.body.schema.clone()));
        }
        if self.directory.schema != TRANSPORT_DIRECTORY_BUNDLE_SCHEMA {
            return Err(IdentityError::UnsupportedSchema(
                self.directory.schema.clone(),
            ));
        }

        // (2) rollback gate: strictly-monotone version AND predecessor chaining.
        if self.body.version <= trust.version_floor {
            return Err(IdentityError::Rollback {
                version: self.body.version,
                floor: trust.version_floor,
            });
        }
        if self.body.previous_version_sha256 != trust.expected_previous_version_sha256 {
            return Err(IdentityError::PreviousVersionMismatch);
        }

        // (3) validity window.
        if trust.now_unix_ms < self.body.issued_at_unix_ms
            || trust.now_unix_ms >= self.body.expires_at_unix_ms
        {
            return Err(IdentityError::OutsideValidityWindow);
        }

        // (4) body-hash pin: the signed body pins the directory by hash.
        let actual_directory_sha256 = canonical_sha256(&self.directory)?;
        if actual_directory_sha256 != self.body.directory_sha256 {
            return Err(IdentityError::BodyHashMismatch {
                actual: actual_directory_sha256,
                signed: self.body.directory_sha256.clone(),
            });
        }

        // (5) pinned-issuer signature over the body.
        let issuer = trust
            .issuers
            .iter()
            .find(|issuer| issuer.issuer == self.body.issuer && issuer.key_id == self.body.key_id)
            .ok_or_else(|| {
                IdentityError::UnknownIssuer(format!("{}#{}", self.body.issuer, self.body.key_id))
            })?;
        let signature_ok = issuer
            .public_key
            .verify_canonical(&self.body, &self.signature)
            .map_err(|error| IdentityError::CanonicalJson(error.to_string()))?;
        if !signature_ok {
            return Err(IdentityError::SignatureInvalid);
        }

        // (6) per-entry structure + domain-separated endorsements. Also builds
        // the derived signer projection in the same pass.
        let mut by_endpoint: HashMap<EndpointId, (String, bool)> = HashMap::new();
        let mut by_kernel_passport: HashMap<String, PublicKey> = HashMap::new();
        let mut by_signer: HashMap<String, SignerBinding> = HashMap::new();
        let mut seen_kernel_ids: HashSet<&str> = HashSet::new();
        for entry in &self.directory.peers {
            let kernel_id = entry.kernel_id.trim();
            if kernel_id.is_empty() || kernel_id != entry.kernel_id {
                return Err(IdentityError::MalformedEntry(
                    "kernel id is empty or padded".to_string(),
                ));
            }
            if !seen_kernel_ids.insert(entry.kernel_id.as_str()) {
                return Err(IdentityError::Duplicate(format!(
                    "kernel id {}",
                    entry.kernel_id
                )));
            }
            // The endorsement binds the long-term passport to the transport key:
            // the passport (any algorithm) must sign the DOMAIN-SEPARATED preimage
            // committing to (context, kernel_id, transport endpoint).
            //
            // A removed entry is a tombstone (suppressed, not resolved): skip its
            // transport endorsement check, mirroring the revocation-signer skip
            // below. Otherwise an eviction bundle that tombstones a peer whose
            // transport endorsement is missing/invalid would fail to verify, so the
            // stale directory would stay active. The removed endpoint still records
            // as removed and resolves to None (fail-closed) regardless, so skipping
            // the endorsement of a suppressed entry costs no authority.
            if !entry.removed {
                let transport_preimage =
                    transport_endorsement_preimage(&entry.kernel_id, &entry.transport_endpoint_id);
                let endorsed = entry
                    .passport_public_key
                    .verify(&transport_preimage, &entry.passport_endorsement);
                if !endorsed {
                    return Err(IdentityError::EndorsementInvalid(entry.kernel_id.clone()));
                }
                // Bind the issuer-signed passport key to this kernel for the
                // bilateral lane's directory-sourced DSSE verification. Only
                // non-removed entries contribute (fail-closed: a tombstoned
                // operator has no co-sign key). `kernel_id` is deduped above, so
                // there is exactly one passport binding per admitted operator.
                by_kernel_passport
                    .insert(entry.kernel_id.clone(), entry.passport_public_key.clone());
            }
            // Per-entry oracle revocation-signer bindings. Each non-removed entry
            // is verified against the SAME passport under a DISTINCT domain tag,
            // then projected into the derived signer directory with the entry's
            // transport endpoint as the structural origin pin.
            for signer in &entry.revocation_signers {
                // A removed operator contributes no signer (fail-closed): eviction
                // revokes its oracle signer in the same bundle, so its oracle
                // material is NOT validated here. Suppressing the binding before
                // the endorsement check keeps eviction from being over-strict: a
                // removed operator whose oracle endorsement is stale or malformed
                // must not fail the whole bundle (its signer is dropped anyway).
                if entry.removed {
                    continue;
                }
                let signer_preimage = revocation_signer_endorsement_preimage(
                    &entry.kernel_id,
                    &signer.signer_id,
                    &signer.oracle_public_key,
                );
                let oracle_endorsed = entry
                    .passport_public_key
                    .verify(&signer_preimage, &signer.oracle_endorsement);
                if !oracle_endorsed {
                    return Err(IdentityError::OracleEndorsementInvalid {
                        kernel_id: entry.kernel_id.clone(),
                        signer_id: signer.signer_id.clone(),
                    });
                }
                // The oracle root is verified by an Ed25519RootVerifier, so a
                // non-Ed25519 oracle key (even with a valid passport endorsement)
                // would be wrapped and then silently fail every lane-b root verify.
                // Reject it here (fail-closed, typed) rather than accept-then-fail.
                let algorithm = signer.oracle_public_key.algorithm();
                if algorithm != SigningAlgorithm::Ed25519 {
                    return Err(IdentityError::NonEd25519OracleKey {
                        kernel_id: entry.kernel_id.clone(),
                        signer_id: signer.signer_id.clone(),
                        algorithm,
                    });
                }
                let binding = SignerBinding {
                    endpoint: entry.transport_endpoint_id,
                    verifier: Ed25519RootVerifier::new(
                        signer.signer_id.clone(),
                        signer.oracle_public_key.clone(),
                    ),
                };
                if by_signer
                    .insert(signer.signer_id.clone(), binding)
                    .is_some()
                {
                    return Err(IdentityError::Duplicate(format!(
                        "revocation signer {}",
                        signer.signer_id
                    )));
                }
            }
            if by_endpoint
                .insert(
                    entry.transport_endpoint_id,
                    (entry.kernel_id.clone(), entry.removed),
                )
                .is_some()
            {
                return Err(IdentityError::Duplicate(format!(
                    "transport endpoint {}",
                    entry.transport_endpoint_id.fmt_short()
                )));
            }
        }
        if by_endpoint.is_empty() {
            return Err(IdentityError::EmptyDirectory);
        }

        // (7) per-treaty party sets. Structurally validated (non-empty,
        // duplicate-free) and indexed into `treaty_id -> {party kernel_ids}`. This
        // is additive: a directory with no treaty entries yields an empty index, so
        // every treaty membership check fails closed (denies).
        let mut treaty_parties: HashMap<String, HashSet<String>> = HashMap::new();
        for treaty in &self.directory.treaties {
            if treaty.treaty_id.trim().is_empty() || treaty.treaty_id.trim() != treaty.treaty_id {
                return Err(IdentityError::MalformedEntry(
                    "treaty id is empty or padded".to_string(),
                ));
            }
            if treaty.party_kernel_ids.is_empty() {
                return Err(IdentityError::MalformedEntry(format!(
                    "treaty {} binds no parties",
                    treaty.treaty_id
                )));
            }
            let mut parties: HashSet<String> = HashSet::new();
            for party in &treaty.party_kernel_ids {
                if party.trim().is_empty() || party.trim() != party {
                    return Err(IdentityError::MalformedEntry(
                        "treaty party kernel id is empty or padded".to_string(),
                    ));
                }
                // A treaty party must be a current, non-removed operator bound in
                // this same signed directory. `by_kernel_passport` holds exactly the
                // non-removed operators (tombstoned/unknown kernels are absent), so a
                // treaty that lists a party without a current binding is rejected
                // fail-closed rather than admitted into the party set.
                if !by_kernel_passport.contains_key(party) {
                    return Err(IdentityError::MalformedEntry(format!(
                        "treaty {} lists party {} with no current directory passport binding",
                        treaty.treaty_id, party
                    )));
                }
                if !parties.insert(party.clone()) {
                    return Err(IdentityError::Duplicate(format!(
                        "treaty {} party {}",
                        treaty.treaty_id, party
                    )));
                }
            }
            if treaty_parties
                .insert(treaty.treaty_id.clone(), parties)
                .is_some()
            {
                return Err(IdentityError::Duplicate(format!(
                    "treaty {}",
                    treaty.treaty_id
                )));
            }
        }

        let body_sha256 = canonical_sha256(self)?;
        Ok(VerifiedDirectory {
            by_endpoint,
            by_kernel_passport,
            signers: VerifiedSignerDirectory::from_verified_map(by_signer),
            treaty_parties,
            version: self.body.version,
            body_sha256,
            expires_at_unix_ms: self.body.expires_at_unix_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use chio_core_types::Keypair;
    use iroh::SecretKey;

    const ISSUER: &str = "did:chio:issuer";
    const KEY_ID: &str = "issuer-key-1";
    const NOW: u64 = 1_000_000;

    fn endpoint_from_seed(seed: u8) -> EndpointId {
        SecretKey::from_bytes(&[seed; 32]).public()
    }

    fn passport_from_seed(seed: u8) -> Keypair {
        Keypair::from_seed(&[seed; 32])
    }

    struct EntrySpec {
        kernel_id: &'static str,
        passport: Keypair,
        transport: EndpointId,
        endorsed_over: EndpointId,
        revocation_signers: Vec<RevocationSignerEntry>,
        removed: bool,
    }

    impl EntrySpec {
        fn admitted(kernel_id: &'static str, passport_seed: u8, transport_seed: u8) -> Self {
            let transport = endpoint_from_seed(transport_seed);
            Self {
                kernel_id,
                passport: passport_from_seed(passport_seed),
                transport,
                endorsed_over: transport,
                revocation_signers: Vec::new(),
                removed: false,
            }
        }

        /// Attach a well-formed revocation-signer binding: the entry's own
        /// passport endorses `oracle_key` under the revocation-signer domain tag.
        fn with_signer(mut self, signer_id: &'static str, oracle_key: &PublicKey) -> Self {
            let oracle_endorsement = self.passport.sign(&revocation_signer_endorsement_preimage(
                self.kernel_id,
                signer_id,
                oracle_key,
            ));
            self.revocation_signers.push(RevocationSignerEntry {
                signer_id: signer_id.to_string(),
                oracle_public_key: oracle_key.clone(),
                oracle_endorsement,
            });
            self
        }

        /// Attach a fully-formed (possibly hostile) revocation-signer entry.
        fn with_raw_signer(mut self, signer: RevocationSignerEntry) -> Self {
            self.revocation_signers.push(signer);
            self
        }
    }

    fn build_entry(spec: &EntrySpec) -> TransportDirectoryEntry {
        let endorsement = spec.passport.sign(&transport_endorsement_preimage(
            spec.kernel_id,
            &spec.endorsed_over,
        ));
        TransportDirectoryEntry {
            kernel_id: spec.kernel_id.to_string(),
            passport_public_key: spec.passport.public_key(),
            transport_endpoint_id: spec.transport,
            passport_endorsement: endorsement,
            revocation_signers: spec.revocation_signers.clone(),
            removed: spec.removed,
        }
    }

    /// Build a fully-signed valid bundle from the given entries, returning the
    /// bundle and the trust it verifies under.
    fn signed_bundle(
        entries: &[EntrySpec],
    ) -> (
        TransportDirectoryBundleDocument,
        TransportDirectoryBundleTrust,
    ) {
        let issuer_keypair = passport_from_seed(200);
        let directory = TransportDirectoryDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            local_kernel_id: "did:chio:local".to_string(),
            peers: entries.iter().map(build_entry).collect(),
            treaties: Vec::new(),
        };
        let directory_sha256 = canonical_sha256(&directory).unwrap();
        let body = TransportDirectoryBundleBody {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            issuer: ISSUER.to_string(),
            key_id: KEY_ID.to_string(),
            directory_sha256,
            version: 5,
            previous_version_sha256: Some("prev-bundle-hash".to_string()),
            issued_at_unix_ms: NOW - 1_000,
            expires_at_unix_ms: NOW + 1_000,
        };
        let (signature, _) = issuer_keypair.sign_canonical(&body).unwrap();
        let bundle = TransportDirectoryBundleDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            body,
            directory,
            signature,
        };
        let trust = TransportDirectoryBundleTrust {
            issuers: vec![TrustedTransportDirectoryIssuer {
                issuer: ISSUER.to_string(),
                key_id: KEY_ID.to_string(),
                public_key: issuer_keypair.public_key(),
            }],
            version_floor: 4,
            expected_previous_version_sha256: Some("prev-bundle-hash".to_string()),
            now_unix_ms: NOW,
        };
        (bundle, trust)
    }

    /// Build a fully-signed bundle at an explicit `version` chaining onto
    /// `previous_version_sha256`. Mirrors [`signed_bundle`] but exposes the
    /// version + predecessor so a rotation CHAIN (version N then N+1) can be
    /// constructed and verified end-to-end.
    fn rotation_bundle(
        entries: &[EntrySpec],
        version: u64,
        previous_version_sha256: Option<String>,
    ) -> TransportDirectoryBundleDocument {
        let issuer_keypair = passport_from_seed(200);
        let directory = TransportDirectoryDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            local_kernel_id: "did:chio:local".to_string(),
            peers: entries.iter().map(build_entry).collect(),
            treaties: Vec::new(),
        };
        let directory_sha256 = canonical_sha256(&directory).unwrap();
        let body = TransportDirectoryBundleBody {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            issuer: ISSUER.to_string(),
            key_id: KEY_ID.to_string(),
            directory_sha256,
            version,
            previous_version_sha256,
            issued_at_unix_ms: NOW - 1_000,
            expires_at_unix_ms: NOW + 1_000,
        };
        let (signature, _) = issuer_keypair.sign_canonical(&body).unwrap();
        TransportDirectoryBundleDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            body,
            directory,
            signature,
        }
    }

    /// Trust inputs pinning the same issuer [`rotation_bundle`] signs with, at an
    /// explicit rollback floor and expected predecessor hash.
    fn rotation_trust(
        version_floor: u64,
        expected_previous_version_sha256: Option<String>,
    ) -> TransportDirectoryBundleTrust {
        TransportDirectoryBundleTrust {
            issuers: vec![TrustedTransportDirectoryIssuer {
                issuer: ISSUER.to_string(),
                key_id: KEY_ID.to_string(),
                public_key: passport_from_seed(200).public_key(),
            }],
            version_floor,
            expected_previous_version_sha256,
            now_unix_ms: NOW,
        }
    }

    #[test]
    fn out_of_window_bundle_bumps_identity_verify_failure_and_is_still_rejected() {
        // Observe-only proof: a bundle presented outside its validity window is
        // still rejected fail-closed and the failure is counted and logged, so a
        // tampered or out-of-window directory bundle is distinguishable from a
        // healthy load in the telemetry. The returned Err is unchanged.
        let alice = EntrySpec::admitted("did:chio:alice", 1, 10);
        let (mut bundle, trust) = signed_bundle(&[alice]);
        // Push the window start past `now` so the validity check fails closed.
        bundle.body.issued_at_unix_ms = NOW + 10_000;

        let before = crate::metrics::verify_failures_total(
            crate::metrics::SEAM_IDENTITY,
            "outside-validity-window",
        );
        let error = bundle
            .verify_bundle(&trust)
            .expect_err("an out-of-window bundle must fail closed");
        assert_eq!(error, IdentityError::OutsideValidityWindow);
        assert_eq!(error.code(), "outside-validity-window");
        assert!(
            crate::metrics::verify_failures_total(
                crate::metrics::SEAM_IDENTITY,
                "outside-validity-window"
            ) > before,
            "the identity verify failure must be counted (observe-only)"
        );
    }

    #[test]
    fn valid_bundle_verifies_and_resolves_endpoints() {
        let alice = EntrySpec::admitted("did:chio:alice", 1, 10);
        let bob = EntrySpec::admitted("did:chio:bob", 2, 11);
        let alice_ep = alice.transport;
        let bob_ep = bob.transport;
        let (bundle, trust) = signed_bundle(&[alice, bob]);

        let directory = bundle.verify_bundle(&trust).expect("valid bundle verifies");
        assert_eq!(directory.version(), 5);
        assert_eq!(directory.len(), 2);
        assert_eq!(directory.authorize(&alice_ep), Some("did:chio:alice"));
        assert_eq!(directory.authorize(&bob_ep), Some("did:chio:bob"));
        // Unknown endpoint does not resolve.
        assert_eq!(directory.authorize(&endpoint_from_seed(99)), None);
        // body_sha256 chains a successor bundle.
        assert_eq!(directory.body_sha256(), canonical_sha256(&bundle).unwrap());
    }

    #[test]
    fn removed_entry_does_not_resolve() {
        let mut ghost = EntrySpec::admitted("did:chio:ghost", 3, 12);
        ghost.removed = true;
        let ghost_ep = ghost.transport;
        // Pair with a live entry so the directory is not empty.
        let live = EntrySpec::admitted("did:chio:live", 4, 13);
        let live_ep = live.transport;
        let (bundle, trust) = signed_bundle(&[ghost, live]);

        let directory = bundle.verify_bundle(&trust).expect("verifies");
        assert_eq!(
            directory.authorize(&ghost_ep),
            None,
            "removed must not resolve"
        );
        assert_eq!(directory.authorize(&live_ep), Some("did:chio:live"));
    }

    #[test]
    fn resolve_transport_endpoint_is_the_reverse_of_authorize_and_fails_closed() {
        let mut ghost = EntrySpec::admitted("did:chio:ghost", 3, 12);
        ghost.removed = true;
        let ghost_ep = ghost.transport;
        let live = EntrySpec::admitted("did:chio:live", 4, 13);
        let live_ep = live.transport;
        let (bundle, trust) = signed_bundle(&[ghost, live]);

        let directory = bundle.verify_bundle(&trust).expect("verifies");
        // A live kernel resolves to exactly the endpoint `authorize` maps back.
        assert_eq!(
            directory.resolve_transport_endpoint("did:chio:live"),
            Some(live_ep),
            "a live kernel must resolve to its bound transport endpoint"
        );
        assert_eq!(directory.authorize(&live_ep), Some("did:chio:live"));
        // A removed kernel resolves to None (fail-closed): the tick never dials it.
        assert_eq!(
            directory.resolve_transport_endpoint("did:chio:ghost"),
            None,
            "a removed kernel must not resolve to an address"
        );
        assert_eq!(directory.authorize(&ghost_ep), None);
        // An unknown kernel resolves to None.
        assert_eq!(
            directory.resolve_transport_endpoint("did:chio:nobody"),
            None
        );
    }

    #[test]
    fn resolve_passport_key_is_directory_bound_and_fails_closed() {
        // The bilateral co-sign lane sources Org B's DSSE-verification key from
        // this accessor, so it must return the issuer-signed passport of an
        // admitted peer and fail closed (None) for a removed tombstone or an
        // unknown kernel. Binding verification to this snapshot is what keeps a
        // rotated-away / revoked passport from being accepted.
        let alice = EntrySpec::admitted("did:chio:alice", 1, 10);
        let alice_key = alice.passport.public_key();
        let mut ghost = EntrySpec::admitted("did:chio:ghost", 3, 12);
        ghost.removed = true;
        let (bundle, trust) = signed_bundle(&[alice, ghost]);

        let directory = bundle.verify_bundle(&trust).expect("verifies");
        assert_eq!(
            directory.resolve_passport_key("did:chio:alice"),
            Some(&alice_key),
            "an admitted peer resolves to its issuer-signed passport key"
        );
        assert_eq!(
            directory.resolve_passport_key("did:chio:ghost"),
            None,
            "a removed operator has no directory-bound passport key (fail-closed)"
        );
        assert_eq!(directory.resolve_passport_key("did:chio:nobody"), None);
    }

    #[test]
    fn eviction_bundle_verifies_when_removed_entry_transport_endorsement_is_invalid() {
        // Eviction path: a removed operator carries an INVALID transport endorsement
        // (its passport signed over a DIFFERENT endpoint than the entry's transport
        // id). Because a tombstone skips the transport-endorsement check, the eviction
        // bundle still verifies - otherwise a peer whose transport endorsement is
        // missing/bad could never be evicted and the stale directory would stay
        // active. The removed endpoint resolves to None (fail-closed) regardless.
        let mut ghost = EntrySpec::admitted("did:chio:ghost", 3, 12);
        ghost.endorsed_over = endpoint_from_seed(99); // endorsement covers the wrong endpoint
        assert_ne!(ghost.endorsed_over, ghost.transport);
        let ghost_ep = ghost.transport;
        ghost.removed = true;
        let live = EntrySpec::admitted("did:chio:live", 4, 13);
        let live_ep = live.transport;
        let (bundle, trust) = signed_bundle(&[ghost, live]);

        let directory = bundle
            .verify_bundle(&trust)
            .expect("a removed entry's invalid transport endorsement must not fail the bundle");
        assert_eq!(
            directory.authorize(&ghost_ep),
            None,
            "the evicted endpoint must not resolve"
        );
        assert_eq!(directory.authorize(&live_ep), Some("did:chio:live"));

        // Control: the SAME invalid transport endorsement on a NON-removed entry DOES
        // fail closed, proving the endorsement is genuinely invalid (fail-closed for
        // live entries is preserved).
        let mut live_bad = EntrySpec::admitted("did:chio:ghost", 3, 12);
        live_bad.endorsed_over = endpoint_from_seed(99);
        let (control_bundle, control_trust) = signed_bundle(&[live_bad]);
        assert!(matches!(
            control_bundle.verify_bundle(&control_trust),
            Err(IdentityError::EndorsementInvalid(_))
        ));
    }

    #[test]
    fn tampered_directory_fails_body_hash_pin() {
        let (mut bundle, trust) = signed_bundle(&[EntrySpec::admitted("did:chio:a", 1, 10)]);
        // Mutate the directory after the hash was pinned in the body.
        bundle.directory.peers[0].kernel_id = "did:chio:evil".to_string();
        assert!(matches!(
            bundle.verify_bundle(&trust),
            Err(IdentityError::BodyHashMismatch { .. })
        ));
    }

    #[test]
    fn wrong_issuer_signature_is_rejected() {
        let (mut bundle, trust) = signed_bundle(&[EntrySpec::admitted("did:chio:a", 1, 10)]);
        // Re-sign the body with a different key (a forged issuer).
        let forger = passport_from_seed(201);
        let (forged, _) = forger.sign_canonical(&bundle.body).unwrap();
        bundle.signature = forged;
        assert_eq!(
            bundle.verify_bundle(&trust).unwrap_err(),
            IdentityError::SignatureInvalid
        );
    }

    #[test]
    fn unknown_issuer_is_rejected() {
        let (bundle, mut trust) = signed_bundle(&[EntrySpec::admitted("did:chio:a", 1, 10)]);
        // Pin a different issuer than the one that signed.
        trust.issuers[0].key_id = "some-other-key".to_string();
        assert!(matches!(
            bundle.verify_bundle(&trust),
            Err(IdentityError::UnknownIssuer(_))
        ));
    }

    #[test]
    fn out_of_window_bundle_is_rejected() {
        let (bundle, mut trust) = signed_bundle(&[EntrySpec::admitted("did:chio:a", 1, 10)]);
        // At/after expiry (window is half-open `[issued, expires)`).
        trust.now_unix_ms = bundle.body.expires_at_unix_ms;
        assert_eq!(
            bundle.verify_bundle(&trust).unwrap_err(),
            IdentityError::OutsideValidityWindow
        );
    }

    #[test]
    fn rolled_back_version_is_rejected() {
        let (bundle, mut trust) = signed_bundle(&[EntrySpec::admitted("did:chio:a", 1, 10)]);
        // Floor at or above the bundle version rejects (no equal, no lower).
        trust.version_floor = bundle.body.version;
        assert_eq!(
            bundle.verify_bundle(&trust).unwrap_err(),
            IdentityError::Rollback {
                version: bundle.body.version,
                floor: bundle.body.version,
            }
        );
    }

    #[test]
    fn wrong_previous_version_hash_is_rejected() {
        let (bundle, mut trust) = signed_bundle(&[EntrySpec::admitted("did:chio:a", 1, 10)]);
        // The candidate does not chain onto the expected predecessor.
        trust.expected_previous_version_sha256 = Some("a-different-predecessor".to_string());
        assert_eq!(
            bundle.verify_bundle(&trust).unwrap_err(),
            IdentityError::PreviousVersionMismatch
        );
    }

    #[test]
    fn wrong_passport_endorsement_is_rejected() {
        // Endorse a DIFFERENT transport id than the one carried by the entry.
        let mut spec = EntrySpec::admitted("did:chio:a", 1, 10);
        spec.endorsed_over = endorse_mismatch();
        // Sanity: the endorsed-over id differs from the transport id.
        assert_ne!(spec.endorsed_over, spec.transport);
        let (bundle, trust) = signed_bundle(&[spec]);
        assert!(matches!(
            bundle.verify_bundle(&trust),
            Err(IdentityError::EndorsementInvalid(_))
        ));
    }

    fn endorse_mismatch() -> EndpointId {
        endpoint_from_seed(77)
    }

    #[test]
    fn missing_passport_endorsement_is_rejected() {
        // A garbage (wrong-key) endorsement stands in for "missing": it fails
        // the passport-over-transport check just the same, fail-closed.
        let (mut bundle, trust) = signed_bundle(&[EntrySpec::admitted("did:chio:a", 1, 10)]);
        let wrong_signer = passport_from_seed(150);
        bundle.directory.peers[0].passport_endorsement =
            wrong_signer.sign(&transport_endorsement_preimage(
                &bundle.directory.peers[0].kernel_id,
                &bundle.directory.peers[0].transport_endpoint_id,
            ));
        // Re-pin the directory hash + re-sign the body so ONLY the endorsement
        // check can fire (isolating check 6 from checks 4 and 5).
        repin_and_resign(&mut bundle);
        assert!(matches!(
            bundle.verify_bundle(&trust),
            Err(IdentityError::EndorsementInvalid(_))
        ));
    }

    fn repin_and_resign(bundle: &mut TransportDirectoryBundleDocument) {
        let issuer_keypair = passport_from_seed(200);
        bundle.body.directory_sha256 = canonical_sha256(&bundle.directory).unwrap();
        let (signature, _) = issuer_keypair.sign_canonical(&bundle.body).unwrap();
        bundle.signature = signature;
    }

    #[test]
    fn empty_directory_is_rejected() {
        let (bundle, trust) = signed_bundle(&[]);
        assert_eq!(
            bundle.verify_bundle(&trust).unwrap_err(),
            IdentityError::EmptyDirectory
        );
    }

    #[test]
    fn transport_key_rotation_end_to_end() {
        // Option B's premise: the passport is the long-term operator identity,
        // and the ed25519 transport EndpointId rotates INDEPENDENTLY of it. Alice
        // keeps the same passport (seed 1) across the rotation and swaps her
        // transport endpoint from E_old to E_new.
        //
        // MODELING NOTE: `verify_bundle`'s per-kernel-id dedup rejects two entries
        // sharing a kernel_id as `Duplicate`, so a rotation for one operator
        // cannot be expressed as (old entry removed=true) + (new entry). Rotation
        // is therefore an in-place REBIND of alice's single entry onto E_new; the
        // rotated-away E_old then simply drops out of the directory and resolves
        // to `None` (fail-closed). The admission gate treats an unbound endpoint
        // and a removed tombstone identically (both 403), so the security
        // property is the same either way.
        let e_old = endpoint_from_seed(10);
        let e_new = endpoint_from_seed(20);
        assert_ne!(e_old, e_new, "the rotation must move to a fresh endpoint");

        // Version N: alice admitted at E_old, passport-endorsed over E_old.
        let bundle_n = rotation_bundle(&[EntrySpec::admitted("did:chio:alice", 1, 10)], 5, None);
        let dir_n = bundle_n
            .verify_bundle(&rotation_trust(4, None))
            .expect("version N verifies");
        assert_eq!(dir_n.authorize(&e_old), Some("did:chio:alice"));
        assert_eq!(dir_n.authorize(&e_new), None, "E_new is not admitted at N");
        let hash_n = dir_n.body_sha256().to_string();

        // Version N+1: alice rebinds to E_new (SAME passport seed 1, freshly
        // endorsed over E_new), chaining onto N via previous_version_sha256.
        let bundle_np1 = rotation_bundle(
            &[EntrySpec::admitted("did:chio:alice", 1, 20)],
            6,
            Some(hash_n.clone()),
        );
        let dir_np1 = bundle_np1
            .verify_bundle(&rotation_trust(5, Some(hash_n.clone())))
            .expect("version N+1 chains onto N and verifies");

        // THE LOAD-BEARING ROTATION PROPERTY: E_new now authorizes to alice's
        // kernel_id, and the rotated-away E_old no longer authorizes at all.
        assert_eq!(
            dir_np1.authorize(&e_new),
            Some("did:chio:alice"),
            "rotated-in E_new authorizes to alice"
        );
        assert_eq!(
            dir_np1.authorize(&e_old),
            None,
            "rotated-away E_old no longer authorizes (fail-closed)"
        );
        assert_eq!(dir_np1.version(), 6);

        // Fail-closed (a): a version N+1 that does NOT chain onto the real N is
        // rejected. An attacker cannot slot in a successor pinned to a bogus
        // predecessor, even with a correct signature and version.
        let bad_chain = rotation_bundle(
            &[EntrySpec::admitted("did:chio:alice", 1, 20)],
            6,
            Some("not-the-real-predecessor".to_string()),
        );
        assert_eq!(
            bad_chain
                .verify_bundle(&rotation_trust(5, Some(hash_n.clone())))
                .unwrap_err(),
            IdentityError::PreviousVersionMismatch
        );

        // Fail-closed (b): after adopting N+1 the floor advances to 6, so
        // replaying the older version-5 bundle N is a downgrade the floor rejects.
        assert_eq!(
            bundle_n
                .verify_bundle(&rotation_trust(6, None))
                .unwrap_err(),
            IdentityError::Rollback {
                version: 5,
                floor: 6,
            }
        );
    }

    #[test]
    fn rotation_to_unendorsed_new_endpoint_is_rejected() {
        // A rotation is only genuine if the passport actually endorses the NEW
        // transport key. Two ways it can be forged, both fail-closed:
        let e_new = endpoint_from_seed(20);

        // (a) alice presents E_new but the endorsement covers E_old (it does not
        // cover the carried transport id): rejected. This keeps a rotated-in
        // transport key from floating free of the long-term passport.
        let mut endorse_stale = EntrySpec::admitted("did:chio:alice", 1, 20);
        endorse_stale.endorsed_over = endpoint_from_seed(10);
        assert_ne!(endorse_stale.transport, endorse_stale.endorsed_over);
        let stale = rotation_bundle(&[endorse_stale], 6, Some("prev".to_string()));
        assert!(matches!(
            stale.verify_bundle(&rotation_trust(5, Some("prev".to_string()))),
            Err(IdentityError::EndorsementInvalid(_))
        ));

        // (b) E_new IS endorsed, but by the WRONG passport (an attacker key, not
        // alice's long-term passport): rejected. Re-pin + re-sign so only the
        // endorsement check can fire.
        let mut wrong_passport = rotation_bundle(
            &[EntrySpec::admitted("did:chio:alice", 1, 20)],
            6,
            Some("prev".to_string()),
        );
        let attacker = passport_from_seed(151);
        wrong_passport.directory.peers[0].passport_endorsement =
            attacker.sign(&transport_endorsement_preimage("did:chio:alice", &e_new));
        repin_and_resign(&mut wrong_passport);
        assert!(matches!(
            wrong_passport.verify_bundle(&rotation_trust(5, Some("prev".to_string()))),
            Err(IdentityError::EndorsementInvalid(_))
        ));
    }

    // -- Revocation signer binding (derived projection) + domain separation --

    fn oracle_key(seed: u8) -> PublicKey {
        passport_from_seed(seed).public_key()
    }

    #[test]
    fn revocation_signer_binding_verifies_and_projects() {
        use chio_revocation_oracle::EpochRootVerifier;

        let opk = oracle_key(60);
        let alice = EntrySpec::admitted("did:chio:alice", 1, 10).with_signer("oracle-a", &opk);
        let alice_ep = alice.transport;
        let (bundle, trust) = signed_bundle(&[alice]);

        let directory = bundle.verify_bundle(&trust).expect("valid bundle verifies");
        let binding = directory
            .resolve_signer("oracle-a")
            .expect("oracle-a is projected into the derived signer directory");
        // The origin pin is structural: the signer's endpoint IS the entry's.
        assert_eq!(binding.endpoint, alice_ep);
        assert_eq!(binding.verifier.signer_id(), "oracle-a");
        assert_eq!(binding.verifier.public_key(), &opk);
        assert_eq!(directory.signer_directory().len(), 1);
        assert!(directory.resolve_signer("oracle-z").is_none());
    }

    #[test]
    fn signerless_bundle_yields_empty_signer_directory() {
        // A v1-style entry (no revocation_signers) verifies and admits no signer,
        // fail-closed: a deployment that has not provisioned oracle bindings simply
        // has an empty signer directory.
        let (bundle, trust) = signed_bundle(&[EntrySpec::admitted("did:chio:a", 1, 10)]);
        let directory = bundle.verify_bundle(&trust).expect("verifies");
        assert!(directory.signer_directory().is_empty());
        assert!(directory.resolve_signer("anything").is_none());
    }

    #[test]
    fn revocation_signers_field_defaults_when_absent_on_the_wire() {
        // Back-compat: a wire entry that predates the field (no `revocationSigners`
        // key) deserializes with an empty vec via `#[serde(default)]`.
        let entry = build_entry(&EntrySpec::admitted("did:chio:a", 1, 10));
        let mut value = serde_json::to_value(&entry).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("revocationSigners")
            .expect("serialized entry carries the field");
        let decoded: TransportDirectoryEntry = serde_json::from_value(value).unwrap();
        assert!(decoded.revocation_signers.is_empty());
        assert_eq!(decoded, entry);
    }

    #[test]
    fn tampered_oracle_public_key_is_rejected() {
        let opk = oracle_key(60);
        let (mut bundle, trust) = signed_bundle(&[
            EntrySpec::admitted("did:chio:alice", 1, 10).with_signer("oracle-a", &opk)
        ]);
        // Swap the oracle key: the endorsement (over the ORIGINAL key) no longer
        // matches the preimage over the tampered key. Re-pin + re-sign so ONLY the
        // oracle endorsement check can fire.
        let tampered = oracle_key(61);
        assert_ne!(opk, tampered);
        bundle.directory.peers[0].revocation_signers[0].oracle_public_key = tampered;
        repin_and_resign(&mut bundle);
        assert!(matches!(
            bundle.verify_bundle(&trust),
            Err(IdentityError::OracleEndorsementInvalid { .. })
        ));
    }

    #[test]
    fn non_ed25519_oracle_key_is_rejected_even_with_valid_endorsement() {
        // A validly-endorsed but non-Ed25519 (P-256) oracle key must be rejected at
        // bundle-verify time: the lane-b Ed25519RootVerifier would otherwise wrap it
        // and silently fail every epoch-root verify. The passport endorses the exact
        // P-256 key (so the endorsement check passes), isolating the algorithm gate.
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04; // uncompressed SEC1 marker; curve-point validity is deferred.
        let p256 = PublicKey::from_p256_sec1(&sec1).expect("well-formed P-256 SEC1 point");
        assert_eq!(p256.algorithm(), SigningAlgorithm::P256);

        let alice = EntrySpec::admitted("did:chio:alice", 1, 10).with_signer("oracle-a", &p256);
        let (bundle, trust) = signed_bundle(&[alice]);
        let error = bundle
            .verify_bundle(&trust)
            .expect_err("a non-Ed25519 oracle key must be rejected fail-closed");
        assert!(
            matches!(
                error,
                IdentityError::NonEd25519OracleKey {
                    algorithm: SigningAlgorithm::P256,
                    ..
                }
            ),
            "unexpected error: {error:?}"
        );
        assert_eq!(error.code(), "non-ed25519-oracle-key");
    }

    #[test]
    fn wrong_passport_oracle_endorsement_is_rejected() {
        let opk = oracle_key(60);
        let (mut bundle, trust) = signed_bundle(&[
            EntrySpec::admitted("did:chio:alice", 1, 10).with_signer("oracle-a", &opk)
        ]);
        // Re-endorse the oracle key with an ATTACKER passport, not alice's.
        let attacker = passport_from_seed(151);
        bundle.directory.peers[0].revocation_signers[0].oracle_endorsement = attacker.sign(
            &revocation_signer_endorsement_preimage("did:chio:alice", "oracle-a", &opk),
        );
        repin_and_resign(&mut bundle);
        assert!(matches!(
            bundle.verify_bundle(&trust),
            Err(IdentityError::OracleEndorsementInvalid { .. })
        ));
    }

    #[test]
    fn duplicate_revocation_signer_id_is_rejected() {
        let opk = oracle_key(60);
        // Two DIFFERENT operators both declaring signer "oracle-a"; each endorses
        // with its own passport over its own kernel_id, so both endorsements are
        // individually valid, but the derived projection rejects the collision.
        let a = EntrySpec::admitted("did:chio:alice", 1, 10).with_signer("oracle-a", &opk);
        let b = EntrySpec::admitted("did:chio:bob", 2, 11).with_signer("oracle-a", &opk);
        let (bundle, trust) = signed_bundle(&[a, b]);
        assert!(matches!(
            bundle.verify_bundle(&trust),
            Err(IdentityError::Duplicate(_))
        ));
    }

    #[test]
    fn removed_entry_suppresses_its_revocation_signer() {
        let opk = oracle_key(60);
        // A removed operator carries a VALID oracle endorsement, yet its signer is
        // suppressed from the projection (fail-closed: eviction revokes the oracle).
        let mut ghost = EntrySpec::admitted("did:chio:ghost", 3, 12).with_signer("oracle-a", &opk);
        ghost.removed = true;
        let live = EntrySpec::admitted("did:chio:live", 4, 13);
        let (bundle, trust) = signed_bundle(&[ghost, live]);
        let directory = bundle.verify_bundle(&trust).expect("verifies");
        assert!(
            directory.resolve_signer("oracle-a").is_none(),
            "a removed operator's oracle signer must be suppressed"
        );
        assert!(directory.signer_directory().is_empty());
    }

    #[test]
    fn removed_entry_with_malformed_oracle_endorsement_does_not_fail_the_bundle() {
        // Eviction path: a removed operator carries a MALFORMED oracle endorsement
        // (its passport signed the WRONG preimage). Because eviction suppresses the
        // signer BEFORE the oracle material is validated, the bad endorsement must
        // not fail the whole bundle - the operator is being evicted and its signer
        // binding is dropped regardless (not over-strict on the eviction path).
        let opk = oracle_key(60);
        // A structurally malformed endorsement: signed over a DIFFERENT signer_id
        // than the entry declares, so it would fail the oracle-endorsement check.
        let bad_signer = RevocationSignerEntry {
            signer_id: "oracle-a".to_string(),
            oracle_public_key: opk.clone(),
            oracle_endorsement: passport_from_seed(3).sign(
                &revocation_signer_endorsement_preimage("did:chio:ghost", "not-oracle-a", &opk),
            ),
        };
        let mut ghost =
            EntrySpec::admitted("did:chio:ghost", 3, 12).with_raw_signer(bad_signer.clone());
        ghost.removed = true;
        let live = EntrySpec::admitted("did:chio:live", 4, 13);
        let (bundle, trust) = signed_bundle(&[ghost, live]);

        let directory = bundle
            .verify_bundle(&trust)
            .expect("a removed entry's malformed oracle endorsement must not fail the bundle");
        assert!(
            directory.resolve_signer("oracle-a").is_none(),
            "the removed operator's signer stays suppressed"
        );
        assert!(directory.signer_directory().is_empty());

        // Control: the SAME malformed endorsement on a NON-removed entry DOES fail
        // closed, proving the endorsement is genuinely malformed (fail-closed for
        // live entries is preserved).
        let live_bad = EntrySpec::admitted("did:chio:ghost", 3, 12).with_raw_signer(bad_signer);
        let (control_bundle, control_trust) = signed_bundle(&[live_bad]);
        assert!(matches!(
            control_bundle.verify_bundle(&control_trust),
            Err(IdentityError::OracleEndorsementInvalid { .. })
        ));
    }

    #[test]
    fn transport_endorsement_is_not_replayable_as_oracle_endorsement() {
        // A signature the passport made as a TRANSPORT endorsement must be rejected
        // when presented as a revocation-signer (oracle) endorsement.
        let passport = passport_from_seed(1);
        let kernel = "did:chio:alice";
        let transport = endpoint_from_seed(10);
        let opk = oracle_key(60);
        let cross = passport.sign(&transport_endorsement_preimage(kernel, &transport));
        let replayed = RevocationSignerEntry {
            signer_id: "oracle-a".to_string(),
            oracle_public_key: opk,
            oracle_endorsement: cross,
        };
        let (bundle, trust) =
            signed_bundle(&[EntrySpec::admitted(kernel, 1, 10).with_raw_signer(replayed)]);
        assert!(matches!(
            bundle.verify_bundle(&trust),
            Err(IdentityError::OracleEndorsementInvalid { .. })
        ));
    }

    #[test]
    fn oracle_endorsement_is_not_replayable_as_transport_endorsement() {
        // The mirror: a signature made as an ORACLE endorsement must be rejected
        // when presented as the transport endorsement.
        let passport = passport_from_seed(1);
        let kernel = "did:chio:alice";
        let opk = oracle_key(60);
        let cross = passport.sign(&revocation_signer_endorsement_preimage(
            kernel, "oracle-a", &opk,
        ));
        let (mut bundle, trust) = signed_bundle(&[EntrySpec::admitted(kernel, 1, 10)]);
        bundle.directory.peers[0].passport_endorsement = cross;
        repin_and_resign(&mut bundle);
        assert!(matches!(
            bundle.verify_bundle(&trust),
            Err(IdentityError::EndorsementInvalid(_))
        ));
    }

    #[test]
    fn directory_document_without_treaties_field_deserializes_back_compat() {
        // A pre-existing directory document (no `treaties` key) still deserializes:
        // the field is additive (`#[serde(default)]`), so an older bundle stays
        // wire-compatible and simply admits nobody to any treaty (fail-closed).
        let json = format!(
            r#"{{"schema":"{schema}","localKernelId":"did:chio:local","peers":[]}}"#,
            schema = TRANSPORT_DIRECTORY_BUNDLE_SCHEMA
        );
        let doc: TransportDirectoryDocument =
            serde_json::from_str(&json).expect("a treaty-less directory document deserializes");
        assert!(
            doc.treaties.is_empty(),
            "an omitted treaties field defaults to empty"
        );
    }

    #[test]
    fn treaty_party_set_is_indexed_and_membership_is_fail_closed() {
        let (mut bundle, trust) = signed_bundle(&[
            EntrySpec::admitted("did:chio:alice", 1, 10),
            EntrySpec::admitted("did:chio:bob", 2, 11),
        ]);
        bundle.directory.treaties = vec![TransportTreatyEntry {
            treaty_id: "treaty-x".to_string(),
            party_kernel_ids: vec!["did:chio:alice".to_string(), "did:chio:bob".to_string()],
        }];
        repin_and_resign(&mut bundle);

        let directory = bundle
            .verify_bundle(&trust)
            .expect("a bundle carrying a treaty party set verifies");
        // Parties resolve; a non-party and an unknown treaty both deny (fail-closed).
        assert!(directory.is_treaty_party("treaty-x", "did:chio:alice"));
        assert!(directory.is_treaty_party("treaty-x", "did:chio:bob"));
        assert!(!directory.is_treaty_party("treaty-x", "did:chio:carol"));
        assert!(!directory.is_treaty_party("treaty-unknown", "did:chio:alice"));
    }

    #[test]
    fn empty_treaty_party_set_is_rejected() {
        let (mut bundle, trust) = signed_bundle(&[EntrySpec::admitted("did:chio:alice", 1, 10)]);
        bundle.directory.treaties = vec![TransportTreatyEntry {
            treaty_id: "treaty-x".to_string(),
            party_kernel_ids: Vec::new(),
        }];
        repin_and_resign(&mut bundle);
        assert!(matches!(
            bundle.verify_bundle(&trust),
            Err(IdentityError::MalformedEntry(_))
        ));
    }

    #[test]
    fn duplicate_treaty_party_is_rejected() {
        let (mut bundle, trust) = signed_bundle(&[EntrySpec::admitted("did:chio:alice", 1, 10)]);
        bundle.directory.treaties = vec![TransportTreatyEntry {
            treaty_id: "treaty-x".to_string(),
            party_kernel_ids: vec!["did:chio:alice".to_string(), "did:chio:alice".to_string()],
        }];
        repin_and_resign(&mut bundle);
        assert!(matches!(
            bundle.verify_bundle(&trust),
            Err(IdentityError::Duplicate(_))
        ));
    }

    #[test]
    fn tampered_treaty_party_set_fails_body_hash_pin() {
        // The party set is pinned by the signed body: mutating it after the hash is
        // pinned fails the body-hash check, so a treaty membership can never be
        // forged onto an otherwise-valid bundle.
        let (mut bundle, trust) = signed_bundle(&[EntrySpec::admitted("did:chio:alice", 1, 10)]);
        bundle.directory.treaties = vec![TransportTreatyEntry {
            treaty_id: "treaty-x".to_string(),
            party_kernel_ids: vec!["did:chio:alice".to_string()],
        }];
        repin_and_resign(&mut bundle);
        // Inject an extra party WITHOUT re-pinning/re-signing.
        bundle.directory.treaties[0]
            .party_kernel_ids
            .push("did:chio:evil".to_string());
        assert!(matches!(
            bundle.verify_bundle(&trust),
            Err(IdentityError::BodyHashMismatch { .. })
        ));
    }
}
