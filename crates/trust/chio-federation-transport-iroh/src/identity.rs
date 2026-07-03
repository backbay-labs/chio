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
//!
//! TODO(iroh-transport): when `chio-pheromone-relay` grows a transport-key
//! directory shape (an issuer-signed `EndpointId` binding + passport
//! endorsement), re-home these types onto it so there is exactly one directory
//! verifier. Until then this mirror MUST NOT weaken any of the five checks.

use std::collections::HashMap;
use std::collections::HashSet;

use chio_core_types::canonical_json_bytes;
use chio_core_types::sha256_hex;
use chio_core_types::PublicKey;
use chio_core_types::Signature;
use iroh::EndpointId;
use serde::Deserialize;
use serde::Serialize;

/// Schema pin for the adapter's issuer-signed transport-directory bundle.
pub const TRANSPORT_DIRECTORY_BUNDLE_SCHEMA: &str =
    "chio.federation.transport.iroh.peer-directory-bundle.v1";

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
    /// Passport signature over `transport_endpoint_id.as_bytes()`: the
    /// passport-over-transport endorsement that keeps the transport key from
    /// floating free of the long-term identity.
    pub passport_endorsement: Signature,
    /// Issuer-signed tombstone. A removed entry never resolves (fail-closed),
    /// mirroring `PeerDirectory::peer` rejecting `removed_peer_ids`.
    #[serde(default)]
    pub removed: bool,
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

/// A directory that passed every check. The gate is built ONLY from this type,
/// so it can never resolve against an unverified bundle (ADAPTER-SPEC section 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDirectory {
    by_endpoint: HashMap<EndpointId, (String, bool)>,
    version: u64,
    body_sha256: String,
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
    /// `PeerDirectoryBundleDocument::verify` plus the Option B endorsement):
    /// 1. schema pins,
    /// 2. rollback gate: `version` strictly above the floor AND
    ///    `previous_version_sha256` chains onto the expected predecessor,
    /// 3. validity window `now in [issued_at, expires_at)`,
    /// 4. body-hash pin: recomputed directory hash equals the signed hash,
    /// 5. pinned-issuer signature over the body,
    /// 6. per-entry passport-over-transport endorsement.
    pub fn verify_bundle(
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

        // (6) per-entry structure + passport-over-transport endorsement.
        let mut by_endpoint: HashMap<EndpointId, (String, bool)> = HashMap::new();
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
            // the passport (any algorithm) must sign the 32 transport-id bytes.
            let endorsed = entry.passport_public_key.verify(
                entry.transport_endpoint_id.as_bytes(),
                &entry.passport_endorsement,
            );
            if !endorsed {
                return Err(IdentityError::EndorsementInvalid(entry.kernel_id.clone()));
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

        let body_sha256 = canonical_sha256(self)?;
        Ok(VerifiedDirectory {
            by_endpoint,
            version: self.body.version,
            body_sha256,
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
                removed: false,
            }
        }
    }

    fn build_entry(spec: &EntrySpec) -> TransportDirectoryEntry {
        let endorsement = spec.passport.sign(spec.endorsed_over.as_bytes());
        TransportDirectoryEntry {
            kernel_id: spec.kernel_id.to_string(),
            passport_public_key: spec.passport.public_key(),
            transport_endpoint_id: spec.transport,
            passport_endorsement: endorsement,
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
            bundle.verify_bundle(&trust),
            Err(IdentityError::SignatureInvalid)
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
            bundle.verify_bundle(&trust),
            Err(IdentityError::OutsideValidityWindow)
        );
    }

    #[test]
    fn rolled_back_version_is_rejected() {
        let (bundle, mut trust) = signed_bundle(&[EntrySpec::admitted("did:chio:a", 1, 10)]);
        // Floor at or above the bundle version rejects (no equal, no lower).
        trust.version_floor = bundle.body.version;
        assert_eq!(
            bundle.verify_bundle(&trust),
            Err(IdentityError::Rollback {
                version: bundle.body.version,
                floor: bundle.body.version,
            })
        );
    }

    #[test]
    fn wrong_previous_version_hash_is_rejected() {
        let (bundle, mut trust) = signed_bundle(&[EntrySpec::admitted("did:chio:a", 1, 10)]);
        // The candidate does not chain onto the expected predecessor.
        trust.expected_previous_version_sha256 = Some("a-different-predecessor".to_string());
        assert_eq!(
            bundle.verify_bundle(&trust),
            Err(IdentityError::PreviousVersionMismatch)
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
            wrong_signer.sign(bundle.directory.peers[0].transport_endpoint_id.as_bytes());
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
            bundle.verify_bundle(&trust),
            Err(IdentityError::EmptyDirectory)
        );
    }
}
