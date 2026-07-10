//! Accept-time admission gate (ADAPTER-SPEC sections 3.2 and 5).
//!
//! The fail-closed connection gate shared by every lane. It runs at
//! `after_handshake`, once iroh has cryptographically authenticated the remote
//! `EndpointId`, and BEFORE any `ProtocolHandler::accept` runs. It resolves the
//! authenticated `EndpointId` through a load-time-verified
//! [`VerifiedDirectory`](crate::identity::VerifiedDirectory) and rejects (403)
//! any endpoint not bound to an admitted, non-removed `kernel_id`.
//!
//! This is a cheap DoS-rejection / defense-in-depth layer, NOT a replacement for
//! the per-frame batch verifier above it (ADR-0014 Drop-In Seam step 3): keep
//! both. On accept, the resolved `kernel_id` is exposed to the lane handler via
//! [`DirectoryGate::resolve`] so it can populate
//! `authenticated_sender_kernel_id`.
//!
//! Register once via `Endpoint::builder(..).hooks(gate)`; the hook applies to
//! both the connect and accept side.

use std::sync::Arc;

use arc_swap::ArcSwap;
use iroh::endpoint::AfterHandshakeOutcome;
use iroh::endpoint::Connection;
use iroh::endpoint::EndpointHooks;
use iroh::EndpointId;

use crate::identity::VerifiedDirectory;

/// QUIC/application close code sent when an endpoint is not admitted. HTTP 403
/// (Forbidden) semantics: authenticated, but not authorized.
pub const NOT_ADMITTED_ERROR_CODE: u32 = 403;

/// Close reason sent alongside [`NOT_ADMITTED_ERROR_CODE`].
pub const NOT_ADMITTED_REASON: &[u8] = b"not admitted";

/// Accept-time gate over an issuer-signed, load-time-verified directory.
///
/// Built ONLY from an `Arc<VerifiedDirectory>`, so it can never resolve against
/// an unverified bundle. The directory lives behind an [`ArcSwap`] so
/// `authorize`/`decide`/`resolve` read the CURRENT directory lock-free while a
/// single-writer [`swap`](Self::swap) publishes a freshly re-verified directory
/// (eviction, rotation, and expiry take effect without a restart).
/// Cloning is cheap (shares one `Arc<ArcSwap<..>>`), so every gate clone observes
/// the reloader's swaps immediately.
#[derive(Debug, Clone)]
pub struct DirectoryGate {
    directory: Arc<ArcSwap<VerifiedDirectory>>,
}

impl DirectoryGate {
    /// Build the gate from a load-time-verified directory.
    #[must_use]
    pub fn new(directory: Arc<VerifiedDirectory>) -> Self {
        Self {
            directory: Arc::new(ArcSwap::from(directory)),
        }
    }

    /// Atomically publish a freshly re-verified directory. Only the reloader
    /// calls this, and only with a `VerifiedDirectory` that passed `verify_bundle`
    /// (or `empty_deny_all`), so the gate can never resolve against an unverified
    /// or rolled-back bundle.
    pub fn swap(&self, next: Arc<VerifiedDirectory>) {
        self.directory.store(next);
    }

    /// The current verified directory (a cheap Arc clone via `load_full`).
    #[must_use]
    pub fn directory(&self) -> Arc<VerifiedDirectory> {
        self.directory.load_full()
    }

    /// The current directory's monotone version (for the reloader's rollback
    /// floor and unchanged fast path).
    #[must_use]
    pub fn current_version(&self) -> u64 {
        self.directory.load().version()
    }

    /// The current directory's expiry (for the reloader's expiry-before-unchanged
    /// check).
    #[must_use]
    pub fn current_expires_at_unix_ms(&self) -> u64 {
        self.directory.load().expires_at_unix_ms()
    }

    /// The current directory's body hash (for the reloader's rollback chaining
    /// and unchanged compare).
    #[must_use]
    pub fn current_body_sha256(&self) -> String {
        self.directory.load().body_sha256().to_string()
    }

    /// Lane-handler-facing resolution: the admitted `kernel_id` bound to an
    /// authenticated `EndpointId`, or `None` when unbound or removed. Lane
    /// handlers call this on `conn.remote_id()` to populate
    /// `authenticated_sender_kernel_id`; it shares the exact resolution the gate
    /// admitted on.
    #[must_use]
    pub fn resolve(&self, endpoint: &EndpointId) -> Option<String> {
        self.directory.load().authorize(endpoint).map(str::to_owned)
    }

    /// Pure admission decision for an authenticated `EndpointId`. Extracted from
    /// [`EndpointHooks::after_handshake`] so the accept/reject logic is unit
    /// testable without a live QUIC handshake.
    ///
    /// Fail-closed: any endpoint not bound to an admitted, non-removed
    /// `kernel_id` is rejected with [`NOT_ADMITTED_ERROR_CODE`].
    #[must_use]
    pub fn decide(&self, endpoint: &EndpointId) -> AfterHandshakeOutcome {
        match self.directory.load().authorize(endpoint) {
            Some(_kernel_id) => {
                // OBSERVE-ONLY: count the admit alongside the unchanged decision.
                crate::metrics::record_admission(crate::metrics::ADMISSION_ACCEPT);
                AfterHandshakeOutcome::Accept
            }
            None => {
                // OBSERVE-ONLY: the admission-gate 403 was the crate's single most
                // security-relevant SILENT event. Count it and emit a structured
                // event carrying the endpoint short-id (never a full key) so an
                // operator can alert on a reject spike (someone probing the mesh).
                // The returned Reject is byte-identical to before.
                crate::metrics::record_admission(crate::metrics::ADMISSION_REJECT);
                tracing::warn!(
                    target: crate::observability::TARGET_ADMISSION,
                    endpoint = %endpoint.fmt_short(),
                    code = NOT_ADMITTED_ERROR_CODE,
                    "admission reject: endpoint not bound to an admitted kernel"
                );
                AfterHandshakeOutcome::Reject {
                    error_code: NOT_ADMITTED_ERROR_CODE.into(),
                    reason: NOT_ADMITTED_REASON.to_vec(),
                }
            }
        }
    }
}

impl EndpointHooks for DirectoryGate {
    // A plain `async fn` satisfies the trait's RPITIT default (ADAPTER-SPEC 3.2:
    // do NOT write a sync fn). `remote_id()` is infallible after the handshake.
    async fn after_handshake(&self, conn: &Connection) -> AfterHandshakeOutcome {
        self.decide(&conn.remote_id())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::identity::transport_endorsement_preimage;
    use crate::identity::TransportDirectoryBundleBody;
    use crate::identity::TransportDirectoryBundleDocument;
    use crate::identity::TransportDirectoryBundleTrust;
    use crate::identity::TransportDirectoryDocument;
    use crate::identity::TransportDirectoryEntry;
    use crate::identity::TrustedTransportDirectoryIssuer;
    use crate::identity::TRANSPORT_DIRECTORY_BUNDLE_SCHEMA;
    use chio_core_types::canonical_json_bytes;
    use chio_core_types::sha256_hex;
    use chio_core_types::Keypair;
    use iroh::SecretKey;

    const NOW: u64 = 2_000_000;

    fn endpoint_from_seed(seed: u8) -> EndpointId {
        SecretKey::from_bytes(&[seed; 32]).public()
    }

    /// Build a verified single-entry directory admitting `kernel_id` at the
    /// transport endpoint derived from `transport_seed`. `removed` tombstones it.
    fn verified_directory(
        kernel_id: &str,
        passport_seed: u8,
        transport_seed: u8,
        removed: bool,
    ) -> Arc<VerifiedDirectory> {
        let passport = Keypair::from_seed(&[passport_seed; 32]);
        let issuer = Keypair::from_seed(&[240; 32]);
        let transport = endpoint_from_seed(transport_seed);
        let entry = TransportDirectoryEntry {
            kernel_id: kernel_id.to_string(),
            passport_public_key: passport.public_key(),
            transport_endpoint_id: transport,
            passport_endorsement: passport
                .sign(&transport_endorsement_preimage(kernel_id, &transport)),
            revocation_signers: Vec::new(),
            removed,
        };
        let directory = TransportDirectoryDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            local_kernel_id: "did:chio:local".to_string(),
            peers: vec![entry],
            treaties: Vec::new(),
        };
        let directory_sha256 = sha256_hex(&canonical_json_bytes(&directory).unwrap());
        let body = TransportDirectoryBundleBody {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            issuer: "did:chio:issuer".to_string(),
            key_id: "issuer-key-1".to_string(),
            directory_sha256,
            version: 1,
            previous_version_sha256: None,
            issued_at_unix_ms: NOW - 1,
            expires_at_unix_ms: NOW + 1,
        };
        let (signature, _) = issuer.sign_canonical(&body).unwrap();
        let bundle = TransportDirectoryBundleDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            body,
            directory,
            signature,
        };
        let trust = TransportDirectoryBundleTrust {
            issuers: vec![TrustedTransportDirectoryIssuer {
                issuer: "did:chio:issuer".to_string(),
                key_id: "issuer-key-1".to_string(),
                public_key: issuer.public_key(),
            }],
            version_floor: 0,
            expected_previous_version_sha256: None,
            now_unix_ms: NOW,
        };
        Arc::new(bundle.verify_bundle(&trust).expect("bundle verifies"))
    }

    fn reject_code(outcome: &AfterHandshakeOutcome) -> Option<(u32, Vec<u8>)> {
        // Handle the Reject variant precisely; do not exhaustively match the
        // outcome enum (Accept is the only other case here).
        if let AfterHandshakeOutcome::Reject { error_code, reason } = outcome {
            return Some((
                u32::try_from(u64::from(*error_code)).unwrap_or(u32::MAX),
                reason.clone(),
            ));
        }
        None
    }

    #[test]
    fn admitted_endpoint_accepts_and_resolves_kernel_id() {
        let gate = DirectoryGate::new(verified_directory("did:chio:alice", 1, 10, false));
        let admitted = endpoint_from_seed(10);

        assert!(matches!(
            gate.decide(&admitted),
            AfterHandshakeOutcome::Accept
        ));
        assert_eq!(gate.resolve(&admitted), Some("did:chio:alice".to_string()));
    }

    #[test]
    fn unbound_endpoint_is_rejected_403() {
        let gate = DirectoryGate::new(verified_directory("did:chio:alice", 1, 10, false));
        // An endpoint that appears in no directory entry at all.
        let outcome = gate.decide(&endpoint_from_seed(200));
        let (code, reason) = reject_code(&outcome).expect("unbound endpoint is rejected");
        assert_eq!(code, NOT_ADMITTED_ERROR_CODE);
        assert_eq!(reason, NOT_ADMITTED_REASON);
        assert_eq!(gate.resolve(&endpoint_from_seed(200)), None);
    }

    #[test]
    fn removed_endpoint_is_rejected_403() {
        // The endpoint IS bound, but the entry is tombstoned: still 403.
        let gate = DirectoryGate::new(verified_directory("did:chio:ghost", 3, 12, true));
        let removed = endpoint_from_seed(12);
        let outcome = gate.decide(&removed);
        let (code, _) = reject_code(&outcome).expect("removed endpoint is rejected");
        assert_eq!(code, NOT_ADMITTED_ERROR_CODE);
        assert_eq!(gate.resolve(&removed), None);
    }

    #[test]
    fn transport_key_rotation_flips_admitted_endpoint_at_the_gate() {
        // Option B end-to-end at the admission layer: alice's ed25519 transport
        // EndpointId rotates from E_old to E_new while her passport (seed 1) stays
        // fixed. The gate admits whichever endpoint the current directory binds.
        // (The chained fail-closed VERIFICATION of the N -> N+1 bundle, and the
        // passport-over-transport endorsement of E_new, are covered in
        // identity.rs; here we assert the resulting gate DECISION flips.)
        let e_old = endpoint_from_seed(10);
        let e_new = endpoint_from_seed(20);

        // Directory version N: alice admitted at E_old.
        let gate_n = DirectoryGate::new(verified_directory("did:chio:alice", 1, 10, false));
        assert!(matches!(
            gate_n.decide(&e_old),
            AfterHandshakeOutcome::Accept
        ));
        assert_eq!(gate_n.resolve(&e_old), Some("did:chio:alice".to_string()));
        // E_new is not yet admitted at N: fail-closed 403.
        assert!(
            reject_code(&gate_n.decide(&e_new)).is_some(),
            "E_new must not be admitted before rotation"
        );

        // Directory version N+1: alice has rotated to E_new (same passport).
        let gate_np1 = DirectoryGate::new(verified_directory("did:chio:alice", 1, 20, false));
        assert!(matches!(
            gate_np1.decide(&e_new),
            AfterHandshakeOutcome::Accept
        ));
        assert_eq!(gate_np1.resolve(&e_new), Some("did:chio:alice".to_string()));

        // THE LOAD-BEARING PROPERTY: the rotated-away E_old no longer admits.
        let outcome = gate_np1.decide(&e_old);
        let (code, reason) =
            reject_code(&outcome).expect("rotated-away E_old is rejected at the gate");
        assert_eq!(code, NOT_ADMITTED_ERROR_CODE);
        assert_eq!(reason, NOT_ADMITTED_REASON);
        assert_eq!(gate_np1.resolve(&e_old), None);
    }

    #[test]
    fn unadmitted_endpoint_bumps_403_counter_and_is_still_rejected() {
        // OBSERVE-ONLY proof: the admission-gate counter advances on a reject AND
        // the decision is byte-identical to before instrumentation (still a 403).
        // Counters are process-global, so assert a monotone lower bound (other
        // tests only ever add), never an exact value.
        let gate = DirectoryGate::new(verified_directory("did:chio:alice", 1, 10, false));
        let before_reject = crate::metrics::admission_total(crate::metrics::ADMISSION_REJECT);
        let before_accept = crate::metrics::admission_total(crate::metrics::ADMISSION_ACCEPT);

        let outcome = gate.decide(&endpoint_from_seed(200));
        let (code, reason) = reject_code(&outcome).expect("unadmitted endpoint is still rejected");
        assert_eq!(code, NOT_ADMITTED_ERROR_CODE);
        assert_eq!(reason, NOT_ADMITTED_REASON);
        assert!(
            crate::metrics::admission_total(crate::metrics::ADMISSION_REJECT) > before_reject,
            "the 403 reject must be counted (observe-only)"
        );

        // An admitted endpoint still accepts AND bumps the accept counter.
        assert!(matches!(
            gate.decide(&endpoint_from_seed(10)),
            AfterHandshakeOutcome::Accept
        ));
        assert!(
            crate::metrics::admission_total(crate::metrics::ADMISSION_ACCEPT) > before_accept,
            "an admit must be counted (observe-only)"
        );
    }

    #[test]
    fn swap_flips_admission_without_reconstructing_the_gate() {
        // Gate at version N admits alice at E_old. Swapping in a directory that
        // tombstones alice flips decide(E_old) to a 403 through the SAME gate
        // clone, with no reconstruction.
        let gate = DirectoryGate::new(verified_directory("did:chio:alice", 1, 10, false));
        let clone = gate.clone();
        let e_old = endpoint_from_seed(10);
        assert!(matches!(gate.decide(&e_old), AfterHandshakeOutcome::Accept));

        // Publish a successor that tombstones alice (removed = true).
        gate.swap(verified_directory("did:chio:alice", 1, 10, true));
        // Both the original handle and the clone observe the swap immediately.
        assert!(reject_code(&gate.decide(&e_old)).is_some());
        assert!(reject_code(&clone.decide(&e_old)).is_some());
        assert_eq!(clone.resolve(&e_old), None);
    }

    #[test]
    fn empty_deny_all_admits_nothing() {
        let gate = DirectoryGate::new(std::sync::Arc::new(
            crate::identity::VerifiedDirectory::empty_deny_all(),
        ));
        assert!(reject_code(&gate.decide(&endpoint_from_seed(10))).is_some());
        assert_eq!(gate.resolve(&endpoint_from_seed(10)), None);
    }
}
