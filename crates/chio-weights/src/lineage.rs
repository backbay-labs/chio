//! Lineage anchoring for published model cards.
//!
//! Publishing a [`crate::bundle::VerifiedModelCard`] to the public registry
//! emits a lineage anchor proof; consumers verify the proof through the
//! existing [`chio_lineage::anchor`] surface. This does not fork the
//! anchor surface; it derives a frontier-shaped digest from a verified
//! model card and packages it as a [`ModelCardLineageAnchor`] artifact whose
//! SHA-256 digest format and signing-state plumbing match
//! [`chio_lineage::anchor::AnchoredFrontier`] verbatim.
//!
//! # Trust contract
//!
//! Every public entry point that returns `Ok(_)` MUST mean:
//!
//! 1. the input was a [`crate::bundle::VerifiedModelCard`] produced by the
//!    cosign-bundle helper (so the upstream attestation already verified),
//!    and
//! 2. the emitted anchor's digest covers the canonical-JSON bytes of the
//!    model card AND the verified attestation's `(subject_digest_sha256,
//!    certificate_identity, certificate_oidc_issuer, rekor_log_index,
//!    rekor_inclusion_verified)` tuple.
//!
//! The digest is computed over a deterministically sorted JSON projection
//! so two implementations producing the same `(card, attestation)` pair
//! produce byte-identical anchor digests.
//!
//! # Soft-dep state
//!
//! `chio-lineage`'s [`SigningState`] enum records hybrid-signing presence.
//! When the caller passes `Some(algorithm)` (i.e. a signer was named but
//! hybrid signing has not produced a payload yet), the anchor records
//! [`SigningState::UnsignedSignerStubbed`] so verifiers fail-closed; when
//! the caller passes `None`, the anchor records
//! [`SigningState::UnsignedSoftDepAbsent`]. Neither variant impersonates
//! [`SigningState::Signed`]. These anchors never construct
//! [`SigningState::Signed`], and imported signed anchors are rejected until
//! a local verifier can authenticate the signature against a trusted key.

use chio_lineage::anchor::{
    is_lowercase_hex_signature_payload, CanonicalSource, FrontierDigest, SigningState,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bundle::VerifiedModelCard;
use crate::error::WeightsError;

/// Schema name pinning the lineage anchor projection used by model cards.
/// Distinct from the lineage-graph frontier schema so consumers can route
/// model-card anchors to the right verifier without parsing the body.
pub const MODEL_CARD_ANCHOR_SCHEMA: &str = "chio.weights.lineage-anchor/v1";

/// Lineage anchor proof for a published model card.
///
/// Produced by [`anchor_model_card`] and consumed by
/// [`verify_model_card_anchor`] (and by external lineage-graph consumers
/// through the existing `chio-lineage` surface). The shape mirrors
/// [`chio_lineage::anchor::AnchoredFrontier`] so the public registry can
/// emit one artifact format across both surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelCardLineageAnchor {
    /// Pinned schema version. MUST equal [`MODEL_CARD_ANCHOR_SCHEMA`].
    pub schema_version: String,
    /// Lineage-graph schema this anchor is published alongside.
    pub graph_schema: String,
    /// Canonical-bytes source identifier reused from the lineage anchor
    /// surface so consumers do not learn a second enum.
    pub canonical_source: CanonicalSource,
    /// Frontier-shaped digest: SHA-256 over the canonical projection bytes.
    pub digest: FrontierDigest,
    /// PQ-hybrid signing state placeholder. Mirrors the lineage anchor
    /// soft-dep slot; hybrid signing populates this when wired.
    pub signing: SigningState,
    /// Lowercase hexadecimal SHA-256 of the canonical-JSON model card
    /// bytes. Pinned in the artifact so consumers can correlate without
    /// re-deriving the digest.
    pub card_canonical_sha256: String,
    /// Hex-encoded `subject_digest_sha256` from the upstream verified
    /// attestation. Equals `card_canonical_sha256` when the cosign bundle
    /// signed the model card's canonical bytes directly; recorded
    /// separately so a future refactor that signs over a different
    /// projection (for example, a higher-level envelope) is detectable
    /// without reading the bundle.
    pub attestation_subject_sha256: String,
    /// Certificate identity SAN that satisfied the expected-identity regex.
    pub certificate_identity: String,
    /// OIDC issuer extracted from the Fulcio certificate.
    pub certificate_oidc_issuer: String,
    /// Rekor transparency log index. `0` if the bundle did not carry one.
    pub rekor_log_index: u64,
    /// `true` when the bundle's Rekor inclusion proof verified.
    pub rekor_inclusion_verified: bool,
    /// Card `weights_hash` lifted onto the anchor for receipt correlation.
    pub weights_hash: String,
    /// Card `issuer` lifted onto the anchor for receipt correlation.
    pub card_issuer: String,
    /// Card `expires_at` lifted so anchor consumers can reason about
    /// liveness without re-parsing the card body.
    pub card_expires_at: DateTime<Utc>,
}

impl ModelCardLineageAnchor {
    /// Return `true` only when the artifact carries a locally verified
    /// signature. No verifier is wired in yet, so every current state is
    /// treated as unsigned for fail-closed consumers.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        false
    }
}

/// Compute the SHA-256 digest of the canonical lineage projection for a
/// model card and a verified attestation. The projection is a
/// deterministically-keyed JSON object so two implementations producing
/// the same inputs produce byte-identical bytes.
///
/// Exposed for tests and for external indexers that want to recompute the
/// expected digest without depending on the entire `chio-weights` build.
pub fn anchor_projection_bytes(
    card_bytes: &[u8],
    attestation: &chio_attest_verify::VerifiedAttestation,
) -> Result<Vec<u8>, WeightsError> {
    let card_sha = sha256_hex(card_bytes);
    let subject_sha = hex::encode(attestation.subject_digest_sha256);
    // Use serde_json's BTreeMap-equivalent: build a sorted Map by hand to
    // preserve byte stability without depending on a canonical-JSON crate
    // here. The keys below are listed in lexicographic order so the
    // emitted JSON is canonical at the top level.
    let payload = serde_json::json!({
        "card_canonical_sha256": card_sha,
        "certificate_identity": attestation.certificate_identity,
        "certificate_oidc_issuer": attestation.certificate_oidc_issuer,
        "rekor_inclusion_verified": attestation.rekor_inclusion_verified,
        "rekor_log_index": attestation.rekor_log_index,
        "schema_version": MODEL_CARD_ANCHOR_SCHEMA,
        "subject_digest_sha256": subject_sha,
    });
    chio_core_types::canonical::canonical_json_bytes(&payload)
        .map_err(|err| WeightsError::Encoding(format!("anchor projection encode: {err}")))
}

/// SHA-256 hex of a byte slice. Mirrors the lineage anchor surface so the
/// digest representation is consistent across both anchor formats.
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

/// Build a [`ModelCardLineageAnchor`] from a verified model card.
///
/// `card_bytes` MUST be the canonical-JSON byte slice the cosign bundle
/// was signed over (i.e. the same bytes passed to
/// [`crate::bundle::verify_model_card_bundle`]). `signer_hint` records the
/// PQ-hybrid signing state in the same shape used by
/// [`chio_lineage::anchor::pin_frontier`]; pass `None` when hybrid
/// signing is absent.
///
/// Fail-closed: rejects when `card_bytes` does not decode to the same
/// model card carried by `verified.card`. This guards against a caller
/// that accidentally hands the helper a stale byte slice.
pub fn anchor_model_card(
    verified: &VerifiedModelCard,
    card_bytes: &[u8],
    graph_schema: &str,
    signer_hint: Option<&str>,
) -> Result<ModelCardLineageAnchor, WeightsError> {
    let decoded = crate::card::ModelCard::from_canonical_json(card_bytes)?;
    if decoded != verified.card {
        return Err(WeightsError::Encoding(
            "card_bytes do not match verified.card; refusing to anchor stale bytes".to_string(),
        ));
    }

    let projection = anchor_projection_bytes(card_bytes, &verified.attestation)?;
    let digest_hex = sha256_hex(&projection);

    // Fail-closed: this helper never has a real signature payload to record,
    // so we MUST NOT construct `SigningState::Signed { signature_hex: "" }`
    // here. Doing so would let a verifier matching `SigningState::Signed
    // { .. }` treat the anchor as authenticated even though no hybrid
    // signature exists. Until hybrid signing plumbs a real payload through
    // this helper, a signer hint produces `UnsignedSignerStubbed` so verifiers
    // see an explicit unsigned variant.
    let signing = match signer_hint {
        Some(algorithm) => SigningState::UnsignedSignerStubbed {
            algorithm: algorithm.to_string(),
        },
        None => SigningState::UnsignedSoftDepAbsent,
    };

    Ok(ModelCardLineageAnchor {
        schema_version: MODEL_CARD_ANCHOR_SCHEMA.to_string(),
        graph_schema: graph_schema.to_string(),
        canonical_source: CanonicalSource::EquivalenceShim,
        digest: FrontierDigest {
            algo: "sha256".to_string(),
            hex: digest_hex,
        },
        signing,
        card_canonical_sha256: sha256_hex(card_bytes),
        attestation_subject_sha256: hex::encode(verified.attestation.subject_digest_sha256),
        certificate_identity: verified.attestation.certificate_identity.clone(),
        certificate_oidc_issuer: verified.attestation.certificate_oidc_issuer.clone(),
        rekor_log_index: verified.attestation.rekor_log_index,
        rekor_inclusion_verified: verified.attestation.rekor_inclusion_verified,
        weights_hash: verified.card.weights_hash.clone(),
        card_issuer: verified.card.issuer.clone(),
        card_expires_at: verified.card.expires_at,
    })
}

/// Recompute the anchor's digest from the given inputs and reject if it
/// does not match `anchor.digest`. Consumers reading an anchor from the
/// public registry call this to verify the proof against the original
/// inputs without trusting the registry's stored digest.
pub fn verify_model_card_anchor(
    anchor: &ModelCardLineageAnchor,
    card_bytes: &[u8],
    attestation: &chio_attest_verify::VerifiedAttestation,
) -> Result<(), WeightsError> {
    if anchor.schema_version != MODEL_CARD_ANCHOR_SCHEMA {
        return Err(WeightsError::SchemaRejected(format!(
            "model card anchor schema_version must be {MODEL_CARD_ANCHOR_SCHEMA:?}, got {:?}",
            anchor.schema_version
        )));
    }
    if anchor.digest.algo != "sha256" {
        return Err(WeightsError::SchemaRejected(format!(
            "model card anchor digest algo must be \"sha256\", got {:?}",
            anchor.digest.algo
        )));
    }
    let expected_hex = sha256_hex(&anchor_projection_bytes(card_bytes, attestation)?);
    if expected_hex != anchor.digest.hex {
        return Err(WeightsError::BundleRejected(format!(
            "model card anchor digest mismatch: expected {expected_hex}, got {}",
            anchor.digest.hex
        )));
    }
    let card_sha = sha256_hex(card_bytes);
    if card_sha != anchor.card_canonical_sha256 {
        return Err(WeightsError::BundleRejected(format!(
            "model card anchor card_canonical_sha256 mismatch: expected {card_sha}, got {}",
            anchor.card_canonical_sha256
        )));
    }
    let expected_subject_sha = hex::encode(attestation.subject_digest_sha256);
    if expected_subject_sha != anchor.attestation_subject_sha256 {
        return Err(WeightsError::BundleRejected(format!(
            "model card anchor attestation_subject_sha256 mismatch: expected {expected_subject_sha}, got {}",
            anchor.attestation_subject_sha256
        )));
    }
    if attestation.certificate_identity != anchor.certificate_identity {
        return Err(WeightsError::BundleRejected(format!(
            "model card anchor certificate_identity mismatch: expected {:?}, got {:?}",
            attestation.certificate_identity, anchor.certificate_identity
        )));
    }
    if attestation.certificate_oidc_issuer != anchor.certificate_oidc_issuer {
        return Err(WeightsError::BundleRejected(format!(
            "model card anchor certificate_oidc_issuer mismatch: expected {:?}, got {:?}",
            attestation.certificate_oidc_issuer, anchor.certificate_oidc_issuer
        )));
    }
    if attestation.rekor_log_index != anchor.rekor_log_index {
        return Err(WeightsError::BundleRejected(format!(
            "model card anchor rekor_log_index mismatch: expected {}, got {}",
            attestation.rekor_log_index, anchor.rekor_log_index
        )));
    }
    if attestation.rekor_inclusion_verified != anchor.rekor_inclusion_verified {
        return Err(WeightsError::BundleRejected(format!(
            "model card anchor rekor_inclusion_verified mismatch: expected {}, got {}",
            attestation.rekor_inclusion_verified, anchor.rekor_inclusion_verified
        )));
    }

    // Defense-in-depth: no local verifier is wired for lineage signature
    // payloads yet. Reject every imported Signed state so arbitrary hex
    // cannot be promoted into public trust evidence.
    if let SigningState::Signed {
        algorithm,
        signature_hex,
    } = &anchor.signing
    {
        if !is_lowercase_hex_signature_payload(signature_hex) {
            return Err(WeightsError::BundleRejected(
                "model card anchor signing state was Signed but signature_hex was empty or not lower-case hexadecimal"
                    .to_string(),
            ));
        }
        return Err(WeightsError::BundleRejected(format!(
            "model card anchor signing algorithm {algorithm:?} is not verified by this build"
        )));
    }

    let card = crate::card::ModelCard::from_canonical_json(card_bytes)?;
    if card.weights_hash != anchor.weights_hash {
        return Err(WeightsError::BundleRejected(format!(
            "model card anchor weights_hash mismatch: expected {:?}, got {:?}",
            card.weights_hash, anchor.weights_hash
        )));
    }
    if card.issuer != anchor.card_issuer {
        return Err(WeightsError::BundleRejected(format!(
            "model card anchor card_issuer mismatch: expected {:?}, got {:?}",
            card.issuer, anchor.card_issuer
        )));
    }
    if card.expires_at != anchor.card_expires_at {
        return Err(WeightsError::BundleRejected(format!(
            "model card anchor card_expires_at mismatch: expected {}, got {}",
            card.expires_at, anchor.card_expires_at
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    use chio_attest_verify::VerifiedAttestation;
    use chrono::TimeZone;

    use crate::card::{ModelCard, StringSet};

    fn fixed_now() -> DateTime<Utc> {
        match Utc.with_ymd_and_hms(2026, 4, 30, 12, 0, 0) {
            chrono::LocalResult::Single(t) => t,
            _ => panic!("fixed_now fixture must construct"),
        }
    }

    fn good_card() -> ModelCard {
        let now = fixed_now();
        match ModelCard::new(
            "0000000000000000000000000000000000000000000000000000000000000001",
            StringSet::new(["tool:read"]),
            StringSet::default(),
            "public-internet",
            "https://example.com/issuer",
            now,
            now + chrono::Duration::days(30),
        ) {
            Ok(c) => c,
            Err(e) => panic!("good_card must construct: {e}"),
        }
    }

    fn good_attestation(card_sha: [u8; 32]) -> VerifiedAttestation {
        VerifiedAttestation {
            subject_digest_sha256: card_sha,
            certificate_identity: "https://example.com/issuer".into(),
            certificate_oidc_issuer: "https://token.example.com".into(),
            rekor_log_index: 42,
            rekor_inclusion_verified: true,
            signed_at: SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn anchor_round_trips_unsigned() {
        let card = good_card();
        let bytes = match card.to_canonical_json() {
            Ok(b) => b,
            Err(e) => panic!("encode: {e}"),
        };
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&Sha256::digest(&bytes));
        let att = good_attestation(digest);
        let verified = VerifiedModelCard {
            card: card.clone(),
            attestation: att.clone(),
        };
        let anchor = match anchor_model_card(&verified, &bytes, "chio.lineage.graph/v1", None) {
            Ok(a) => a,
            Err(e) => panic!("anchor: {e}"),
        };
        assert_eq!(anchor.schema_version, MODEL_CARD_ANCHOR_SCHEMA);
        assert!(matches!(
            anchor.signing,
            SigningState::UnsignedSoftDepAbsent
        ));
        match verify_model_card_anchor(&anchor, &bytes, &att) {
            Ok(()) => {}
            Err(e) => panic!("verify: {e}"),
        }
    }

    #[test]
    fn anchor_records_signer_hint() {
        let card = good_card();
        let bytes = match card.to_canonical_json() {
            Ok(b) => b,
            Err(e) => panic!("encode: {e}"),
        };
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&Sha256::digest(&bytes));
        let att = good_attestation(digest);
        let verified = VerifiedModelCard {
            card,
            attestation: att,
        };
        let anchor = match anchor_model_card(
            &verified,
            &bytes,
            "chio.lineage.graph/v1",
            Some("hybrid:ed25519+ml-dsa-65"),
        ) {
            Ok(a) => a,
            Err(e) => panic!("anchor: {e}"),
        };
        // Signer hint is present but no signature payload was supplied, so
        // the anchor MUST record `UnsignedSignerStubbed`. A naive `Signed`
        // variant with empty `signature_hex` would let a verifier matching
        // on the variant alone treat the artifact as authenticated.
        assert!(matches!(
            anchor.signing,
            SigningState::UnsignedSignerStubbed { ref algorithm }
                if algorithm == "hybrid:ed25519+ml-dsa-65"
        ));
        assert!(!anchor.is_signed());
    }

    #[test]
    fn anchor_signed_state_with_malformed_payload_is_unsigned() {
        let card = good_card();
        let bytes = match card.to_canonical_json() {
            Ok(b) => b,
            Err(e) => panic!("encode: {e}"),
        };
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&Sha256::digest(&bytes));
        let att = good_attestation(digest);
        let verified = VerifiedModelCard {
            card,
            attestation: att,
        };
        let mut anchor = match anchor_model_card(&verified, &bytes, "chio.lineage.graph/v1", None) {
            Ok(a) => a,
            Err(e) => panic!("anchor: {e}"),
        };

        for signature_hex in ["DEADBEEF", "dead beef", " deadbeef", "zz", "f"] {
            anchor.signing = SigningState::Signed {
                algorithm: "hybrid:ed25519+ml-dsa-65".to_string(),
                signature_hex: signature_hex.to_string(),
            };
            assert!(
                !anchor.is_signed(),
                "malformed signature payload {signature_hex:?} must be unsigned"
            );
        }
    }

    #[test]
    fn anchor_rejects_stale_bytes() {
        let card = good_card();
        let bytes = match card.to_canonical_json() {
            Ok(b) => b,
            Err(e) => panic!("encode: {e}"),
        };
        // Stale bytes: a different card.
        let now = fixed_now();
        let other = match ModelCard::new(
            "0000000000000000000000000000000000000000000000000000000000000002",
            StringSet::default(),
            StringSet::default(),
            "public-internet",
            "https://example.com/issuer",
            now,
            now + chrono::Duration::days(1),
        ) {
            Ok(c) => c,
            Err(e) => panic!("other card: {e}"),
        };
        let other_bytes = match other.to_canonical_json() {
            Ok(b) => b,
            Err(e) => panic!("encode: {e}"),
        };
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&Sha256::digest(&bytes));
        let att = good_attestation(digest);
        let verified = VerifiedModelCard {
            card,
            attestation: att,
        };
        let res = anchor_model_card(&verified, &other_bytes, "chio.lineage.graph/v1", None);
        assert!(matches!(res, Err(WeightsError::Encoding(_))));
    }

    #[test]
    fn verify_rejects_tampered_digest() {
        let card = good_card();
        let bytes = match card.to_canonical_json() {
            Ok(b) => b,
            Err(e) => panic!("encode: {e}"),
        };
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&Sha256::digest(&bytes));
        let att = good_attestation(digest);
        let verified = VerifiedModelCard {
            card,
            attestation: att.clone(),
        };
        let mut anchor = match anchor_model_card(&verified, &bytes, "chio.lineage.graph/v1", None) {
            Ok(a) => a,
            Err(e) => panic!("anchor: {e}"),
        };
        anchor.digest.hex = "0".repeat(64);
        let res = verify_model_card_anchor(&anchor, &bytes, &att);
        assert!(matches!(res, Err(WeightsError::BundleRejected(_))));
    }

    #[test]
    fn verify_rejects_tampered_attestation_metadata() {
        let card = good_card();
        let bytes = match card.to_canonical_json() {
            Ok(b) => b,
            Err(e) => panic!("encode: {e}"),
        };
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&Sha256::digest(&bytes));
        let att = good_attestation(digest);
        let verified = VerifiedModelCard {
            card,
            attestation: att.clone(),
        };
        let mut anchor = match anchor_model_card(&verified, &bytes, "chio.lineage.graph/v1", None) {
            Ok(a) => a,
            Err(e) => panic!("anchor: {e}"),
        };
        anchor.certificate_identity = "https://example.com/forged".to_string();
        let res = verify_model_card_anchor(&anchor, &bytes, &att);
        assert!(matches!(res, Err(WeightsError::BundleRejected(_))));
    }

    #[test]
    fn verify_rejects_tampered_card_metadata() {
        let card = good_card();
        let bytes = match card.to_canonical_json() {
            Ok(b) => b,
            Err(e) => panic!("encode: {e}"),
        };
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&Sha256::digest(&bytes));
        let att = good_attestation(digest);
        let verified = VerifiedModelCard {
            card,
            attestation: att.clone(),
        };
        let mut anchor = match anchor_model_card(&verified, &bytes, "chio.lineage.graph/v1", None) {
            Ok(a) => a,
            Err(e) => panic!("anchor: {e}"),
        };
        anchor.card_issuer = "https://example.com/forged".to_string();
        let res = verify_model_card_anchor(&anchor, &bytes, &att);
        assert!(matches!(res, Err(WeightsError::BundleRejected(_))));
    }

    #[test]
    fn verify_rejects_wrong_schema_version() {
        let card = good_card();
        let bytes = match card.to_canonical_json() {
            Ok(b) => b,
            Err(e) => panic!("encode: {e}"),
        };
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&Sha256::digest(&bytes));
        let att = good_attestation(digest);
        let verified = VerifiedModelCard {
            card,
            attestation: att.clone(),
        };
        let mut anchor = match anchor_model_card(&verified, &bytes, "chio.lineage.graph/v1", None) {
            Ok(a) => a,
            Err(e) => panic!("anchor: {e}"),
        };
        anchor.schema_version = "chio.weights.lineage-anchor/v999".to_string();
        let res = verify_model_card_anchor(&anchor, &bytes, &att);
        assert!(matches!(res, Err(WeightsError::SchemaRejected(_))));
    }

    #[test]
    fn anchor_digest_is_deterministic_across_runs() {
        let card = good_card();
        let bytes = match card.to_canonical_json() {
            Ok(b) => b,
            Err(e) => panic!("encode: {e}"),
        };
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&Sha256::digest(&bytes));
        let att = good_attestation(digest);
        let a = match anchor_projection_bytes(&bytes, &att) {
            Ok(bytes) => sha256_hex(&bytes),
            Err(e) => panic!("projection A: {e}"),
        };
        let b = match anchor_projection_bytes(&bytes, &att) {
            Ok(bytes) => sha256_hex(&bytes),
            Err(e) => panic!("projection B: {e}"),
        };
        assert_eq!(a, b);
    }
}
