//! `chio.finding.seller-authorization.v1`: Finding-issuer-signed
//! authorization for a seller (or delegate) to list one exact Finding.
//!
//! Required even when issuer and seller are the same key, so the direct
//! and delegated cases share one verification path. The envelope signer
//! must equal the embedded issuer, which in turn must equal the Finding's
//! issuer at the surface that resolves both artifacts.

use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};

use crate::envelope::require_ed25519;
use crate::validate::{require_hex64, require_non_empty, require_window, FindingError};

/// Finding-issuer-signed seller authorization.
pub const FINDING_SELLER_AUTHORIZATION_SCHEMA_V1: &str =
    chio_core_types::CHIO_FINDING_SELLER_AUTHORIZATION_V1_SCHEMA;

/// Where sale proceeds go. Either a direct rail-tagged beneficiary
/// destination or a provider-signed payee mapping committed by envelope
/// digest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FindingPayee {
    Beneficiary {
        destination: String,
        currency: String,
    },
    ProviderPayeeMapping {
        mapping_envelope_sha256: String,
    },
}

impl FindingPayee {
    fn validate(&self) -> Result<(), FindingError> {
        match self {
            FindingPayee::Beneficiary {
                destination,
                currency,
            } => {
                require_non_empty(destination, "payee.destination")?;
                crate::validate::require_currency(currency, "payee.currency")
            }
            FindingPayee::ProviderPayeeMapping {
                mapping_envelope_sha256,
            } => require_hex64(mapping_envelope_sha256, "payee.mapping_envelope_sha256"),
        }
    }
}

/// Seller-authorization body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingSellerAuthorization {
    pub schema: String,
    /// Content-addressed: sha256 of the canonical body with
    /// `authorization_id` cleared.
    pub authorization_id: String,
    pub finding_id: String,
    pub finding_artifact_sha256: String,
    pub listing_id: String,
    /// Finding issuer; must sign the enclosing envelope.
    pub issuer: PublicKey,
    /// Authorized seller or delegate.
    pub seller: PublicKey,
    pub provider_server_id: String,
    pub provider_tool: String,
    pub payee: FindingPayee,
    pub revocation_status_ref: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Issuer-signed envelope for the authorization.
pub type SignedFindingSellerAuthorization = SignedExportEnvelope<FindingSellerAuthorization>;

impl FindingSellerAuthorization {
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != FINDING_SELLER_AUTHORIZATION_SCHEMA_V1 {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        require_hex64(&self.authorization_id, "authorization_id")?;
        require_hex64(&self.finding_id, "finding_id")?;
        require_hex64(&self.finding_artifact_sha256, "finding_artifact_sha256")?;
        require_non_empty(&self.listing_id, "listing_id")?;
        require_ed25519(&self.issuer, "issuer")?;
        require_ed25519(&self.seller, "seller")?;
        require_non_empty(&self.provider_server_id, "provider_server_id")?;
        require_non_empty(&self.provider_tool, "provider_tool")?;
        self.payee.validate()?;
        require_non_empty(&self.revocation_status_ref, "revocation_status_ref")?;
        require_window(self.issued_at, self.expires_at, "issued_at", "expires_at")?;
        self.verify_authorization_id()
    }

    /// Recompute and compare the content-addressed authorization id.
    pub fn verify_authorization_id(&self) -> Result<(), FindingError> {
        let expected = compute_authorization_id(self)?;
        if expected == self.authorization_id {
            Ok(())
        } else {
            Err(FindingError::ArtifactIdMismatch("authorization_id"))
        }
    }
}

/// Content-addressed authorization id: sha256 over the canonical body with
/// `authorization_id` cleared.
pub fn compute_authorization_id(
    authorization: &FindingSellerAuthorization,
) -> Result<String, FindingError> {
    let mut body = authorization.clone();
    body.authorization_id = String::new();
    let bytes =
        chio_core_types::canonical_json_bytes(&body).map_err(|_| FindingError::Canonicalization)?;
    Ok(chio_core_types::crypto::sha256_hex(&bytes))
}

/// Verify a signed seller authorization: the envelope signer must equal
/// the embedded issuer and verify strictly. The caller separately asserts
/// the embedded issuer equals the resolved Finding's issuer.
pub fn verify_signed_seller_authorization(
    signed: &SignedFindingSellerAuthorization,
) -> Result<(), FindingError> {
    signed.body.validate()?;
    crate::envelope::verify_pinned_envelope(signed, &signed.body.issuer, "seller_authorization")
}
