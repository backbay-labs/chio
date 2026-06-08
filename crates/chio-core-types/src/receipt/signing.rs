use alloc::format;
use alloc::string::{String, ToString};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::body::{ChioReceiptBody, ChioReceiptIdInput};
use super::validation::{
    require_exact, require_lowercase_hex, require_lowercase_hex_chars, require_wire_identifier,
};

/// Versioned schema for BBS material bound to a Chio receipt.
pub const CHIO_RECEIPT_BBS_SIGNATURE_SCHEMA: &str = "chio.receipt.bbs_signature.v1";
/// Algorithm label used for receipt-bound BBS material.
pub const CHIO_RECEIPT_BBS_SIGNATURE_ALGORITHM: &str = "bbs";
/// Receipt-body BBS projection version accepted by the v1 receipt schema.
pub const CHIO_RECEIPT_BBS_PROJECTION_VERSION_V1: &str = "chio.bbs-projection.receipt.v1";
/// BBS ciphersuite accepted by the v1 receipt schema.
pub const CHIO_RECEIPT_BBS_CIPHERSUITE_V1: &str = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
/// Number of receipt-body projection messages covered by v1 BBS material.
pub const CHIO_RECEIPT_BBS_MESSAGE_COUNT_V1: usize = 14;

/// BBS signature material bound into a signed Chio receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BbsReceiptSignature {
    /// Versioned BBS receipt-signature schema.
    pub schema: String,
    /// Projection version used to derive the signed BBS message vector.
    pub projection_version: String,
    /// BBS algorithm family. v1 uses [`CHIO_RECEIPT_BBS_SIGNATURE_ALGORITHM`].
    pub algorithm: String,
    /// Concrete BBS ciphersuite used by the issuer.
    pub ciphersuite: String,
    /// Stable issuer fingerprint for BBS public-key lookup.
    pub issuer_fingerprint: String,
    /// Hex-encoded BBS public key.
    pub issuer_public_key_hex: String,
    /// Number of projected messages covered by the signature.
    pub message_count: usize,
    /// Hex-encoded BBS signature bytes.
    pub signature_hex: String,
}

impl BbsReceiptSignature {
    /// Validate shape-level BBS material before binding it into an Ed25519
    /// receipt signature. Cryptographic BBS verification remains in
    /// `chio-selective-disclosure`.
    pub fn validate(&self) -> Result<()> {
        require_exact(
            &self.schema,
            CHIO_RECEIPT_BBS_SIGNATURE_SCHEMA,
            "bbs_signature.schema",
        )?;
        require_exact(
            &self.algorithm,
            CHIO_RECEIPT_BBS_SIGNATURE_ALGORITHM,
            "bbs_signature.algorithm",
        )?;
        require_exact(
            &self.projection_version,
            CHIO_RECEIPT_BBS_PROJECTION_VERSION_V1,
            "bbs_signature.projection_version",
        )?;
        require_exact(
            &self.ciphersuite,
            CHIO_RECEIPT_BBS_CIPHERSUITE_V1,
            "bbs_signature.ciphersuite",
        )?;
        require_wire_identifier(
            &self.issuer_fingerprint,
            128,
            "bbs_signature.issuer_fingerprint",
        )?;
        require_lowercase_hex_chars(
            &self.issuer_public_key_hex,
            192,
            "bbs_signature.issuer_public_key_hex",
        )?;
        require_lowercase_hex(&self.signature_hex, "bbs_signature.signature_hex")?;
        if self.message_count != CHIO_RECEIPT_BBS_MESSAGE_COUNT_V1 {
            return Err(Error::CanonicalJson(format!(
                "bbs_signature.message_count must equal {CHIO_RECEIPT_BBS_MESSAGE_COUNT_V1}"
            )));
        }
        Ok(())
    }
}

/// Canonical receipt signing input.
///
/// The receipt id is computed from [`ChioReceiptIdInput`]. The signature then
/// binds both that id and the exact body input used to derive it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChioReceiptSigningBody {
    pub id: String,
    pub body: ChioReceiptIdInput,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bbs_signature: Option<BbsReceiptSignature>,
}

pub const CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY: &str = "chio_receipt_signing_nonce";
const CHIO_RECEIPT_ORIGINAL_METADATA_KEY: &str = "original_metadata";

/// Bind the canonical signing nonce into a receipt body's metadata before the
/// content-addressed id is computed.
///
/// Every receipt-signing entrypoint MUST call this after
/// `ChioReceiptBody::validate_signable_semantics` and before `chio_receipt_id`
/// so the nonce (the caller-supplied `body.id`) is folded into the id input,
/// and therefore into the signed bytes. The classical `ChioReceipt::sign` /
/// `ChioReceipt::sign_with_backend` paths call it inline; the kernel's hybrid
/// signing path (`chio_kernel::sign_receipt_body_hybrid_canonical`) calls it
/// through this public export so both paths produce byte-identical receipts.
///
/// No-op when `body.id` is empty after trimming.
pub fn bind_receipt_signing_nonce(body: &mut ChioReceiptBody) {
    let nonce = body.id.trim();
    if nonce.is_empty() {
        return;
    }

    let mut metadata = match body.metadata.take() {
        Some(serde_json::Value::Object(map)) => map,
        Some(value) => {
            let mut map = serde_json::Map::new();
            map.insert(CHIO_RECEIPT_ORIGINAL_METADATA_KEY.to_string(), value);
            map
        }
        None => serde_json::Map::new(),
    };
    metadata.insert(
        CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY.to_string(),
        serde_json::Value::String(nonce.to_string()),
    );
    body.metadata = Some(serde_json::Value::Object(metadata));
}

impl ChioReceiptSigningBody {
    #[must_use]
    pub fn from_body_and_bbs(
        body: &ChioReceiptBody,
        bbs_signature: Option<&BbsReceiptSignature>,
    ) -> Self {
        Self {
            id: body.id.clone(),
            body: ChioReceiptIdInput::from(body),
            bbs_signature: bbs_signature.cloned(),
        }
    }
}

impl From<&ChioReceiptBody> for ChioReceiptSigningBody {
    fn from(body: &ChioReceiptBody) -> Self {
        Self::from_body_and_bbs(body, None)
    }
}

pub(crate) fn validate_bbs_receipt_binding(
    body: &ChioReceiptBody,
    bbs_signature: Option<&BbsReceiptSignature>,
) -> Result<()> {
    match (&body.bbs_projection_version, bbs_signature) {
        (None, None) => Ok(()),
        (Some(_), None) => Err(Error::CanonicalJson(
            "bbs_projection_version requires bbs_signature".to_string(),
        )),
        (None, Some(_)) => Err(Error::CanonicalJson(
            "bbs_signature requires bbs_projection_version".to_string(),
        )),
        (Some(version), Some(signature)) => {
            signature.validate()?;
            if version != &signature.projection_version {
                return Err(Error::CanonicalJson(
                    "bbs_projection_version must match bbs_signature.projection_version"
                        .to_string(),
                ));
            }
            Ok(())
        }
    }
}
