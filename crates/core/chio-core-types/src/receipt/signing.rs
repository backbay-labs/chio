use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::canonical::{CanonicalBytes, CanonicalJsonWitness};
use crate::crypto::sha256_hex;
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

/// Error raised when a [`ReceiptSigningHandle`] is consumed against a receipt
/// body whose claimed `content_hash` does not match the hash the signer
/// recomputed over the bound canonical content.
///
/// This is the WYSIWYS ("what you see is what you sign") fail-closed gate: the
/// signer refuses to bind a signature to a body whose `content_hash` field was
/// not derived from the exact content the handle was built over. It closes the
/// render-A / sign-B class of attacks where a caller renders content `A` to a
/// human but submits a body claiming the hash of content `B`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentHashMismatch {
    /// The hash recomputed by the signer over the handle's canonical content.
    pub recomputed: String,
    /// The `content_hash` the caller embedded in the receipt body.
    pub claimed: String,
}

impl ContentHashMismatch {
    /// Render a stable, non-secret-bearing description for error surfaces.
    #[must_use]
    pub fn message(&self) -> String {
        format!(
            "receipt content_hash mismatch: body claimed {} but signer recomputed {} over the bound canonical content",
            self.claimed, self.recomputed
        )
    }
}

impl From<ContentHashMismatch> for Error {
    fn from(mismatch: ContentHashMismatch) -> Self {
        Error::CanonicalJson(mismatch.message())
    }
}

/// A one-time, move-only handle that binds a signature to a *specific*
/// evaluated artifact's canonical content.
///
/// # Why this exists (WYSIWYS at the trust boundary)
///
/// Today the receipt signer accepts a [`ChioReceiptBody`] whose `content_hash`
/// is a caller-supplied string and never recomputes it. That lets a caller
/// render content `A` to a human (and to the audit surface) while handing the
/// signer a body claiming the hash of content `B` -- a render-A / sign-B
/// forgery. A signature over such a body says nothing about the content the
/// human actually saw.
///
/// `ReceiptSigningHandle` closes that gap. It is constructed *inside the trust
/// boundary* from the exact canonical content the producer evaluated; at
/// construction time it recomputes `content_hash = sha256_hex(canonical_content)`
/// and stores both the immutable canonical bytes and the authoritative hash.
/// The signing entrypoints that take a handle then refuse to sign unless the
/// body's claimed `content_hash` equals the handle's recomputed hash
/// ([`ContentHashMismatch`], fail-closed).
///
/// # One-time semantics
///
/// The handle is **move-only** (no `Clone`): the signing entrypoints consume it
/// by value, so a single handle corresponds to a single signing attempt over a
/// single evaluated artifact. A producer cannot reuse one handle to back two
/// different signatures, and cannot smuggle a handle built over content `A`
/// into a sign call for content `B` -- the recomputed hash is fixed at
/// construction and the body's claim is checked against it.
///
/// # Seam note (follow-up: full `evaluate()` -> `sign()` binding)
///
/// In the present change the handle is built from canonical content bytes that
/// the producer supplies via [`ReceiptSigningHandle::from_content`] /
/// [`ReceiptSigningHandle::from_canonical_bytes`]. The intended end state is
/// that `evaluate()` *returns* the handle (so the only way to obtain one is to
/// have actually run an evaluation, and the bytes are the evaluator's own
/// canonical output rather than anything the caller chose). Threading the
/// handle out of `chio-kernel-core::evaluate` and through every adapter's
/// receipt-construction path is a larger change tracked as a follow-up
/// (follow-up seam). The hash-recompute + refuse-on-mismatch guarantee in this
/// type already closes the render-A / sign-B regression regardless of that
/// follow-up, because the signer never trusts the caller's `content_hash`.
///
/// # Debug redaction
///
/// `Debug` is implemented by hand (not derived) so the raw `content_preimage`
/// -- which for a value receipt is the exact canonical tool output and can carry
/// user data or secrets -- never reaches a log line, a `debug_assert!` panic, or
/// a `{:?}` format. The custom impl prints the recomputed `content_hash` (a
/// non-secret digest) and the preimage *length* in place of the bytes
/// themselves. See the `debug_redacts_preimage` test.
pub struct ReceiptSigningHandle {
    /// The exact byte preimage the `content_hash` is defined over. For a
    /// canonical-JSON artifact this is the RFC 8785 serialization; for a
    /// stream receipt it is the concatenated per-chunk digest preimage the
    /// kernel hashes (see `chio-kernel`'s `stream_receipt_content`). The
    /// handle never trusts a caller-asserted hash: `content_hash` below is
    /// always recomputed from these bytes at construction.
    content_preimage: Vec<u8>,
    content_hash: String,
}

impl core::fmt::Debug for ReceiptSigningHandle {
    /// Redacted formatter: prints the recomputed `content_hash` (non-secret)
    /// and the preimage byte length, but NEVER the preimage bytes. The raw
    /// preimage is the canonical tool output for value receipts and may carry
    /// user data or secrets, so it must not leak into logs or panic messages.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ReceiptSigningHandle")
            .field("content_hash", &self.content_hash)
            .field("content_preimage_len", &self.content_preimage.len())
            .field("content_preimage", &"<redacted>")
            .finish()
    }
}

impl ReceiptSigningHandle {
    /// Build a handle by serializing an evaluated artifact to canonical JSON
    /// and recomputing its content hash.
    ///
    /// `content` is the artifact the producer actually evaluated and intends to
    /// represent to the human (e.g. the tool output, the request projection).
    /// The handle owns the resulting canonical bytes and the
    /// `sha256_hex(canonical)` digest; both are fixed for the lifetime of the
    /// handle.
    ///
    /// # Errors
    ///
    /// Returns an error if `content` cannot be canonicalized.
    pub fn from_content<T: Serialize>(content: &T) -> Result<Self> {
        let canonical_content = CanonicalBytes::from_serializable(content)?;
        Ok(Self::from_canonical_bytes(canonical_content))
    }

    /// Build a handle directly from already-canonicalized content bytes.
    ///
    /// Use this when the producer has computed the canonical bytes through the
    /// witnessed [`CanonicalBytes`] path already (e.g. a shared evaluation
    /// buffer) and wants to avoid reserializing. The content hash is recomputed
    /// here regardless, so the resulting hash is always the signer's own,
    /// never a caller-asserted value.
    #[must_use]
    pub fn from_canonical_bytes(canonical_content: CanonicalBytes<CanonicalJsonWitness>) -> Self {
        Self::from_content_preimage(canonical_content.into_vec())
    }

    /// Build a handle from the exact byte preimage the receipt `content_hash`
    /// is defined over, recomputing the hash here.
    ///
    /// Use this on the production kernel signing path, where `content_hash` is
    /// not always `sha256_hex(canonical_json(value))`: stream receipts hash a
    /// concatenation of per-chunk digests, and the empty-output receipt hashes
    /// the literal `null` canonicalization. In every case the kernel already
    /// holds the exact bytes it hashed; passing them here lets the signer
    /// recompute the same digest independently and refuse to sign when the
    /// body's claimed `content_hash` does not match (WYSIWYS, fail-closed).
    ///
    /// The hash is recomputed from `preimage` regardless of its shape, so the
    /// resulting hash is always the signer's own, never a caller assertion.
    #[must_use]
    pub fn from_content_preimage(preimage: Vec<u8>) -> Self {
        let content_hash = sha256_hex(&preimage);
        Self {
            content_preimage: preimage,
            content_hash,
        }
    }

    /// The authoritative `content_hash` recomputed by the signer over the bound
    /// canonical content. This is what the receipt body's `content_hash` must
    /// equal for signing to proceed.
    #[must_use]
    pub fn content_hash(&self) -> &str {
        &self.content_hash
    }

    /// Borrow the immutable canonical content bytes bound to this handle.
    #[must_use]
    pub fn canonical_content(&self) -> &[u8] {
        &self.content_preimage
    }

    /// Fail-closed check that the body's claimed `content_hash` matches the
    /// hash recomputed over this handle's canonical content.
    ///
    /// # Errors
    ///
    /// Returns [`ContentHashMismatch`] when the body's `content_hash` differs
    /// from the handle's recomputed hash.
    pub fn ensure_body_matches(
        &self,
        body: &ChioReceiptBody,
    ) -> core::result::Result<(), ContentHashMismatch> {
        if body.content_hash == self.content_hash {
            Ok(())
        } else {
            Err(ContentHashMismatch {
                recomputed: self.content_hash.clone(),
                claimed: body.content_hash.clone(),
            })
        }
    }

    /// Consume the handle, returning the recomputed hash and canonical bytes.
    ///
    /// Consuming by value enforces the one-time semantics: once a handle has
    /// been turned into a signed receipt (or otherwise unwrapped) it cannot be
    /// reused to back another signature.
    #[must_use]
    pub fn into_parts(self) -> (String, Vec<u8>) {
        (self.content_hash, self.content_preimage)
    }
}
