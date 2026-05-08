//! Bilateral cross-kernel runtime co-signing.
//!
//! When an agent from Organisation A invokes a tool hosted by Organisation B,
//! both kernels need to sign the same receipt so that either org can
//! independently verify the chain. This module defines the wire-level
//! [`CoSigningRequest`] / [`CoSigningResponse`] envelope, the
//! [`DualSignedReceipt`] artifact (which carries both signatures side-by-
//! side without mutating the core `ChioReceipt` body), and a
//! [`BilateralCoSigningProtocol`] trait that the kernel calls after it
//! signs a receipt locally.
//!
//! ## Design notes
//!
//! * `chio-core-types::ChioReceipt` is intentionally untouched -- co-signatures
//!   ride in this federation-specific envelope. An Org A verifier that only
//!   understands the base receipt can still verify it in isolation; a Dual
//!   verifier checks the base receipt plus the remote org's detached
//!   signature over the same canonical body.
//! * Verification is strict: a `DualSignedReceipt` only verifies when BOTH
//!   signatures validate against their declared kernel IDs and both kernel
//!   IDs match the expected pinned peers. Either half alone is not
//!   sufficient.
//! * Signing happens over canonical JSON (RFC 8785) of the
//!   [`CoSigningBody`]: receipt body bytes + both kernel IDs. This keeps the
//!   detached remote signature deterministic across implementations.

use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::{Ed25519Backend, Keypair, PublicKey, Signature, SigningBackend};
use chio_core_types::receipt::ChioReceipt;
use serde::{Deserialize, Serialize};

pub const BILATERAL_COSIGNING_SCHEMA: &str = "chio.federation-bilateral-cosigning.v1";
pub const BILATERAL_DUAL_RECEIPT_SCHEMA: &str = "chio.federation-dual-signed-receipt.v1";

/// Canonical body that the local and remote kernels both sign. The bytes of
/// this structure (in canonical JSON) are the signed message for
/// [`DualSignedReceipt::org_a_signature`] and
/// [`DualSignedReceipt::org_b_signature`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoSigningBody {
    pub schema: String,
    /// Canonical JSON encoding of the underlying `ChioReceipt`, as a UTF-8
    /// string. The string form (rather than a nested object) keeps signing
    /// stable even if the receipt schema grows new `skip_serializing_if`
    /// fields later: both kernels sign exactly the bytes they saw.
    pub receipt_canonical_json: String,
    pub org_a_kernel_id: String,
    pub org_b_kernel_id: String,
}

impl CoSigningBody {
    /// Construct the canonical body from a receipt and the two kernel IDs
    /// participating in the exchange. Returns the body plus the canonical
    /// bytes of the receipt, so callers can persist them.
    pub fn from_receipt(
        receipt: &ChioReceipt,
        org_a_kernel_id: &str,
        org_b_kernel_id: &str,
    ) -> Result<Self, BilateralCoSigningError> {
        let bytes = canonical_json_bytes(receipt)
            .map_err(|e| BilateralCoSigningError::CanonicalJson(e.to_string()))?;
        let receipt_canonical_json = String::from_utf8(bytes)
            .map_err(|e| BilateralCoSigningError::CanonicalJson(e.to_string()))?;
        Ok(Self {
            schema: BILATERAL_COSIGNING_SCHEMA.to_string(),
            receipt_canonical_json,
            org_a_kernel_id: org_a_kernel_id.to_string(),
            org_b_kernel_id: org_b_kernel_id.to_string(),
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BilateralCoSigningError> {
        canonical_json_bytes(self)
            .map_err(|e| BilateralCoSigningError::CanonicalJson(e.to_string()))
    }
}

/// A receipt co-signed by two kernels across a federation boundary.
///
/// * `body` -- the underlying `ChioReceipt` that both kernels agreed on.
/// * `org_a_signature` -- detached signature by the origin (Org A) kernel
///   over the canonical [`CoSigningBody`].
/// * `org_b_signature` -- detached signature by the tool-host (Org B) kernel
///   over the same canonical body.
///
/// The existing receipt's built-in `signature` and `kernel_key` fields are
/// unchanged: a classic verifier can still check the receipt in isolation,
/// while a federation-aware verifier additionally checks both detached
/// signatures via [`DualSignedReceipt::verify`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DualSignedReceipt {
    pub schema: String,
    pub body: ChioReceipt,
    pub org_a_kernel_id: String,
    pub org_b_kernel_id: String,
    pub org_a_signature: Signature,
    pub org_b_signature: Signature,
}

impl DualSignedReceipt {
    /// Verify both detached signatures against the provided pinned peer
    /// public keys. Returns `Ok(())` only when BOTH signatures validate.
    ///
    /// Neither half of the dual signature is sufficient on its own; a
    /// caller that can only check one side must still refuse the receipt.
    ///
    /// # Non-§6 disclaimer (TRJ5-B4 / R4 BLOCKER 1)
    ///
    /// **This method is NOT a `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md`
    /// §6 verifier.** The signatures it checks are computed over the
    /// canonical-JSON encoding of [`CoSigningBody`]; the §6 envelope's
    /// signatures are computed over DSSE PAE bytes wrapping an in-toto
    /// Statement. The two preimages share zero bytes (R4 finding 1).
    ///
    /// Verifiers seeking §6 conformance MUST instead use
    /// [`crate::bilateral_dsse::verify_dsse_envelope`] against a
    /// [`crate::bilateral_dsse::DsseEnvelope`]. The trj5 federation hot
    /// path emits both artifacts under cohabitation; deprecation of this
    /// legacy verifier is queued for trj6.
    pub fn verify(
        &self,
        org_a_public_key: &PublicKey,
        org_b_public_key: &PublicKey,
    ) -> Result<(), BilateralCoSigningError> {
        let body =
            CoSigningBody::from_receipt(&self.body, &self.org_a_kernel_id, &self.org_b_kernel_id)?;
        let bytes = body.canonical_bytes()?;

        if !org_a_public_key.verify(&bytes, &self.org_a_signature) {
            return Err(BilateralCoSigningError::OrgASignatureInvalid);
        }
        if !org_b_public_key.verify(&bytes, &self.org_b_signature) {
            return Err(BilateralCoSigningError::OrgBSignatureInvalid);
        }
        Ok(())
    }
}

/// Request sent from the tool-host kernel (Org B) to the origin kernel
/// (Org A) asking it to co-sign a receipt that Org B already signed
/// locally.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoSigningRequest {
    pub schema: String,
    pub body: ChioReceipt,
    pub org_a_kernel_id: String,
    pub org_b_kernel_id: String,
    /// Org B's own signature over the canonical cosigning body. The origin
    /// kernel verifies this before agreeing to sign.
    pub org_b_signature: Signature,
}

impl CoSigningRequest {
    pub fn new(
        body: ChioReceipt,
        org_a_kernel_id: String,
        org_b_kernel_id: String,
        org_b_signature: Signature,
    ) -> Self {
        Self {
            schema: BILATERAL_COSIGNING_SCHEMA.to_string(),
            body,
            org_a_kernel_id,
            org_b_kernel_id,
            org_b_signature,
        }
    }
}

/// Response from the origin kernel (Org A) carrying its co-signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoSigningResponse {
    pub schema: String,
    pub org_a_signature: Signature,
}

/// Errors surfaced by the bilateral co-signing protocol. All variants are
/// fail-closed: on any error the kernel MUST refuse to persist a dual-signed
/// receipt for the failing exchange.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BilateralCoSigningError {
    #[error("canonical JSON encoding failed: {0}")]
    CanonicalJson(String),

    #[error("origin (Org A) signature failed verification")]
    OrgASignatureInvalid,

    #[error("tool-host (Org B) signature failed verification")]
    OrgBSignatureInvalid,

    #[error("remote peer {0} is not a trusted federation peer")]
    UnknownPeer(String),

    #[error("remote peer {0} has exceeded its rotation window and must re-handshake")]
    PeerExpired(String),

    #[error("co-signing transport failed: {0}")]
    TransportFailure(String),

    #[error("co-signing request rejected by peer: {0}")]
    PeerRejected(String),

    #[error("receipt body mismatch between request and signed body")]
    ReceiptMismatch,
}

/// Trait implemented by an object that can obtain a co-signature from a
/// remote kernel. Production deployments plug an mTLS-backed RPC client
/// in here; in-process tests use [`InProcessCoSigner`].
pub trait BilateralCoSigningProtocol: Send + Sync {
    /// Request a co-signature for a receipt that this kernel already
    /// signed. The caller is the tool-host kernel (Org B); the remote is
    /// the origin kernel (Org A) whose agent initiated the call.
    fn request_cosignature(
        &self,
        request: &CoSigningRequest,
    ) -> Result<CoSigningResponse, BilateralCoSigningError>;
}

/// In-process reference implementation of [`BilateralCoSigningProtocol`].
///
/// Holds the origin kernel's signing keypair directly, so tests and
/// single-host integration environments can exercise the co-signing path
/// without an actual mTLS transport. Production deployments should wrap
/// the remote kernel behind an attested RPC client instead.
pub struct InProcessCoSigner {
    origin_kernel_id: String,
    origin_keypair: Keypair,
    /// Expected public key of the tool-host kernel (Org B). The origin
    /// kernel verifies Org B's signature against this key before it is
    /// willing to co-sign.
    tool_host_public_key: PublicKey,
}

impl core::fmt::Debug for InProcessCoSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InProcessCoSigner")
            .field("origin_kernel_id", &self.origin_kernel_id)
            .finish_non_exhaustive()
    }
}

impl InProcessCoSigner {
    pub fn new(
        origin_kernel_id: impl Into<String>,
        origin_keypair: Keypair,
        tool_host_public_key: PublicKey,
    ) -> Self {
        Self {
            origin_kernel_id: origin_kernel_id.into(),
            origin_keypair,
            tool_host_public_key,
        }
    }

    pub fn origin_kernel_id(&self) -> &str {
        &self.origin_kernel_id
    }

    pub fn origin_public_key(&self) -> PublicKey {
        self.origin_keypair.public_key()
    }
}

impl BilateralCoSigningProtocol for InProcessCoSigner {
    fn request_cosignature(
        &self,
        request: &CoSigningRequest,
    ) -> Result<CoSigningResponse, BilateralCoSigningError> {
        if request.org_a_kernel_id != self.origin_kernel_id {
            return Err(BilateralCoSigningError::UnknownPeer(
                request.org_a_kernel_id.clone(),
            ));
        }
        let body = CoSigningBody::from_receipt(
            &request.body,
            &request.org_a_kernel_id,
            &request.org_b_kernel_id,
        )?;
        let bytes = body.canonical_bytes()?;

        if !self
            .tool_host_public_key
            .verify(&bytes, &request.org_b_signature)
        {
            return Err(BilateralCoSigningError::OrgBSignatureInvalid);
        }

        let backend = Ed25519Backend::new(self.origin_keypair.clone());
        let signature = backend
            .sign_bytes(&bytes)
            .map_err(|e| BilateralCoSigningError::TransportFailure(e.to_string()))?;
        Ok(CoSigningResponse {
            schema: BILATERAL_COSIGNING_SCHEMA.to_string(),
            org_a_signature: signature,
        })
    }
}

/// Helper used by the tool-host (Org B) side to drive the full protocol:
/// locally sign the canonical body, ask the remote [`BilateralCoSigningProtocol`]
/// for a co-signature, and assemble the verified [`DualSignedReceipt`].
pub fn co_sign_with_origin(
    origin_kernel_id: &str,
    origin_public_key: &PublicKey,
    tool_host_kernel_id: &str,
    tool_host_keypair: &Keypair,
    receipt: ChioReceipt,
    cosigner: &dyn BilateralCoSigningProtocol,
) -> Result<DualSignedReceipt, BilateralCoSigningError> {
    // W2.4: emit `chio_federation_hop_total` and observe
    // `chio_federation_hop_latency_seconds` at the federation-hop boundary.
    // The recorder fires before returning so even signature-failure paths
    // surface in the registry, matching the counter/histogram pair the
    // chio-recording-rules.yml alert pack expects.
    let started = std::time::Instant::now();
    let outcome = co_sign_with_origin_inner(
        origin_kernel_id,
        origin_public_key,
        tool_host_kernel_id,
        tool_host_keypair,
        receipt,
        cosigner,
    );
    let result = if outcome.is_ok() {
        crate::metrics::HOP_RESULT_OK
    } else {
        crate::metrics::HOP_RESULT_ERROR
    };
    let elapsed_nanos = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    crate::metrics::observe_federation_hop_latency_nanos(result, elapsed_nanos);
    outcome
}

fn co_sign_with_origin_inner(
    origin_kernel_id: &str,
    origin_public_key: &PublicKey,
    tool_host_kernel_id: &str,
    tool_host_keypair: &Keypair,
    receipt: ChioReceipt,
    cosigner: &dyn BilateralCoSigningProtocol,
) -> Result<DualSignedReceipt, BilateralCoSigningError> {
    let body = CoSigningBody::from_receipt(&receipt, origin_kernel_id, tool_host_kernel_id)?;
    let bytes = body.canonical_bytes()?;

    let backend = Ed25519Backend::new(tool_host_keypair.clone());
    let org_b_signature = backend
        .sign_bytes(&bytes)
        .map_err(|e| BilateralCoSigningError::TransportFailure(e.to_string()))?;

    let request = CoSigningRequest::new(
        receipt.clone(),
        origin_kernel_id.to_string(),
        tool_host_kernel_id.to_string(),
        org_b_signature.clone(),
    );
    let response = cosigner.request_cosignature(&request)?;

    if !origin_public_key.verify(&bytes, &response.org_a_signature) {
        return Err(BilateralCoSigningError::OrgASignatureInvalid);
    }

    let dual = DualSignedReceipt {
        schema: BILATERAL_DUAL_RECEIPT_SCHEMA.to_string(),
        body: receipt,
        org_a_kernel_id: origin_kernel_id.to_string(),
        org_b_kernel_id: tool_host_kernel_id.to_string(),
        org_a_signature: response.org_a_signature,
        org_b_signature,
    };
    // Double-check the assembled artifact verifies end-to-end. The kernel
    // relies on this invariant to persist only dual-signed artifacts that
    // would themselves pass third-party verification.
    dual.verify(origin_public_key, &tool_host_keypair.public_key())?;
    Ok(dual)
}

// ---------------------------------------------------------------------------
// TRJ5-B4.3: federation hot path also emits the §6-conformant DSSE envelope.
// ---------------------------------------------------------------------------

/// Combined output of the trj5 bilateral co-sign hot path: the legacy
/// [`DualSignedReceipt`] (retained for backward compatibility) plus the
/// `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §6-conformant DSSE
/// envelope.
///
/// **Verifiers seeking §6 conformance MUST verify
/// [`Self::dsse_envelope`].** The legacy `DualSignedReceipt` shares zero
/// signed bytes with the DSSE PAE preimage and is therefore NOT a §6
/// artifact; see `crate::bilateral_dsse` module docs.
#[derive(Debug, Clone)]
pub struct BilateralCoSignArtifacts {
    /// Legacy artifact. Retained for federation transport callers that
    /// have not yet migrated to DSSE-shaped envelopes. Trj6 may collapse
    /// this surface; trj5 ships both.
    pub dual_signed_receipt: DualSignedReceipt,
    /// §6-conformant DSSE envelope. The trj5 hot path emits this whenever
    /// both kernel keypairs are available locally (the in-process
    /// federation demo path). Cross-host emission is queued for trj6
    /// when a DSSE-aware `BilateralCoSigningProtocol` lands.
    pub dsse_envelope: crate::bilateral_dsse::DsseEnvelope,
}

/// Drive the bilateral co-sign protocol AND emit the §6-conformant DSSE
/// envelope. The DSSE envelope is produced by signing the DSSE PAE bytes
/// locally with both kernel keypairs; this matches the in-process
/// federation demo (Lane C) where both signing identities are co-located.
///
/// Cross-host deployments MUST wait for trj6's DSSE-aware
/// [`BilateralCoSigningProtocol`] extension; until then those callers
/// should continue invoking [`co_sign_with_origin`] (legacy artifact only,
/// **NOT §6-conformant**) with full awareness of the disclaimer on
/// [`DualSignedReceipt::verify`].
///
/// `tool_name` and `timestamp_unix_ms` are surfaced to callers because
/// they are §5 predicate fields the §6 envelope binds. `tool_name` is
/// typically `receipt.tool_name`; `timestamp_unix_ms` is the wall-clock
/// at canonicalisation (Org B-side).
#[allow(clippy::too_many_arguments)]
pub fn co_sign_with_origin_full(
    origin_kernel_id: &str,
    origin_keypair: &Keypair,
    tool_host_kernel_id: &str,
    tool_host_keypair: &Keypair,
    receipt: ChioReceipt,
    cosigner: &dyn BilateralCoSigningProtocol,
    tool_name: &str,
    timestamp_unix_ms: u64,
) -> Result<BilateralCoSignArtifacts, BilateralCoSigningError> {
    // Legacy hop: produces the existing DualSignedReceipt (and emits the
    // hop counter / histogram via co_sign_with_origin's wrapper).
    let dual = co_sign_with_origin(
        origin_kernel_id,
        &origin_keypair.public_key(),
        tool_host_kernel_id,
        tool_host_keypair,
        receipt.clone(),
        cosigner,
    )?;

    // §6 envelope: the DSSE PAE preimage shares ZERO bytes with the
    // legacy preimage (R4 BLOCKER 1). Both kernels sign the same PAE
    // bytes; in the in-process demo we hold both keys directly.
    let dsse_envelope = crate::bilateral_dsse::sign_dsse_envelope(
        &receipt,
        origin_keypair,
        tool_host_keypair,
        origin_kernel_id,
        tool_host_kernel_id,
        tool_name,
        timestamp_unix_ms,
    )?;

    Ok(BilateralCoSignArtifacts {
        dual_signed_receipt: dual,
        dsse_envelope,
    })
}
