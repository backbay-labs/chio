use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::crypto::{
    canonical_json_bytes, is_default_optional_algorithm, sha256_hex, sign_canonical_with_backend,
    Keypair, PublicKey, Signature, SigningAlgorithm, SigningBackend,
};
use crate::error::{Error, Result};
use crate::signer_binding::{
    ensure_backend_matches_embedded_key, ensure_keypair_matches_embedded_key,
};

use super::crypto_floor::{
    ensure_receipt_signature_algorithm_allowed, ReceiptCryptoFloor, ReceiptFloorVerifyError,
};
use super::decision::{Decision, ToolCallAction};
use super::economics::{FinancialBudgetAuthorityReceiptMetadata, FinancialReceiptMetadata};
use super::kinds::{
    BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
};
use super::metadata::{ActorRef, GuardEvidence, ReceiptSemanticFields};
use super::signing::{
    bind_receipt_signing_nonce, validate_bbs_receipt_binding, BbsReceiptSignature,
    ChioReceiptSigningBody, ReceiptSigningHandle,
};

/// Current signed receipt schema.
pub const CHIO_RECEIPT_SCHEMA: &str = "chio.receipt.v1";

/// A Chio receipt. Signed proof that a tool call was evaluated by the Kernel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChioReceipt {
    /// Content-addressed receipt ID derived from the canonical receipt body.
    pub id: String,
    /// Unix timestamp (seconds) when the receipt was created.
    pub timestamp: u64,
    /// ID of the capability token that was exercised (or presented).
    pub capability_id: String,
    /// Tool server that handled the invocation.
    pub tool_server: String,
    /// Tool that was invoked (or attempted).
    pub tool_name: String,
    /// The action that was evaluated.
    pub action: ToolCallAction,
    /// The Kernel's decision. Present only for mediated decisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    /// Signed receipt semantic kind.
    pub receipt_kind: ReceiptKind,
    /// Signed runtime boundary class.
    pub boundary_class: BoundaryClass,
    /// Signed observation outcome for trace and advisory records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation_outcome: Option<ObservationOutcome>,
    /// Signed tool-origin classification.
    pub tool_origin: ToolOrigin,
    /// Signed redaction mode.
    pub redaction_mode: RedactionMode,
    /// Signed actor attribution chain.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actor_chain: Vec<ActorRef>,
    /// SHA-256 hash of the evaluated content for this receipt.
    pub content_hash: String,
    /// SHA-256 hash of the policy that was applied.
    pub policy_hash: String,
    /// Per-guard evidence collected during evaluation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<GuardEvidence>,
    /// Optional receipt metadata for stream/accounting details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    /// Strength of kernel mediation that produced this receipt.
    pub trust_level: TrustLevel,
    /// Multi-tenant receipt isolation: tenant identifier for
    /// multi-tenant deployments. `None` in single-tenant mode; derived
    /// from the authenticated session's enterprise identity context and
    /// MUST NOT be taken from caller-provided request fields (caller
    /// choice would defeat the isolation intent).
    ///
    /// Serialized only when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// BBS projection version bound into the receipt id when BBS material is
    /// present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bbs_projection_version: Option<String>,
    /// The Kernel's public key (for verification without out-of-band lookup).
    pub kernel_key: PublicKey,
    /// Optional BBS material for selective disclosure over this receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bbs_signature: Option<BbsReceiptSignature>,
    /// Signing algorithm used for [`ChioReceipt::signature`]. Informational
    /// only: verification dispatches off the self-describing encoding of the
    /// signature itself.
    #[serde(default, skip_serializing_if = "is_default_optional_algorithm")]
    pub algorithm: Option<SigningAlgorithm>,
    /// Signature over canonical JSON of [`ChioReceiptSigningBody`].
    pub signature: Signature,
}

/// The body of a receipt (everything except the signature), used for signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChioReceiptBody {
    pub id: String,
    pub timestamp: u64,
    pub capability_id: String,
    pub tool_server: String,
    pub tool_name: String,
    pub action: ToolCallAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    pub receipt_kind: ReceiptKind,
    pub boundary_class: BoundaryClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation_outcome: Option<ObservationOutcome>,
    pub tool_origin: ToolOrigin,
    pub redaction_mode: RedactionMode,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actor_chain: Vec<ActorRef>,
    pub content_hash: String,
    pub policy_hash: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<GuardEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub trust_level: TrustLevel,
    /// Tenant id on the canonical signing body. Omitted from canonical JSON
    /// when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub kernel_key: PublicKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bbs_projection_version: Option<String>,
}

impl ChioReceiptBody {
    /// Derive v1 receipt semantics for this signing body.
    #[must_use]
    pub fn semantic_fields(&self) -> ReceiptSemanticFields {
        ReceiptSemanticFields {
            receipt_kind: self.receipt_kind,
            boundary_class: self.boundary_class,
            observation_outcome: self.observation_outcome,
            tool_origin: self.tool_origin,
            redaction_mode: self.redaction_mode,
            actor_chain: self.actor_chain.clone(),
        }
    }

    /// Validate receipt semantics before signing.
    pub fn validate_signable_semantics(&self) -> Result<()> {
        let semantics = self.semantic_fields();
        semantics.validate_decision(self.decision.as_ref())?;
        let expected_trust = match semantics.receipt_kind {
            ReceiptKind::MediatedDecision => TrustLevel::Mediated,
            ReceiptKind::TraceObservation => TrustLevel::Verified,
            ReceiptKind::AdvisoryEvaluation => TrustLevel::Advisory,
        };
        if self.trust_level != expected_trust {
            return Err(Error::CanonicalJson(format!(
                "{} receipts require trust_level {}",
                semantics.receipt_kind.as_str(),
                expected_trust.as_str()
            )));
        }
        Ok(())
    }
}

/// Receipt fields that define the authoritative receipt id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChioReceiptIdInput {
    pub timestamp: u64,
    pub capability_id: String,
    pub tool_server: String,
    pub tool_name: String,
    pub action: ToolCallAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    pub receipt_kind: ReceiptKind,
    pub boundary_class: BoundaryClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation_outcome: Option<ObservationOutcome>,
    pub tool_origin: ToolOrigin,
    pub redaction_mode: RedactionMode,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actor_chain: Vec<ActorRef>,
    pub content_hash: String,
    pub policy_hash: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<GuardEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub trust_level: TrustLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub kernel_key: PublicKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bbs_projection_version: Option<String>,
}

impl From<&ChioReceiptBody> for ChioReceiptIdInput {
    fn from(body: &ChioReceiptBody) -> Self {
        Self {
            timestamp: body.timestamp,
            capability_id: body.capability_id.clone(),
            tool_server: body.tool_server.clone(),
            tool_name: body.tool_name.clone(),
            action: body.action.clone(),
            decision: body.decision.clone(),
            receipt_kind: body.receipt_kind,
            boundary_class: body.boundary_class,
            observation_outcome: body.observation_outcome,
            tool_origin: body.tool_origin,
            redaction_mode: body.redaction_mode,
            actor_chain: body.actor_chain.clone(),
            content_hash: body.content_hash.clone(),
            policy_hash: body.policy_hash.clone(),
            evidence: body.evidence.clone(),
            metadata: body.metadata.clone(),
            trust_level: body.trust_level,
            tenant_id: body.tenant_id.clone(),
            kernel_key: body.kernel_key.clone(),
            bbs_projection_version: body.bbs_projection_version.clone(),
        }
    }
}

/// Compute the authoritative receipt id from canonical receipt body fields.
pub fn chio_receipt_id(body: &ChioReceiptBody) -> Result<String> {
    let input = ChioReceiptIdInput::from(body);
    let canonical = canonical_json_bytes(&input)?;
    Ok(sha256_hex(&canonical))
}

/// Validate, bind the caller nonce, and compute the authoritative receipt id.
pub fn prepare_receipt_body_for_signing(mut body: ChioReceiptBody) -> Result<ChioReceiptBody> {
    body.validate_signable_semantics()?;
    bind_receipt_signing_nonce(&mut body);
    body.id = chio_receipt_id(&body)?;
    Ok(body)
}

impl ChioReceipt {
    fn from_signed_body(
        body: ChioReceiptBody,
        bbs_signature: Option<BbsReceiptSignature>,
        algorithm: Option<SigningAlgorithm>,
        signature: Signature,
    ) -> Self {
        Self {
            id: body.id,
            timestamp: body.timestamp,
            capability_id: body.capability_id,
            tool_server: body.tool_server,
            tool_name: body.tool_name,
            action: body.action,
            decision: body.decision,
            receipt_kind: body.receipt_kind,
            boundary_class: body.boundary_class,
            observation_outcome: body.observation_outcome,
            tool_origin: body.tool_origin,
            redaction_mode: body.redaction_mode,
            actor_chain: body.actor_chain,
            content_hash: body.content_hash,
            policy_hash: body.policy_hash,
            evidence: body.evidence,
            metadata: body.metadata,
            trust_level: body.trust_level,
            tenant_id: body.tenant_id,
            bbs_projection_version: body.bbs_projection_version,
            kernel_key: body.kernel_key,
            bbs_signature,
            algorithm,
            signature,
        }
    }

    /// Sign a receipt body with the Kernel's Ed25519 keypair.
    pub fn sign(body: ChioReceiptBody, keypair: &Keypair) -> Result<Self> {
        validate_bbs_receipt_binding(&body, None)?;
        ensure_keypair_matches_embedded_key(&body.kernel_key, keypair, "receipt", "kernel_key")?;
        let body = prepare_receipt_body_for_signing(body)?;
        let signing_body = ChioReceiptSigningBody::from(&body);
        let (signature, _bytes) = keypair.sign_canonical(&signing_body)?;
        Ok(Self::from_signed_body(body, None, None, signature))
    }

    /// Sign a receipt body with an arbitrary [`SigningBackend`].
    ///
    /// The `body.kernel_key` must equal `backend.public_key()`.
    pub fn sign_with_backend(body: ChioReceiptBody, backend: &dyn SigningBackend) -> Result<Self> {
        validate_bbs_receipt_binding(&body, None)?;
        ensure_backend_matches_embedded_key(&body.kernel_key, backend, "receipt", "kernel_key")?;
        let body = prepare_receipt_body_for_signing(body)?;
        let signing_body = ChioReceiptSigningBody::from(&body);
        let (signature, _bytes) = sign_canonical_with_backend(backend, &signing_body)?;
        Ok(Self::from_signed_body(
            body,
            None,
            Some(backend.algorithm()),
            signature,
        ))
    }

    /// WYSIWYS receipt signing: recompute `content_hash` inside the trust
    /// boundary and refuse to sign if the body's claimed hash differs.
    ///
    /// The `handle` is a one-time [`ReceiptSigningHandle`] bound to a specific
    /// evaluated artifact's canonical content. The signer recomputes
    /// `content_hash` over that content and consumes the handle by value, so a
    /// signature produced here corresponds to *that* content -- not to an
    /// arbitrary caller-supplied `content_hash`. This closes the render-A /
    /// sign-B class of forgeries.
    ///
    /// # Errors
    ///
    /// Returns an error (fail-closed) when the body's `content_hash` does not
    /// equal the hash recomputed over the handle's content, when the BBS
    /// binding is invalid, when `body.kernel_key` does not match `keypair`, or
    /// when canonical signing fails.
    pub fn sign_with_handle(
        body: ChioReceiptBody,
        keypair: &Keypair,
        handle: ReceiptSigningHandle,
    ) -> Result<Self> {
        // Recompute-and-refuse FIRST, before any signing work, so a hash
        // mismatch can never produce a signature. `handle` is moved in and not
        // used afterwards, enforcing one-time consumption per signature.
        handle.ensure_body_matches(&body)?;
        Self::sign(body, keypair)
    }

    /// WYSIWYS receipt signing via an arbitrary [`SigningBackend`].
    ///
    /// Behaves like [`ChioReceipt::sign_with_handle`] but routes the signing
    /// step through a [`SigningBackend`] (the FIPS-capable / platform-keystore
    /// path used by the WASM and mobile adapters). The `content_hash` recompute
    /// + refuse-on-mismatch gate runs identically before any signing work.
    ///
    /// # Errors
    ///
    /// Returns an error (fail-closed) when the body's `content_hash` does not
    /// equal the hash recomputed over the handle's content, when the BBS
    /// binding is invalid, when `body.kernel_key` does not match
    /// `backend.public_key()`, or when canonical signing fails.
    pub fn sign_with_backend_using_handle(
        body: ChioReceiptBody,
        backend: &dyn SigningBackend,
        handle: ReceiptSigningHandle,
    ) -> Result<Self> {
        handle.ensure_body_matches(&body)?;
        Self::sign_with_backend(body, backend)
    }

    /// Sign a receipt body while binding already-produced BBS material into
    /// the authoritative receipt signature.
    pub fn sign_with_bbs(
        body: ChioReceiptBody,
        keypair: &Keypair,
        bbs_signature: BbsReceiptSignature,
    ) -> Result<Self> {
        validate_bbs_receipt_binding(&body, Some(&bbs_signature))?;
        ensure_keypair_matches_embedded_key(&body.kernel_key, keypair, "receipt", "kernel_key")?;
        let body = prepare_receipt_body_for_signing(body)?;
        let signing_body = ChioReceiptSigningBody::from_body_and_bbs(&body, Some(&bbs_signature));
        let (signature, _bytes) = keypair.sign_canonical(&signing_body)?;
        Ok(Self::from_signed_body(
            body,
            Some(bbs_signature),
            None,
            signature,
        ))
    }

    /// Sign a body that has already had its nonce bound and receipt id
    /// computed. This is for producers that must project the final receipt
    /// body before producing BBS material.
    pub fn sign_prepared_with_bbs(
        body: ChioReceiptBody,
        keypair: &Keypair,
        bbs_signature: BbsReceiptSignature,
    ) -> Result<Self> {
        body.validate_signable_semantics()?;
        validate_bbs_receipt_binding(&body, Some(&bbs_signature))?;
        ensure_keypair_matches_embedded_key(&body.kernel_key, keypair, "receipt", "kernel_key")?;
        let expected_id = chio_receipt_id(&body)?;
        if body.id != expected_id {
            return Err(Error::CanonicalJson(
                "prepared receipt body id does not match canonical receipt id".to_string(),
            ));
        }
        let signing_body = ChioReceiptSigningBody::from_body_and_bbs(&body, Some(&bbs_signature));
        let (signature, _bytes) = keypair.sign_canonical(&signing_body)?;
        Ok(Self::from_signed_body(
            body,
            Some(bbs_signature),
            None,
            signature,
        ))
    }

    /// WYSIWYS BBS receipt signing: recompute `content_hash` inside the trust
    /// boundary and refuse to sign if the prepared body's claimed hash differs.
    ///
    /// This is the BBS/selective-disclosure analogue of
    /// [`ChioReceipt::sign_with_handle`]. The classical and backend handle
    /// signers recompute `content_hash` over a one-time
    /// [`ReceiptSigningHandle`] and refuse on mismatch; the older
    /// [`ChioReceipt::sign_prepared_with_bbs`] entrypoint does not recompute
    /// `content_hash`. This entrypoint signs only after the recompute matches.
    ///
    /// The `handle` is bound to the exact canonical content the producer
    /// evaluated. The signer recomputes `content_hash` over that content and
    /// consumes the handle by value, so a BBS signature produced here
    /// corresponds to *that* content, not an arbitrary caller-supplied
    /// `content_hash`. `prepare_receipt_body_for_signing` does not mutate
    /// `content_hash` (it only binds the nonce and computes the id), so the
    /// gate runs identically whether the body is checked before or after
    /// preparation.
    ///
    /// # Errors
    ///
    /// Returns an error (fail-closed) when the body's `content_hash` does not
    /// equal the hash recomputed over the handle's content, or for any error
    /// surfaced by [`ChioReceipt::sign_prepared_with_bbs`].
    pub fn sign_prepared_with_bbs_using_handle(
        body: ChioReceiptBody,
        keypair: &Keypair,
        bbs_signature: BbsReceiptSignature,
        handle: ReceiptSigningHandle,
    ) -> Result<Self> {
        // Recompute-and-refuse FIRST, before any signing work, so a hash
        // mismatch can never produce a BBS-bound signature. `handle` is moved
        // in and not used afterwards, enforcing one-time consumption.
        handle.ensure_body_matches(&body)?;
        Self::sign_prepared_with_bbs(body, keypair, bbs_signature)
    }

    /// Extract the body for re-verification.
    #[must_use]
    pub fn body(&self) -> ChioReceiptBody {
        ChioReceiptBody {
            id: self.id.clone(),
            timestamp: self.timestamp,
            capability_id: self.capability_id.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            action: self.action.clone(),
            decision: self.decision.clone(),
            receipt_kind: self.receipt_kind,
            boundary_class: self.boundary_class,
            observation_outcome: self.observation_outcome,
            tool_origin: self.tool_origin,
            redaction_mode: self.redaction_mode,
            actor_chain: self.actor_chain.clone(),
            content_hash: self.content_hash.clone(),
            policy_hash: self.policy_hash.clone(),
            evidence: self.evidence.clone(),
            metadata: self.metadata.clone(),
            trust_level: self.trust_level,
            tenant_id: self.tenant_id.clone(),
            kernel_key: self.kernel_key.clone(),
            bbs_projection_version: self.bbs_projection_version.clone(),
        }
    }

    /// Verify the receipt signature against the embedded kernel key.
    pub fn verify_signature(&self) -> Result<bool> {
        let body = self.body();
        if body.validate_signable_semantics().is_err() {
            return Ok(false);
        }
        if validate_bbs_receipt_binding(&body, self.bbs_signature.as_ref()).is_err() {
            return Ok(false);
        }
        if chio_receipt_id(&body)? != self.id {
            return Ok(false);
        }
        let signing_body =
            ChioReceiptSigningBody::from_body_and_bbs(&body, self.bbs_signature.as_ref());
        self.kernel_key
            .verify_canonical(&signing_body, &self.signature)
    }

    /// Verify the receipt signature and enforce the configured crypto floor.
    ///
    /// Verification dispatches off `Signature::algorithm()`:
    ///
    /// - [`SigningAlgorithm::Hybrid`] receipts are accepted under
    ///   [`ReceiptCryptoFloor::AllowHybrid`] and
    ///   [`ReceiptCryptoFloor::PqRequired`] and rejected under
    ///   [`ReceiptCryptoFloor::AllowClassical`].
    /// - Classical receipts (Ed25519 / P-256 / P-384) are accepted under
    ///   [`ReceiptCryptoFloor::AllowClassical`] and
    ///   [`ReceiptCryptoFloor::AllowHybrid`] and rejected under
    ///   [`ReceiptCryptoFloor::PqRequired`].
    ///
    /// The floor check runs before the cryptographic verification step so
    /// policy-bearing verifiers can record downgrade attempts distinctly from
    /// malformed or forged signatures.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptFloorVerifyError::RejectedByCryptoFloor`] when the
    /// signature algorithm violates the floor.
    /// [`ReceiptFloorVerifyError::AlgorithmMismatch`] when the envelope field
    /// disagrees with the signature material.
    /// [`ReceiptFloorVerifyError::Crypto`] when canonical re-serialization or
    /// signature verification returns an error.
    pub fn verify_signature_with_floor(
        &self,
        floor: ReceiptCryptoFloor,
    ) -> core::result::Result<bool, ReceiptFloorVerifyError> {
        let signature_algorithm = self.signature.algorithm();
        ensure_receipt_signature_algorithm_allowed(self.algorithm, signature_algorithm, floor)?;

        self.verify_signature()
            .map_err(ReceiptFloorVerifyError::Crypto)
    }

    /// Derive v1 receipt semantics for display, SIEM, and bridge gates.
    #[must_use]
    pub fn semantic_fields(&self) -> ReceiptSemanticFields {
        ReceiptSemanticFields {
            receipt_kind: self.receipt_kind,
            boundary_class: self.boundary_class,
            observation_outcome: self.observation_outcome,
            tool_origin: self.tool_origin,
            redaction_mode: self.redaction_mode,
            actor_chain: self.actor_chain.clone(),
        }
    }

    /// Whether this receipt records an allow decision.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        self.trust_level == TrustLevel::Mediated
            && self.semantic_fields().is_authorized(self.decision.as_ref())
    }

    /// Whether this receipt records a deny decision.
    #[must_use]
    pub fn is_denied(&self) -> bool {
        matches!(self.decision, Some(Decision::Deny { .. }))
    }

    /// Whether this receipt records a cancelled terminal outcome.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        matches!(self.decision, Some(Decision::Cancelled { .. }))
    }

    /// Whether this receipt records an incomplete terminal outcome.
    #[must_use]
    pub fn is_incomplete(&self) -> bool {
        matches!(self.decision, Some(Decision::Incomplete { .. }))
    }

    fn typed_metadata<T>(&self, key: &str) -> Option<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        self.metadata
            .as_ref()
            .and_then(|metadata| metadata.get(key))
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok())
    }

    /// Extract typed financial receipt metadata when present.
    #[must_use]
    pub fn financial_metadata(&self) -> Option<FinancialReceiptMetadata> {
        self.typed_metadata("financial")
    }

    /// Extract typed budget-authority lineage for monetary receipts when present.
    #[must_use]
    pub fn financial_budget_authority_metadata(
        &self,
    ) -> Option<FinancialBudgetAuthorityReceiptMetadata> {
        self.typed_metadata("budget_authority")
    }
}
