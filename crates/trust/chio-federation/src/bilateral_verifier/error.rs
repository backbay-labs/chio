use super::*;

// ---------------------------------------------------------------------------
// Spec §7.1 error codes
// ---------------------------------------------------------------------------

/// Fail-closed error codes returned by [`verify_bilateral_cosign_invocation`].
/// Each exposed variant maps verbatim to a spec §7.1 code (the `Display`
/// impl emits the code itself); kernels that surface verifier output in
/// receipts SHOULD log the code as the canonical value. Strict Chio
/// ordered and quorum consistency claims are accepted only by strict
/// treaty-bound Chio predicates that carry matching treaty refs and an
/// explicit consistency anchor.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum VerifierError {
    /// `dsse.malformed` - envelope JSON is not parseable, payloadType
    /// mismatched, or signatures count != expected for the cosign mode.
    #[error("dsse.malformed: {0}")]
    DsseMalformed(String),
    /// `statement.malformed` - Statement payload is not parseable JSON.
    #[error("statement.malformed: {0}")]
    StatementMalformed(String),
    /// `statement.schema_invalid` - Statement does not satisfy in-toto v1 schema.
    #[error("statement.schema_invalid: {0}")]
    StatementSchemaInvalid(String),
    /// `predicate.type_unrecognised` - predicateType is neither the proposed
    /// in-toto URI nor the chio-namespaced fallback.
    #[error("predicate.type_unrecognised: {0}")]
    PredicateTypeUnrecognised(String),
    #[error("predicate.schema_invalid: {0}")]
    PredicateSchemaInvalid(String),
    /// `subject.digest_mismatch` - subject SHA-256 does not match the
    /// resolved receipt body's canonical-JSON.
    #[error("subject.digest_mismatch: {0}")]
    SubjectDigestMismatch(String),
    /// `peer.unpinned_or_keyid_mismatch` - either kernel identity is not
    /// pinned in the verifier's peer set, or its declared fingerprint
    /// disagrees with the pinned passport.
    #[error("peer.unpinned_or_keyid_mismatch: {0}")]
    PeerUnpinnedOrKeyidMismatch(String),
    /// `peer.revoked_at_epoch` - a participating kernel's passport is
    /// revoked at the pinned epoch.
    #[error("peer.revoked_at_epoch: {0}")]
    PeerRevokedAtEpoch(String),
    /// `signature.server_a_invalid` - tool_server_a's signature does not
    /// verify under its passport key.
    #[error("signature.server_a_invalid: {0}")]
    SignatureServerAInvalid(String),
    /// `signature.server_b_invalid` - tool_server_b's signature does not
    /// verify under its passport key.
    #[error("signature.server_b_invalid: {0}")]
    SignatureServerBInvalid(String),
    /// `policy.verdict_disagreement` - verdicts disagree, or
    /// joint_disposition is inconsistent.
    #[error("policy.verdict_disagreement: {0}")]
    PolicyVerdictDisagreement(String),
    /// `capability.lease_expired_or_unknown` - the named capability lease
    /// cannot be resolved or is past its `expires_at_unix_ms`.
    #[error("capability.lease_expired_or_unknown: {0}")]
    CapabilityLeaseExpiredOrUnknown(String),
    /// `governance.receipt_required_missing` - a receipt-backed class
    /// lacks a `governance_receipt_ref`.
    #[error("governance.receipt_required_missing: {0}")]
    GovernanceReceiptRequiredMissing(String),
    /// `ladder.manifest_missing` - strict Chio verification requires
    /// a signed ladder manifest reference for every participating peer.
    #[error("ladder.manifest_missing: {0}")]
    LadderManifestMissing(String),
    /// `ladder.manifest_stale` - the pinned ladder manifest reference
    /// is not live at the verifier's pinned epoch.
    #[error("ladder.manifest_stale: {0}")]
    LadderManifestStale(String),
    /// Fail-closed action-class invariant: `governance.unknown_action_class`.
    /// The predicate's `tool_name` is not registered in the verifier's
    /// `action_classes` table. Strict mode requires explicit registration:
    /// falling back to `Routine` (no governance receipt required) for an
    /// unregistered tool is fail-OPEN for receipt-backed classes that were
    /// misspelled or omitted from the registry.
    #[error("governance.unknown_action_class: {tool_name:?}")]
    UnknownActionClass { tool_name: String },
}

impl VerifierError {
    /// The bare spec code (e.g. `"subject.digest_mismatch"`), without
    /// the trailing context. Stable across releases.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::DsseMalformed(_) => "dsse.malformed",
            Self::StatementMalformed(_) => "statement.malformed",
            Self::StatementSchemaInvalid(_) => "statement.schema_invalid",
            Self::PredicateTypeUnrecognised(_) => "predicate.type_unrecognised",
            Self::PredicateSchemaInvalid(_) => "predicate.schema_invalid",
            Self::SubjectDigestMismatch(_) => "subject.digest_mismatch",
            Self::PeerUnpinnedOrKeyidMismatch(_) => "peer.unpinned_or_keyid_mismatch",
            Self::PeerRevokedAtEpoch(_) => "peer.revoked_at_epoch",
            Self::SignatureServerAInvalid(_) => "signature.server_a_invalid",
            Self::SignatureServerBInvalid(_) => "signature.server_b_invalid",
            Self::PolicyVerdictDisagreement(_) => "policy.verdict_disagreement",
            Self::CapabilityLeaseExpiredOrUnknown(_) => "capability.lease_expired_or_unknown",
            Self::GovernanceReceiptRequiredMissing(_) => "governance.receipt_required_missing",
            Self::LadderManifestMissing(_) => "ladder.manifest_missing",
            Self::LadderManifestStale(_) => "ladder.manifest_stale",
            Self::UnknownActionClass { .. } => "governance.unknown_action_class",
        }
    }
}

impl From<BilateralCoSigningError> for VerifierError {
    fn from(e: BilateralCoSigningError) -> Self {
        map_bilateral_error(e)
    }
}

pub(super) fn map_bilateral_error(error: BilateralCoSigningError) -> VerifierError {
    match error {
        BilateralCoSigningError::OrgASignatureInvalid => VerifierError::SignatureServerAInvalid(
            "PAE re-derivation under tool_server_a passport key failed".to_string(),
        ),
        BilateralCoSigningError::OrgBSignatureInvalid => VerifierError::SignatureServerBInvalid(
            "PAE re-derivation under tool_server_b passport key failed".to_string(),
        ),
        BilateralCoSigningError::ReceiptMismatch => VerifierError::SubjectDigestMismatch(
            "embedded receipt does not match the signed subject or resolved receipt".to_string(),
        ),
        BilateralCoSigningError::CanonicalJson(message) => {
            if message.starts_with("statement.malformed: subject name") {
                VerifierError::SubjectDigestMismatch(message)
            } else if message.starts_with("predicate.schema_invalid: server_a=")
                || message.starts_with("predicate.schema_invalid: unsupported verdict")
                || message.contains("requires allow verdict for admission")
                || message.contains("policy_id must be non-empty")
                || message.contains("policy_version must be non-empty")
                || message.contains("joint_disposition=")
            {
                VerifierError::PolicyVerdictDisagreement(message)
            } else if message.starts_with("payload json:")
                || message.starts_with("statement.malformed")
                || message.contains("not canonical JSON")
            {
                VerifierError::StatementMalformed(message)
            } else if message.starts_with("statement.schema_invalid") {
                VerifierError::StatementSchemaInvalid(message)
            } else if message.starts_with("predicate.type_unrecognised") {
                VerifierError::PredicateTypeUnrecognised(message)
            } else if message.starts_with("predicate.schema_invalid") {
                VerifierError::PredicateSchemaInvalid(message)
            } else if message.starts_with("subject.digest_mismatch") {
                VerifierError::SubjectDigestMismatch(message)
            } else {
                VerifierError::DsseMalformed(message)
            }
        }
        other => VerifierError::DsseMalformed(other.to_string()),
    }
}
