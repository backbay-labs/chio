use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::{sha256_hex, Keypair, PublicKey, Signature};
use serde::{Deserialize, Serialize};

use crate::obligation::{
    ObligationAtomV1, ObligationDispositionRecordV1, ObligationDispositionV1, ObligationError,
};

mod abort;
mod engine;
mod finalization;
mod lifecycle;

pub use abort::*;
pub use engine::{
    compute_netting_round, sign_netting_round, verify_netting_round, verify_signed_netting_round,
};
pub use finalization::*;
pub use lifecycle::*;

pub const CLEARING_ALGORITHM_V1: &str = "balance_match.v1";
pub const CLEARING_PARTICIPANT_SNAPSHOT_SCHEMA: &str = "chio.clearing.participant-snapshot.v1";
pub const CLEARING_PARTICIPANT_SNAPSHOT_ACKNOWLEDGEMENT_SCHEMA: &str =
    "chio.clearing.participant-snapshot-acknowledgement.v1";
pub const CLEARING_INPUT_MANIFEST_SCHEMA: &str = "chio.clearing.input-manifest.v1";
pub const CLEARING_ROUND_CORE_SCHEMA: &str = "chio.clearing.netting-round-core.v1";
pub const CLEARING_PARTICIPANT_STATEMENT_SCHEMA: &str = "chio.clearing.participant-statement.v1";
pub const CLEARING_SETTLEMENT_INTENT_SCHEMA: &str = "chio.clearing.settlement-intent.v1";
pub const CLEARING_TRANSFORMATION_SCHEMA: &str = "chio.clearing.atom-transformation.v1";
pub const CLEARING_OUTPUT_MANIFEST_SCHEMA: &str = "chio.clearing.output-manifest.v1";
pub const CLEARING_PARTICIPANT_ACCEPTANCE_SCHEMA: &str = "chio.clearing.participant-acceptance.v1";
pub const CLEARING_ROUND_FINALIZATION_SCHEMA: &str = "chio.clearing.round-finalization.v1";
pub const CLEARING_ZERO_DISPATCH_PROOF_SCHEMA: &str = "chio.clearing.zero-dispatch-proof.v1";
pub const CLEARING_ROUND_ABORT_SCHEMA: &str = "chio.clearing.round-abort.v1";

pub(super) const MAX_CLEARING_INPUTS: usize =
    chio_core_types::economic_continuity::MAX_ECONOMIC_TRANSITIONS - 2;
pub(super) const MAX_CLEARING_SETTLEMENT_INTENTS: usize = MAX_CLEARING_INPUTS * 2 - 1;
pub(super) const MAX_CLEARING_PARTICIPANTS: usize = 1_024;
pub(super) const MAX_CLEARING_IDENTITIES_PER_PARTICIPANT: usize = 64;
pub(super) const MAX_TEXT_BYTES: usize = 2_048;
pub(super) const I_JSON_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;
pub(super) const SNAPSHOT_DIGEST_DOMAIN: &[u8] = b"chio.clearing.participant-snapshot.digest.v1\0";
pub(super) const INPUT_MANIFEST_DIGEST_DOMAIN: &[u8] = b"chio.clearing.input-manifest.digest.v1\0";
pub(super) const ROUND_CORE_DIGEST_DOMAIN: &[u8] = b"chio.clearing.round-core.digest.v1\0";
pub(super) const STATEMENT_DIGEST_DOMAIN: &[u8] = b"chio.clearing.statement.digest.v1\0";
pub(super) const INTENT_DIGEST_DOMAIN: &[u8] = b"chio.clearing.intent.digest.v1\0";
pub(super) const TRANSFORMATION_DIGEST_DOMAIN: &[u8] = b"chio.clearing.transformation.digest.v1\0";
pub(super) const OUTPUT_MANIFEST_DIGEST_DOMAIN: &[u8] =
    b"chio.clearing.output-manifest.digest.v1\0";
pub(super) const RESERVATION_ROOT_DOMAIN: &[u8] = b"chio.clearing.reservation-root.v1\0";
pub(super) const STATEMENT_ROOT_DOMAIN: &[u8] = b"chio.clearing.statement-root.v1\0";
pub(super) const INTENT_ROOT_DOMAIN: &[u8] = b"chio.clearing.intent-root.v1\0";
pub(super) const TRANSFORMATION_ROOT_DOMAIN: &[u8] = b"chio.clearing.transformation-root.v1\0";
pub(super) const INTENT_ID_DOMAIN: &[u8] = b"chio.clearing.intent.id.v1\0";
pub(super) const DISPATCH_KEY_DOMAIN: &[u8] = b"chio.clearing.dispatch-key.v1\0";
pub(super) const SIGNED_ENVELOPE_DIGEST_DOMAIN: &[u8] =
    b"chio.clearing.signed-envelope.digest.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedClearingEnvelopeV1<T> {
    pub body: T,
    pub signer_key: PublicKey,
    pub signature: Signature,
}

impl<T> SignedClearingEnvelopeV1<T>
where
    T: Serialize + Clone,
{
    pub fn sign(body: T, keypair: &Keypair) -> Result<Self, ClearingError> {
        let (signature, _) = keypair
            .sign_canonical(&body)
            .map_err(|error| ClearingError::Canonicalization(error.to_string()))?;
        Ok(Self {
            body,
            signer_key: keypair.public_key(),
            signature,
        })
    }

    pub fn verify_signature(&self) -> Result<bool, ClearingError> {
        self.signer_key
            .verify_canonical(&self.body, &self.signature)
            .map_err(|_| ClearingError::AuthorityVerification)
    }

    pub fn digest(&self) -> Result<String, ClearingError> {
        domain_digest(SIGNED_ENVELOPE_DIGEST_DOMAIN, self)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClearingError {
    #[error("invalid clearing field `{0}`")]
    InvalidField(&'static str),
    #[error("clearing authority verification failed")]
    AuthorityVerification,
    #[error("clearing input manifest is incomplete")]
    IncompleteManifest,
    #[error("duplicate clearing obligation")]
    DuplicateObligation,
    #[error("clearing input currency does not match the round")]
    CurrencyMismatch,
    #[error("clearing participant identity is unresolved or ambiguous: {0}")]
    ParticipantIdentity(String),
    #[error("clearing arithmetic overflow")]
    ArithmeticOverflow,
    #[error("illegal clearing lifecycle transition")]
    IllegalLifecycleTransition,
    #[error("clearing lifecycle projection is incomplete")]
    IncompleteLifecycleProjection,
    #[error("clearing obligation invalid: {0}")]
    Obligation(#[from] ObligationError),
    #[error("clearing canonicalization failed: {0}")]
    Canonicalization(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearingAuthorityTrustV1 {
    pub clearing_authority_id: String,
    pub clearing_authority_key: PublicKey,
    pub clearing_authority_key_epoch: u64,
    pub participant_authority_id: String,
    pub participant_authority_key: PublicKey,
    pub participant_key_epoch: u64,
    pub obligation_authority_id: String,
    pub obligation_authority_key: PublicKey,
    pub obligation_key_epoch: u64,
    pub trusted_time_unix_ms: u64,
}

impl ClearingAuthorityTrustV1 {
    pub(super) fn validate(&self) -> Result<(), ClearingError> {
        validate_text("clearing_authority_id", &self.clearing_authority_id)?;
        validate_positive(
            "clearing_authority_key_epoch",
            self.clearing_authority_key_epoch,
        )?;
        validate_text("participant_authority_id", &self.participant_authority_id)?;
        validate_positive("participant_key_epoch", self.participant_key_epoch)?;
        validate_text("obligation_authority_id", &self.obligation_authority_id)?;
        validate_positive("obligation_key_epoch", self.obligation_key_epoch)?;
        validate_positive("trusted_time_unix_ms", self.trusted_time_unix_ms)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingParticipantBindingV1 {
    pub participant_id: String,
    pub identities: Vec<String>,
    pub settlement_destination: String,
    pub acknowledgement_key: PublicKey,
    pub acknowledgement_key_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingParticipantSnapshotBodyV1 {
    pub schema: String,
    pub authority_id: String,
    pub key_epoch: u64,
    pub algorithm_version: String,
    pub valid_from_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub participants: Vec<ClearingParticipantBindingV1>,
}

pub type SignedClearingParticipantSnapshotV1 =
    SignedClearingEnvelopeV1<ClearingParticipantSnapshotBodyV1>;

impl ClearingParticipantSnapshotBodyV1 {
    pub fn digest(&self) -> Result<String, ClearingError> {
        domain_digest(SNAPSHOT_DIGEST_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingParticipantSnapshotAcknowledgementBodyV1 {
    pub schema: String,
    pub participant_snapshot_digest: String,
    pub participant_id: String,
    pub algorithm_version: String,
    pub key_epoch: u64,
    pub accepted_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

pub type SignedClearingParticipantSnapshotAcknowledgementV1 =
    SignedClearingEnvelopeV1<ClearingParticipantSnapshotAcknowledgementBodyV1>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingObligationInputV1 {
    pub source_sequence: u64,
    pub atom: ObligationAtomV1,
    pub disposition: ObligationDispositionRecordV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingInputManifestEntryV1 {
    pub source_sequence: u64,
    pub obligation_id: String,
    pub atom_digest: String,
    pub disposition_digest: String,
    pub disposition_version: u64,
    pub lifecycle_fence: u64,
    pub round_id: String,
}

impl ClearingInputManifestEntryV1 {
    pub fn from_reserved(input: &ClearingObligationInputV1) -> Result<Self, ClearingError> {
        input.atom.validate()?;
        input.disposition.validate_against(&input.atom)?;
        validate_positive("source_sequence", input.source_sequence)?;
        let round_id = match input.disposition.disposition() {
            ObligationDispositionV1::ClearingReserved { round_id } => round_id.clone(),
            _ => return Err(ClearingError::InvalidField("obligation_disposition")),
        };
        Ok(Self {
            source_sequence: input.source_sequence,
            obligation_id: input.atom.obligation_id().to_owned(),
            atom_digest: input.atom.digest()?,
            disposition_digest: input.disposition.digest(&input.atom)?,
            disposition_version: input.disposition.version(),
            lifecycle_fence: input.disposition.lifecycle_fence(),
            round_id,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingInputManifestBodyV1 {
    pub schema: String,
    pub authority_id: String,
    pub key_epoch: u64,
    pub source_id: String,
    pub epoch: u64,
    pub range_start_sequence: u64,
    pub range_end_sequence: u64,
    pub start_checkpoint_digest: String,
    pub end_checkpoint_digest: String,
    pub entries: Vec<ClearingInputManifestEntryV1>,
    pub has_more: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

pub type SignedClearingInputManifestV1 = SignedClearingEnvelopeV1<ClearingInputManifestBodyV1>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingRoundRequestV1 {
    pub round_id: String,
    pub epoch: u64,
    pub governance_scope_id: String,
    pub currency: String,
    pub algorithm_version: String,
    pub participant_snapshot: SignedClearingParticipantSnapshotV1,
    pub participant_acknowledgements: Vec<SignedClearingParticipantSnapshotAcknowledgementV1>,
    pub input_manifest: SignedClearingInputManifestV1,
    pub obligations: Vec<ClearingObligationInputV1>,
    pub dispute_window_ends_at_unix_ms: u64,
    pub generated_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NettingRoundCoreV1 {
    pub schema: String,
    pub round_id: String,
    pub epoch: u64,
    pub governance_scope_id: String,
    pub clearing_authority_id: String,
    pub clearing_authority_key_epoch: u64,
    pub currency: String,
    pub algorithm_version: String,
    pub participant_snapshot_digest: String,
    pub input_manifest_digest: String,
    pub input_count: u64,
    pub reservation_root: String,
    pub dispute_window_ends_at_unix_ms: u64,
    pub generated_at_unix_ms: u64,
}

impl NettingRoundCoreV1 {
    pub fn digest(&self) -> Result<String, ClearingError> {
        domain_digest(ROUND_CORE_DIGEST_DOMAIN, self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingBalanceDirectionV1 {
    Debit,
    Credit,
    Zero,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingBalanceV1 {
    pub direction: ClearingBalanceDirectionV1,
    pub units: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingParticipantStatementV1 {
    pub schema: String,
    pub round_core_digest: String,
    pub participant_id: String,
    pub gross_debit_units: u64,
    pub gross_credit_units: u64,
    pub bilateral_debit_cancelled_units: u64,
    pub bilateral_credit_cancelled_units: u64,
    pub net_balance: ClearingBalanceV1,
    pub contributing_atom_digests: Vec<String>,
}

impl ClearingParticipantStatementV1 {
    pub fn digest(&self) -> Result<String, ClearingError> {
        domain_digest(STATEMENT_DIGEST_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingSettlementIntentV1 {
    pub schema: String,
    pub intent_id: String,
    pub round_core_digest: String,
    pub ordinal: u64,
    pub debtor_participant_id: String,
    pub creditor_participant_id: String,
    pub creditor_settlement_destination: String,
    pub amount: MonetaryAmount,
    pub contributing_reservation_root: String,
    pub dispatch_idempotency_key: String,
}

impl ClearingSettlementIntentV1 {
    pub fn digest(&self) -> Result<String, ClearingError> {
        domain_digest(INTENT_DIGEST_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingAtomTransformationV1 {
    pub schema: String,
    pub round_core_digest: String,
    pub source_sequence: u64,
    pub obligation_id: String,
    pub atom_digest: String,
    pub debtor_identity: String,
    pub creditor_identity: String,
    pub debtor_participant_id: String,
    pub creditor_participant_id: String,
    pub amount: MonetaryAmount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingOutputManifestV1 {
    pub schema: String,
    pub round_core_digest: String,
    pub participant_statement_root: String,
    pub participant_statement_count: u64,
    pub settlement_intent_root: String,
    pub settlement_intent_count: u64,
    pub atom_transformation_root: String,
    pub atom_transformation_count: u64,
}

impl ClearingOutputManifestV1 {
    pub fn digest(&self) -> Result<String, ClearingError> {
        domain_digest(OUTPUT_MANIFEST_DIGEST_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingRoundOutputV1 {
    pub core: NettingRoundCoreV1,
    pub participant_statements: Vec<ClearingParticipantStatementV1>,
    pub intents: Vec<ClearingSettlementIntentV1>,
    pub transformations: Vec<ClearingAtomTransformationV1>,
    pub output_manifest: ClearingOutputManifestV1,
}

pub type SignedNettingRoundCoreV1 = SignedClearingEnvelopeV1<NettingRoundCoreV1>;
pub type SignedClearingParticipantStatementV1 =
    SignedClearingEnvelopeV1<ClearingParticipantStatementV1>;
pub type SignedClearingSettlementIntentV1 = SignedClearingEnvelopeV1<ClearingSettlementIntentV1>;
pub type SignedClearingAtomTransformationV1 =
    SignedClearingEnvelopeV1<ClearingAtomTransformationV1>;
pub type SignedClearingOutputManifestV1 = SignedClearingEnvelopeV1<ClearingOutputManifestV1>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedClearingRoundOutputV1 {
    pub core: SignedNettingRoundCoreV1,
    pub participant_statements: Vec<SignedClearingParticipantStatementV1>,
    pub intents: Vec<SignedClearingSettlementIntentV1>,
    pub transformations: Vec<SignedClearingAtomTransformationV1>,
    pub output_manifest: SignedClearingOutputManifestV1,
}

pub(super) fn domain_digest<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<String, ClearingError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| ClearingError::Canonicalization(error.to_string()))?;
    let mut preimage = Vec::with_capacity(domain.len() + bytes.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&bytes);
    Ok(sha256_hex(&preimage))
}

pub(super) fn validate_text(field: &'static str, value: &str) -> Result<(), ClearingError> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > MAX_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        Err(ClearingError::InvalidField(field))
    } else {
        Ok(())
    }
}

pub(super) fn validate_digest(field: &'static str, value: &str) -> Result<(), ClearingError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ClearingError::InvalidField(field))
    }
}

pub(super) fn validate_positive(field: &'static str, value: u64) -> Result<(), ClearingError> {
    if value == 0 || value > I_JSON_MAX_SAFE_INTEGER {
        Err(ClearingError::InvalidField(field))
    } else {
        Ok(())
    }
}

pub(super) fn validate_currency(value: &str) -> Result<(), ClearingError> {
    if value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_uppercase()) {
        Ok(())
    } else {
        Err(ClearingError::InvalidField("currency"))
    }
}

pub(super) fn checked_u64(value: u128) -> Result<u64, ClearingError> {
    let value = u64::try_from(value).map_err(|_| ClearingError::ArithmeticOverflow)?;
    if value > I_JSON_MAX_SAFE_INTEGER {
        Err(ClearingError::ArithmeticOverflow)
    } else {
        Ok(value)
    }
}

pub(super) fn checked_count(value: usize) -> Result<u64, ClearingError> {
    let value = u64::try_from(value).map_err(|_| ClearingError::ArithmeticOverflow)?;
    if value > I_JSON_MAX_SAFE_INTEGER {
        Err(ClearingError::ArithmeticOverflow)
    } else {
        Ok(value)
    }
}
