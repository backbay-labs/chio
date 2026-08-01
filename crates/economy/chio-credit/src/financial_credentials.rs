use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use chio_core_types::{canonical_json_bytes, sha256_hex, Hash, Keypair, MerkleProof, MerkleTree};
use chio_did::DidChio;
use chio_fincred::{
    CreditScorecardConfidenceV1, CreditScorecardCredentialSubjectV1,
    CreditScorecardImportedSignalContextV1, CreditScorecardRiskBandV1,
    ExposureHistoryCredentialSubjectV1, ExposureHistoryPositionV1, FinancialCredentialEvidenceV1,
    FinancialCredentialFamilyV1, FinancialCredentialSubjectV1, FinancialCredentialWindowV1,
    FinancialSourceArtifactRoleV1, FinancialSourceBundleArtifactV1,
    FinancialSourceCheckpointBodyV1, FinancialSourceCommittedLeafProofV1,
    FinancialSourceCompletenessBoundaryV1, FinancialSourceDisclosureV1,
    FinancialSourceMemberBodyV1, FinancialSourceQueryKeyV1, LossHistoryCredentialSubjectV1,
    PremiumHistoryCredentialSubjectV1, SignedFinancialSourceCheckpointV1,
    SignedFinancialSourceCompletenessAttestationV1, SignedFinancialSourceMemberV1,
    FINANCIAL_SOURCE_CHECKPOINT_SCHEMA_V1, FINANCIAL_SOURCE_COMPLETENESS_ATTESTATION_SCHEMA_V1,
    FINANCIAL_SOURCE_MEMBER_SCHEMA_V1, MAX_I_JSON_SAFE_INTEGER,
};
use serde::{de::DeserializeOwned, Serialize};

use crate::capability::{governance::ProvenanceEvidenceClass, scope::MonetaryAmount};
use crate::crypto::PublicKey;
use crate::underwriting::{SignedUnderwritingDecision, UnderwritingPremiumState};
use crate::{
    CreditBondLifecycleState, CreditLossLifecycleEventKind, CreditScorecardBand,
    CreditScorecardConfidence, ExposureLedgerDecisionEntry, ExposureLedgerReceiptEntry,
    SignedCreditLossLifecycle, SignedCreditScorecardReport, SignedExposureLedgerReport,
    CREDIT_LOSS_LIFECYCLE_ARTIFACT_SCHEMA, CREDIT_LOSS_LIFECYCLE_REPORT_SCHEMA,
    CREDIT_SCORECARD_SCHEMA, EXPOSURE_LEDGER_SCHEMA,
};

const SOURCE_ARTIFACT_DIGEST_DOMAIN: &[u8] = b"chio.fincred.source-artifact.v1\0";
const SOURCE_DISCLOSURE_DIGEST_DOMAIN: &[u8] = b"chio.fincred.source-disclosure.v1\0";
const SOURCE_CHECKPOINT_DIGEST_DOMAIN: &[u8] = b"chio.fincred.source-checkpoint-digest.v1\0";
const EXPOSURE_RECEIPT_MEMBER_SCHEMA_V1: &str = "chio.fincred.exposure-receipt-member.v1";
const EXPOSURE_DECISION_MEMBER_SCHEMA_V1: &str = "chio.fincred.exposure-decision-member.v1";
const MAX_SOURCE_ARTIFACTS: usize = 256;
const MAX_SOURCE_ARTIFACT_BYTES: usize = 512 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FinancialCredentialProjectionError {
    #[error("settlement reliability window contains no authenticated obligations")]
    EmptyWindow,
    #[error("settlement reliability counts are inconsistent")]
    InvalidReliabilityCounts,
    #[error("settlement reliability ratio overflowed")]
    ReliabilityRatioOverflow,
    #[error("settlement reliability proof substrate is unavailable")]
    ReliabilityProofSubstrateUnavailable,
    #[error("financial source resolver proof substrate is unavailable")]
    ResolverProofSubstrateUnavailable,
    #[error("financial credential source signature inspection failed")]
    InvalidSourceSignature,
    #[error("financial credential source schema is invalid")]
    InvalidSourceSchema,
    #[error("financial credential source is incomplete")]
    IncompleteSource,
    #[error("financial credential source subject is missing or inconsistent")]
    InvalidSourceSubject,
    #[error("financial credential source amount overflowed")]
    AmountOverflow,
    #[error("financial credential value exceeds the I-JSON integer range")]
    IJsonIntegerOutOfRange,
    #[error("financial source completeness attestation authority pin is invalid")]
    InvalidSourceAuthority,
    #[error("financial source completeness attestation signature is invalid")]
    InvalidSourceAttestationSignature,
    #[error("financial source completeness attestation does not bind the requested source set")]
    InvalidSourceAttestationBinding,
    #[error("financial source completeness attestation is stale or outside its validity window")]
    StaleSourceAttestation,
    #[error("financial source evidence class exceeds its authenticated ceiling")]
    SourceEvidenceClassOverclaim,
    #[error("financial credential source is invalid: {0}")]
    InvalidSource(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinancialSourceAuthorityPinV1 {
    source_id: String,
    checkpoint_authority_epoch: u64,
    checkpoint_authority_key: PublicKey,
    store_generation: u64,
    checkpoint_sequence: u64,
    checkpoint_digest: String,
    cutoff: u64,
    index_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinancialSourceAuthorityPinConfigV1 {
    pub source_id: String,
    pub checkpoint_authority_epoch: u64,
    pub checkpoint_authority_key: PublicKey,
    pub store_generation: u64,
    pub checkpoint_sequence: u64,
    pub checkpoint_digest: String,
    pub cutoff: u64,
    pub index_root: String,
}

impl FinancialSourceAuthorityPinV1 {
    pub fn from_operator_config(
        config: FinancialSourceAuthorityPinConfigV1,
    ) -> Result<Self, FinancialCredentialProjectionError> {
        ensure_i_json(config.checkpoint_authority_epoch)?;
        ensure_i_json(config.store_generation)?;
        ensure_i_json(config.checkpoint_sequence)?;
        ensure_i_json(config.cutoff)?;
        if !valid_identifier(&config.source_id)
            || config.checkpoint_authority_epoch == 0
            || config.store_generation == 0
            || config.checkpoint_sequence == 0
            || !valid_digest(&config.checkpoint_digest)
            || !valid_digest(&config.index_root)
        {
            return Err(FinancialCredentialProjectionError::InvalidSourceAuthority);
        }
        Ok(Self {
            source_id: config.source_id,
            checkpoint_authority_epoch: config.checkpoint_authority_epoch,
            checkpoint_authority_key: config.checkpoint_authority_key,
            store_generation: config.store_generation,
            checkpoint_sequence: config.checkpoint_sequence,
            checkpoint_digest: config.checkpoint_digest,
            cutoff: config.cutoff,
            index_root: config.index_root,
        })
    }
}

#[derive(Debug, Clone)]
pub struct QualifiedFinancialSourceCheckpointV1 {
    body: FinancialSourceCheckpointBodyV1,
    checkpoint_digest: String,
}

impl QualifiedFinancialSourceCheckpointV1 {
    #[must_use]
    pub const fn body(&self) -> &FinancialSourceCheckpointBodyV1 {
        &self.body
    }

    #[must_use]
    pub fn checkpoint_digest(&self) -> &str {
        &self.checkpoint_digest
    }
}

pub fn qualify_financial_source_checkpoint(
    checkpoint: &SignedFinancialSourceCheckpointV1,
    authority_pin: &FinancialSourceAuthorityPinV1,
    now: u64,
) -> Result<QualifiedFinancialSourceCheckpointV1, FinancialCredentialProjectionError> {
    let body = &checkpoint.body;
    if body.schema != FINANCIAL_SOURCE_CHECKPOINT_SCHEMA_V1
        || body.source_id != authority_pin.source_id
        || body.checkpoint_authority_epoch != authority_pin.checkpoint_authority_epoch
        || body.checkpoint_authority_key != authority_pin.checkpoint_authority_key
        || checkpoint.signer_key != authority_pin.checkpoint_authority_key
    {
        return Err(FinancialCredentialProjectionError::InvalidSourceAuthority);
    }
    if !authority_pin
        .checkpoint_authority_key
        .verify_canonical(body, &checkpoint.signature)
        .map_err(|_| FinancialCredentialProjectionError::InvalidSourceAttestationSignature)?
    {
        return Err(FinancialCredentialProjectionError::InvalidSourceAttestationSignature);
    }
    validate_source_checkpoint_body(body, now)?;
    let checkpoint_digest = domain_digest(
        SOURCE_CHECKPOINT_DIGEST_DOMAIN,
        &canonical_json_bytes(body).map_err(|error| {
            FinancialCredentialProjectionError::InvalidSource(error.to_string())
        })?,
    );
    if body.store_generation != authority_pin.store_generation
        || body.checkpoint_sequence != authority_pin.checkpoint_sequence
        || body.cutoff != authority_pin.cutoff
        || body.index_root != authority_pin.index_root
        || checkpoint_digest != authority_pin.checkpoint_digest
    {
        return Err(FinancialCredentialProjectionError::InvalidSourceAuthority);
    }
    Ok(QualifiedFinancialSourceCheckpointV1 {
        body: body.clone(),
        checkpoint_digest,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinancialSourceCompletenessAttestationRequestV1 {
    pub source_family: FinancialCredentialFamilyV1,
    pub subject: String,
    pub source_signer_key: PublicKey,
    pub cutoff: u64,
    pub window: FinancialCredentialWindowV1,
    pub source_artifact_digests: Vec<String>,
    pub disclosure: FinancialSourceDisclosureV1,
    pub disclosure_digest: String,
    pub maximum_source_evidence_class: ProvenanceEvidenceClass,
    pub expected_members: Vec<FinancialSourceExpectedMemberV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinancialSourceExpectedMemberV1 {
    pub query_key: FinancialSourceQueryKeyV1,
    pub source_artifact_digest: String,
    pub evidence_class: ProvenanceEvidenceClass,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedFinancialSourceDisclosureV1 {
    source_artifact_digests: Vec<String>,
    expected_members: Vec<FinancialSourceExpectedMemberV1>,
    source_evidence_class: ProvenanceEvidenceClass,
}

impl ValidatedFinancialSourceDisclosureV1 {
    #[must_use]
    pub fn source_artifact_digests(&self) -> &[String] {
        &self.source_artifact_digests
    }

    #[must_use]
    pub fn expected_members(&self) -> &[FinancialSourceExpectedMemberV1] {
        &self.expected_members
    }

    #[must_use]
    pub const fn source_evidence_class(&self) -> ProvenanceEvidenceClass {
        self.source_evidence_class
    }
}

#[derive(Debug)]
pub struct VerifiedFinancialCredentialIssuanceV1 {
    subject: FinancialCredentialSubjectV1,
    evidence: FinancialCredentialEvidenceV1,
    source_evidence_class: ProvenanceEvidenceClass,
    proof_issued_at: u64,
    proof_expires_at: u64,
}

impl VerifiedFinancialCredentialIssuanceV1 {
    #[must_use]
    pub fn into_validated_parts(
        self,
    ) -> (
        FinancialCredentialSubjectV1,
        FinancialCredentialEvidenceV1,
        ProvenanceEvidenceClass,
        u64,
        u64,
    ) {
        (
            self.subject,
            self.evidence,
            self.source_evidence_class,
            self.proof_issued_at,
            self.proof_expires_at,
        )
    }
}

pub fn settlement_reliability_ratio_bps(
    on_time_count: u64,
    obligation_count: u64,
) -> Result<u32, FinancialCredentialProjectionError> {
    if obligation_count == 0 {
        return Err(FinancialCredentialProjectionError::EmptyWindow);
    }
    if on_time_count > obligation_count {
        return Err(FinancialCredentialProjectionError::InvalidReliabilityCounts);
    }
    ensure_i_json(on_time_count)?;
    ensure_i_json(obligation_count)?;
    let numerator = u128::from(on_time_count)
        .checked_mul(10_000)
        .ok_or(FinancialCredentialProjectionError::ReliabilityRatioOverflow)?;
    u32::try_from(numerator / u128::from(obligation_count))
        .map_err(|_| FinancialCredentialProjectionError::ReliabilityRatioOverflow)
}

pub fn prepare_credit_scorecard_financial_source(
    report: &SignedCreditScorecardReport,
    exposure_report: &SignedExposureLedgerReport,
    members: &[SignedFinancialSourceMemberV1],
) -> Result<FinancialSourceCompletenessAttestationRequestV1, FinancialCredentialProjectionError> {
    inspect_source_signature(report.verify_signature())?;
    if report.body.schema != CREDIT_SCORECARD_SCHEMA {
        return Err(FinancialCredentialProjectionError::InvalidSourceSchema);
    }
    let subject = project_credit_scorecard_subject(report)?;
    let window = complete_report_window(
        report.body.filters.since,
        report.body.filters.until,
        report.body.generated_at,
    )?;
    ensure_complete_counts(
        report.body.summary.matching_receipts,
        report.body.summary.returned_receipts,
    )?;
    ensure_complete_counts(
        report.body.summary.matching_decisions,
        report.body.summary.returned_decisions,
    )?;
    validate_scorecard_exposure_binding(report, exposure_report)?;
    let (mut artifacts, expected_members) = validate_exposure_report_members(
        exposure_report,
        FinancialCredentialFamilyV1::CreditScorecard,
        members,
    )?;
    artifacts.push(source_bundle_artifact(
        FinancialSourceArtifactRoleV1::Claim,
        CREDIT_SCORECARD_SCHEMA,
        report,
    )?);
    artifacts.push(source_bundle_artifact(
        FinancialSourceArtifactRoleV1::Claim,
        EXPOSURE_LEDGER_SCHEMA,
        exposure_report,
    )?);
    prepare_request(
        FinancialCredentialFamilyV1::CreditScorecard,
        subject.id.clone(),
        report.signer_key.clone(),
        window,
        artifacts,
        ProvenanceEvidenceClass::Asserted,
        expected_members,
    )
}

pub fn verify_credit_scorecard_financial_credential_input(
    report: &SignedCreditScorecardReport,
    exposure_report: &SignedExposureLedgerReport,
    members: &[SignedFinancialSourceMemberV1],
    proof: &SignedFinancialSourceCompletenessAttestationV1,
    checkpoint: &QualifiedFinancialSourceCheckpointV1,
    now: u64,
) -> Result<VerifiedFinancialCredentialIssuanceV1, FinancialCredentialProjectionError> {
    let request = prepare_credit_scorecard_financial_source(report, exposure_report, members)?;
    let subject =
        FinancialCredentialSubjectV1::CreditScorecard(project_credit_scorecard_subject(report)?);
    verify_issuance_input(subject, request, proof, checkpoint, now)
}

pub fn prepare_exposure_history_financial_source(
    report: &SignedExposureLedgerReport,
    members: &[SignedFinancialSourceMemberV1],
) -> Result<FinancialSourceCompletenessAttestationRequestV1, FinancialCredentialProjectionError> {
    inspect_source_signature(report.verify_signature())?;
    if report.body.schema != EXPOSURE_LEDGER_SCHEMA {
        return Err(FinancialCredentialProjectionError::InvalidSourceSchema);
    }
    if report.body.summary.truncated_receipts || report.body.summary.truncated_decisions {
        return Err(FinancialCredentialProjectionError::IncompleteSource);
    }
    let subject = project_exposure_history_subject(report)?;
    let window = complete_report_window(
        report.body.filters.since,
        report.body.filters.until,
        report.body.generated_at,
    )?;
    ensure_complete_counts(
        report.body.summary.matching_receipts,
        report.body.summary.returned_receipts,
    )?;
    ensure_complete_counts(
        report.body.summary.matching_decisions,
        report.body.summary.returned_decisions,
    )?;
    let (mut artifacts, expected_members) = validate_exposure_report_members(
        report,
        FinancialCredentialFamilyV1::ExposureHistory,
        members,
    )?;
    artifacts.push(source_bundle_artifact(
        FinancialSourceArtifactRoleV1::Claim,
        EXPOSURE_LEDGER_SCHEMA,
        report,
    )?);
    prepare_request(
        FinancialCredentialFamilyV1::ExposureHistory,
        subject.id.clone(),
        report.signer_key.clone(),
        window,
        artifacts,
        ProvenanceEvidenceClass::Asserted,
        expected_members,
    )
}

pub fn verify_exposure_history_financial_credential_input(
    report: &SignedExposureLedgerReport,
    members: &[SignedFinancialSourceMemberV1],
    proof: &SignedFinancialSourceCompletenessAttestationV1,
    checkpoint: &QualifiedFinancialSourceCheckpointV1,
    now: u64,
) -> Result<VerifiedFinancialCredentialIssuanceV1, FinancialCredentialProjectionError> {
    let request = prepare_exposure_history_financial_source(report, members)?;
    let subject =
        FinancialCredentialSubjectV1::ExposureHistory(project_exposure_history_subject(report)?);
    verify_issuance_input(subject, request, proof, checkpoint, now)
}

pub fn prepare_premium_history_financial_source(
    decisions: &[SignedUnderwritingDecision],
    window: FinancialCredentialWindowV1,
) -> Result<FinancialSourceCompletenessAttestationRequestV1, FinancialCredentialProjectionError> {
    let subject = project_premium_history_subject(decisions)?;
    let ordered = ordered_underwriting_decisions(decisions)?;
    let first = ordered
        .first()
        .ok_or(FinancialCredentialProjectionError::IncompleteSource)?;
    let mut artifacts = Vec::with_capacity(ordered.len());
    let mut expected_members = Vec::with_capacity(ordered.len());
    for decision in &ordered {
        let (artifact, expected) = expected_native_member(
            FinancialCredentialFamilyV1::PremiumHistory,
            subject.id.clone(),
            decision.body.issued_at,
            decision.body.decision_id.clone(),
            crate::underwriting::UNDERWRITING_DECISION_ARTIFACT_SCHEMA,
            *decision,
            ProvenanceEvidenceClass::Asserted,
        )?;
        artifacts.push(artifact);
        expected_members.push(expected);
    }
    prepare_request(
        FinancialCredentialFamilyV1::PremiumHistory,
        subject.id.clone(),
        first.signer_key.clone(),
        window,
        artifacts,
        ProvenanceEvidenceClass::Asserted,
        expected_members,
    )
}

pub fn verify_premium_history_financial_credential_input(
    decisions: &[SignedUnderwritingDecision],
    window: FinancialCredentialWindowV1,
    proof: &SignedFinancialSourceCompletenessAttestationV1,
    checkpoint: &QualifiedFinancialSourceCheckpointV1,
    now: u64,
) -> Result<VerifiedFinancialCredentialIssuanceV1, FinancialCredentialProjectionError> {
    let request = prepare_premium_history_financial_source(decisions, window)?;
    let subject =
        FinancialCredentialSubjectV1::PremiumHistory(project_premium_history_subject(decisions)?);
    verify_issuance_input(subject, request, proof, checkpoint, now)
}

pub fn prepare_loss_history_financial_source(
    events: &[SignedCreditLossLifecycle],
    window: FinancialCredentialWindowV1,
) -> Result<FinancialSourceCompletenessAttestationRequestV1, FinancialCredentialProjectionError> {
    let ordered = ordered_loss_events(events)?;
    validate_loss_lifecycle_continuity(&ordered)?;
    let subject = project_loss_history_subject(&ordered)?;
    let first = ordered
        .first()
        .ok_or(FinancialCredentialProjectionError::IncompleteSource)?;
    let mut artifacts = Vec::with_capacity(ordered.len());
    let mut expected_members = Vec::with_capacity(ordered.len());
    for event in &ordered {
        let (artifact, expected) = expected_native_member(
            FinancialCredentialFamilyV1::LossHistory,
            subject.id.clone(),
            event.body.issued_at,
            event.body.event_id.clone(),
            CREDIT_LOSS_LIFECYCLE_ARTIFACT_SCHEMA,
            *event,
            ProvenanceEvidenceClass::Asserted,
        )?;
        artifacts.push(artifact);
        expected_members.push(expected);
    }
    prepare_request(
        FinancialCredentialFamilyV1::LossHistory,
        subject.id.clone(),
        first.signer_key.clone(),
        window,
        artifacts,
        ProvenanceEvidenceClass::Observed,
        expected_members,
    )
}

pub fn verify_loss_history_financial_credential_input(
    events: &[SignedCreditLossLifecycle],
    window: FinancialCredentialWindowV1,
    proof: &SignedFinancialSourceCompletenessAttestationV1,
    checkpoint: &QualifiedFinancialSourceCheckpointV1,
    now: u64,
) -> Result<VerifiedFinancialCredentialIssuanceV1, FinancialCredentialProjectionError> {
    let ordered = ordered_loss_events(events)?;
    validate_loss_lifecycle_continuity(&ordered)?;
    let subject =
        FinancialCredentialSubjectV1::LossHistory(project_loss_history_subject(&ordered)?);
    let request = prepare_loss_history_financial_source(events, window)?;
    verify_issuance_input(subject, request, proof, checkpoint, now)
}

#[path = "financial_credentials/projection.rs"]
mod projection;
#[path = "financial_credentials/verification.rs"]
mod verification;

use projection::{
    complete_report_window, ensure_complete_counts, inspect_source_signature, ordered_loss_events,
    ordered_underwriting_decisions, project_credit_scorecard_subject,
    project_exposure_history_subject, project_loss_history_subject,
    project_premium_history_subject, validate_loss_lifecycle_continuity,
};
use verification::{prepare_request, validate_source_checkpoint_body, verify_issuance_input};
#[cfg(test)]
use verification::{verify_completeness_boundary, verify_source_completeness_attestation};

fn source_bundle_artifact<T: Serialize>(
    role: FinancialSourceArtifactRoleV1,
    artifact_schema: &str,
    artifact: &T,
) -> Result<FinancialSourceBundleArtifactV1, FinancialCredentialProjectionError> {
    let canonical = canonical_json_bytes(artifact)
        .map_err(|error| FinancialCredentialProjectionError::InvalidSource(error.to_string()))?;
    if canonical.len() > MAX_SOURCE_ARTIFACT_BYTES {
        return Err(FinancialCredentialProjectionError::InvalidSource(
            "source artifact exceeds the bounded bundle limit".to_string(),
        ));
    }
    let canonical_artifact = String::from_utf8(canonical.clone())
        .map_err(|error| FinancialCredentialProjectionError::InvalidSource(error.to_string()))?;
    Ok(FinancialSourceBundleArtifactV1 {
        role,
        artifact_schema: artifact_schema.to_string(),
        artifact_digest: domain_digest(SOURCE_ARTIFACT_DIGEST_DOMAIN, &canonical),
        canonical_artifact,
    })
}

pub fn sign_exposure_receipt_financial_source_member(
    source_family: FinancialCredentialFamilyV1,
    receipt: &ExposureLedgerReceiptEntry,
    signer: &Keypair,
) -> Result<SignedFinancialSourceMemberV1, FinancialCredentialProjectionError> {
    let subject = source_subject_did(receipt.subject_key.as_deref())?;
    sign_financial_source_member(
        FinancialSourceQueryKeyV1 {
            source_family,
            subject,
            occurred_at: receipt.timestamp,
            artifact_id: receipt.receipt_id.clone(),
        },
        EXPOSURE_RECEIPT_MEMBER_SCHEMA_V1,
        receipt,
        signer,
    )
}

pub fn sign_exposure_decision_financial_source_member(
    source_family: FinancialCredentialFamilyV1,
    decision: &ExposureLedgerDecisionEntry,
    signer: &Keypair,
) -> Result<SignedFinancialSourceMemberV1, FinancialCredentialProjectionError> {
    let subject = source_subject_did(decision.agent_subject.as_deref())?;
    sign_financial_source_member(
        FinancialSourceQueryKeyV1 {
            source_family,
            subject,
            occurred_at: decision.issued_at,
            artifact_id: decision.decision_id.clone(),
        },
        EXPOSURE_DECISION_MEMBER_SCHEMA_V1,
        decision,
        signer,
    )
}

fn sign_financial_source_member<T: Serialize>(
    query_key: FinancialSourceQueryKeyV1,
    artifact_schema: &str,
    artifact: &T,
    signer: &Keypair,
) -> Result<SignedFinancialSourceMemberV1, FinancialCredentialProjectionError> {
    if !matches!(
        query_key.source_family,
        FinancialCredentialFamilyV1::CreditScorecard | FinancialCredentialFamilyV1::ExposureHistory
    ) {
        return Err(FinancialCredentialProjectionError::InvalidSourceSchema);
    }
    ensure_i_json(query_key.occurred_at)?;
    if !valid_identifier(&query_key.subject) || !valid_identifier(&query_key.artifact_id) {
        return Err(FinancialCredentialProjectionError::InvalidSourceSchema);
    }
    let canonical_artifact =
        String::from_utf8(canonical_json_bytes(artifact).map_err(|error| {
            FinancialCredentialProjectionError::InvalidSource(error.to_string())
        })?)
        .map_err(|error| FinancialCredentialProjectionError::InvalidSource(error.to_string()))?;
    SignedFinancialSourceMemberV1::sign(
        FinancialSourceMemberBodyV1 {
            schema: FINANCIAL_SOURCE_MEMBER_SCHEMA_V1.to_string(),
            query_key,
            artifact_schema: artifact_schema.to_string(),
            canonical_artifact,
        },
        signer,
    )
    .map_err(|error| FinancialCredentialProjectionError::InvalidSource(error.to_string()))
}

fn inspect_financial_source_member(
    member: &SignedFinancialSourceMemberV1,
    expected_family: FinancialCredentialFamilyV1,
    expected_signer: &PublicKey,
) -> Result<FinancialSourceExpectedMemberV1, FinancialCredentialProjectionError> {
    inspect_source_signature(member.verify_signature())?;
    if member.body.schema != FINANCIAL_SOURCE_MEMBER_SCHEMA_V1
        || member.body.query_key.source_family != expected_family
        || &member.signer_key != expected_signer
    {
        return Err(FinancialCredentialProjectionError::InvalidSourceSchema);
    }
    let (query_key, evidence_class) = match member.body.artifact_schema.as_str() {
        EXPOSURE_RECEIPT_MEMBER_SCHEMA_V1 => {
            let receipt: ExposureLedgerReceiptEntry =
                parse_canonical_source_artifact(&member.body.canonical_artifact)?;
            (
                FinancialSourceQueryKeyV1 {
                    source_family: expected_family,
                    subject: source_subject_did(receipt.subject_key.as_deref())?,
                    occurred_at: receipt.timestamp,
                    artifact_id: receipt.receipt_id,
                },
                ProvenanceEvidenceClass::Asserted,
            )
        }
        EXPOSURE_DECISION_MEMBER_SCHEMA_V1 => {
            let decision: ExposureLedgerDecisionEntry =
                parse_canonical_source_artifact(&member.body.canonical_artifact)?;
            (
                FinancialSourceQueryKeyV1 {
                    source_family: expected_family,
                    subject: source_subject_did(decision.agent_subject.as_deref())?,
                    occurred_at: decision.issued_at,
                    artifact_id: decision.decision_id,
                },
                ProvenanceEvidenceClass::Asserted,
            )
        }
        _ => return Err(FinancialCredentialProjectionError::InvalidSourceSchema),
    };
    if member.body.query_key != query_key {
        return Err(FinancialCredentialProjectionError::InvalidSourceAttestationBinding);
    }
    let artifact = source_bundle_artifact(
        FinancialSourceArtifactRoleV1::Member,
        FINANCIAL_SOURCE_MEMBER_SCHEMA_V1,
        member,
    )?;
    Ok(FinancialSourceExpectedMemberV1 {
        query_key,
        source_artifact_digest: artifact.artifact_digest,
        evidence_class,
    })
}

fn parse_canonical_source_artifact<T: DeserializeOwned + Serialize>(
    canonical: &str,
) -> Result<T, FinancialCredentialProjectionError> {
    let value = serde_json::from_str::<T>(canonical)
        .map_err(|error| FinancialCredentialProjectionError::InvalidSource(error.to_string()))?;
    let round_trip = canonical_json_bytes(&value)
        .map_err(|error| FinancialCredentialProjectionError::InvalidSource(error.to_string()))?;
    if round_trip != canonical.as_bytes() {
        return Err(FinancialCredentialProjectionError::InvalidSourceSchema);
    }
    Ok(value)
}

fn validate_exposure_report_members(
    report: &SignedExposureLedgerReport,
    source_family: FinancialCredentialFamilyV1,
    members: &[SignedFinancialSourceMemberV1],
) -> Result<
    (
        Vec<FinancialSourceBundleArtifactV1>,
        Vec<FinancialSourceExpectedMemberV1>,
    ),
    FinancialCredentialProjectionError,
> {
    let receipt_count = count_i_json(report.body.receipts.len())?;
    let decision_count = count_i_json(report.body.decisions.len())?;
    if report.body.summary.truncated_receipts
        || report.body.summary.truncated_decisions
        || report.body.summary.matching_receipts != report.body.summary.returned_receipts
        || report.body.summary.matching_decisions != report.body.summary.returned_decisions
        || report.body.summary.returned_receipts != receipt_count
        || report.body.summary.returned_decisions != decision_count
    {
        return Err(FinancialCredentialProjectionError::IncompleteSource);
    }
    if members.is_empty() || members.len() > MAX_SOURCE_ARTIFACTS {
        return Err(FinancialCredentialProjectionError::IncompleteSource);
    }
    let mut report_members = BTreeSet::new();
    for receipt in &report.body.receipts {
        report_members.insert((
            EXPOSURE_RECEIPT_MEMBER_SCHEMA_V1,
            canonical_json_string(receipt)?,
        ));
    }
    for decision in &report.body.decisions {
        report_members.insert((
            EXPOSURE_DECISION_MEMBER_SCHEMA_V1,
            canonical_json_string(decision)?,
        ));
    }
    if report_members.len() != report.body.receipts.len() + report.body.decisions.len()
        || report_members.len() != members.len()
    {
        return Err(FinancialCredentialProjectionError::IncompleteSource);
    }
    let mut supplied_members = BTreeSet::new();
    let mut artifacts = Vec::with_capacity(members.len());
    let mut expected = Vec::with_capacity(members.len());
    for member in members {
        if !supplied_members.insert((
            member.body.artifact_schema.as_str(),
            member.body.canonical_artifact.as_str(),
        )) {
            return Err(FinancialCredentialProjectionError::IncompleteSource);
        }
        expected.push(inspect_financial_source_member(
            member,
            source_family,
            &report.signer_key,
        )?);
        artifacts.push(source_bundle_artifact(
            FinancialSourceArtifactRoleV1::Member,
            FINANCIAL_SOURCE_MEMBER_SCHEMA_V1,
            member,
        )?);
    }
    if report_members
        != supplied_members
            .into_iter()
            .map(|(schema, canonical)| (schema, canonical.to_string()))
            .collect()
    {
        return Err(FinancialCredentialProjectionError::IncompleteSource);
    }
    Ok((artifacts, expected))
}

fn validate_scorecard_exposure_binding(
    scorecard: &SignedCreditScorecardReport,
    exposure: &SignedExposureLedgerReport,
) -> Result<(), FinancialCredentialProjectionError> {
    inspect_source_signature(exposure.verify_signature())?;
    if exposure.body.schema != EXPOSURE_LEDGER_SCHEMA
        || exposure.signer_key != scorecard.signer_key
        || exposure.body.filters != scorecard.body.filters
        || exposure.body.summary.truncated_receipts
        || exposure.body.summary.truncated_decisions
        || exposure.body.summary.matching_receipts != exposure.body.summary.returned_receipts
        || exposure.body.summary.matching_decisions != exposure.body.summary.returned_decisions
        || scorecard.body.summary.matching_receipts != exposure.body.summary.matching_receipts
        || scorecard.body.summary.returned_receipts != exposure.body.summary.returned_receipts
        || scorecard.body.summary.matching_decisions != exposure.body.summary.matching_decisions
        || scorecard.body.summary.returned_decisions != exposure.body.summary.returned_decisions
        || scorecard.body.summary.currencies != exposure.body.summary.currencies
        || scorecard.body.summary.mixed_currency_book != exposure.body.summary.mixed_currency_book
        || scorecard.body.positions != exposure.body.positions
    {
        return Err(FinancialCredentialProjectionError::IncompleteSource);
    }
    Ok(())
}

fn canonical_json_string<T: Serialize>(
    value: &T,
) -> Result<String, FinancialCredentialProjectionError> {
    String::from_utf8(
        canonical_json_bytes(value).map_err(|error| {
            FinancialCredentialProjectionError::InvalidSource(error.to_string())
        })?,
    )
    .map_err(|error| FinancialCredentialProjectionError::InvalidSource(error.to_string()))
}

fn expected_native_member<T: Serialize>(
    source_family: FinancialCredentialFamilyV1,
    subject: String,
    occurred_at: u64,
    artifact_id: String,
    artifact_schema: &str,
    artifact: &T,
    evidence_class: ProvenanceEvidenceClass,
) -> Result<
    (
        FinancialSourceBundleArtifactV1,
        FinancialSourceExpectedMemberV1,
    ),
    FinancialCredentialProjectionError,
> {
    let bundled = source_bundle_artifact(
        FinancialSourceArtifactRoleV1::Member,
        artifact_schema,
        artifact,
    )?;
    Ok((
        bundled.clone(),
        FinancialSourceExpectedMemberV1 {
            query_key: FinancialSourceQueryKeyV1 {
                source_family,
                subject,
                occurred_at,
                artifact_id,
            },
            source_artifact_digest: bundled.artifact_digest,
            evidence_class,
        },
    ))
}

#[path = "financial_credentials/disclosure.rs"]
mod disclosure;

pub use disclosure::validate_financial_source_disclosure;

fn source_subject_did(subject: Option<&str>) -> Result<String, FinancialCredentialProjectionError> {
    let subject = subject.ok_or(FinancialCredentialProjectionError::InvalidSourceSubject)?;
    if subject.starts_with("did:chio:") {
        return DidChio::from_str(subject)
            .map(|did| did.to_string())
            .map_err(|_| FinancialCredentialProjectionError::InvalidSourceSubject);
    }
    let public_key = PublicKey::from_hex(subject)
        .map_err(|_| FinancialCredentialProjectionError::InvalidSourceSubject)?;
    DidChio::from_public_key(public_key)
        .map(|did| did.to_string())
        .map_err(|_| FinancialCredentialProjectionError::InvalidSourceSubject)
}

fn bind_subject(
    expected: &mut Option<String>,
    candidate: String,
) -> Result<(), FinancialCredentialProjectionError> {
    match expected {
        Some(subject) if subject != &candidate => {
            Err(FinancialCredentialProjectionError::InvalidSourceSubject)
        }
        Some(_) => Ok(()),
        None => {
            *expected = Some(candidate);
            Ok(())
        }
    }
}

fn validate_money(amount: &MonetaryAmount) -> Result<(), FinancialCredentialProjectionError> {
    if !valid_currency(&amount.currency) {
        return Err(FinancialCredentialProjectionError::InvalidSource(
            "financial source currency is invalid".to_string(),
        ));
    }
    ensure_i_json(amount.units)
}

fn count_i_json(value: usize) -> Result<u64, FinancialCredentialProjectionError> {
    let value = u64::try_from(value)
        .map_err(|_| FinancialCredentialProjectionError::IJsonIntegerOutOfRange)?;
    ensure_i_json(value)?;
    Ok(value)
}

fn checked_i_json_add(left: u64, right: u64) -> Result<u64, FinancialCredentialProjectionError> {
    let value = left
        .checked_add(right)
        .ok_or(FinancialCredentialProjectionError::AmountOverflow)?;
    ensure_i_json(value)?;
    Ok(value)
}

fn ensure_i_json(value: u64) -> Result<(), FinancialCredentialProjectionError> {
    if is_i_json(value) {
        Ok(())
    } else {
        Err(FinancialCredentialProjectionError::IJsonIntegerOutOfRange)
    }
}

const fn is_i_json(value: u64) -> bool {
    value <= MAX_I_JSON_SAFE_INTEGER
}

fn valid_currency(currency: &str) -> bool {
    currency.len() == 3 && currency.bytes().all(|byte| byte.is_ascii_uppercase())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

const fn evidence_class_rank(class: ProvenanceEvidenceClass) -> u8 {
    match class {
        ProvenanceEvidenceClass::Asserted => 0,
        ProvenanceEvidenceClass::Observed => 1,
        ProvenanceEvidenceClass::Verified => 2,
    }
}

fn domain_digest(domain: &[u8], canonical: &[u8]) -> String {
    let mut preimage = Vec::with_capacity(domain.len() + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(canonical);
    sha256_hex(&preimage)
}

#[cfg(test)]
#[path = "financial_credentials/tests.rs"]
mod tests;
