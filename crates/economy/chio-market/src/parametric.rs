use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::capability::scope::MonetaryAmount;
use crate::credit::CapitalExecutionRailKind;
use crate::crypto::{canonical_json_bytes, sha256_hex, PublicKey};
use crate::receipt::lineage::SignedExportEnvelope;
use crate::{
    LiabilityBoundCoverageArtifact, SignedLiabilityBoundCoverage,
    LIABILITY_BOUND_COVERAGE_ARTIFACT_SCHEMA,
};

mod claim;
mod evidence;
mod lifecycle;

pub use claim::*;
pub use evidence::*;
pub use lifecycle::*;

pub const PARAMETRIC_POLICY_SCHEMA: &str = "chio.parametric.policy.v1";
pub const TRIGGER_INSTANCE_ID_DOMAIN: &str = "chio.parametric.trigger-instance.v1";
pub const PARAMETRIC_CLAIM_ID_DOMAIN: &str = "chio.parametric.claim.id.v1";
pub const TRIGGER_PREDICATE_DIGEST_DOMAIN: &str = "chio.parametric.trigger-predicate.v1";
pub const EVIDENCE_RANGE_DIGEST_DOMAIN: &str = "chio.parametric.evidence-range.v1";
pub const MAX_SIGNED_PARAMETRIC_POLICY_BYTES: usize = 1_048_576;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ParametricContractError {
    #[error("parametric canonicalization failed: {0}")]
    Canonicalization(String),
    #[error("invalid parametric field: {0}")]
    InvalidField(&'static str),
    #[error("unsupported parametric schema: {0}")]
    UnknownSchema(String),
    #[error("parametric artifact signature is invalid")]
    InvalidSignature,
    #[error("parametric policy signer is not trusted")]
    UntrustedPolicySigner,
    #[error("parametric evidence source is not trusted")]
    UntrustedEvidenceSource,
    #[error("parametric evidence signer is not trusted")]
    UntrustedEvidenceSigner,
    #[error("parametric evidence anchor epoch is stale")]
    StaleEvidenceAnchorEpoch,
    #[error("parametric evidence signer epoch is stale")]
    StaleEvidenceSignerEpoch,
    #[error("parametric evidence range proof is invalid")]
    InvalidEvidenceRangeProof,
    #[error("parametric evidence range boundaries are incomplete")]
    IncompleteEvidenceBoundaries,
    #[error("bound coverage authority is not trusted")]
    UntrustedCoverageAuthority,
    #[error("parametric policy binding mismatch: {0}")]
    BindingMismatch(&'static str),
    #[error("parametric payout schedule overflowed")]
    ScheduleOverflow,
    #[error("parametric payout exceeds bound coverage")]
    ScheduleExceedsCoverage,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TriggerMagnitudeUnit {
    Count,
    BasisPoints,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum TriggerMagnitude {
    Count { value: u64 },
    BasisPoints { value: u64 },
}

impl TriggerMagnitude {
    #[must_use]
    pub const fn unit(&self) -> TriggerMagnitudeUnit {
        match self {
            Self::Count { .. } => TriggerMagnitudeUnit::Count,
            Self::BasisPoints { .. } => TriggerMagnitudeUnit::BasisPoints,
        }
    }

    #[must_use]
    pub const fn value(&self) -> u64 {
        match self {
            Self::Count { value } | Self::BasisPoints { value } => *value,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum TriggerPredicate {
    GuardDenialRate { min_events: u64, threshold_bps: u32 },
    DriftSeverity { min_critical: u64 },
    SettlementFailureCount { min_failures: u64 },
}

impl TriggerPredicate {
    pub fn validate(&self) -> Result<(), ParametricContractError> {
        match self {
            Self::GuardDenialRate {
                min_events,
                threshold_bps,
            } => {
                if *min_events == 0 {
                    return Err(ParametricContractError::InvalidField(
                        "predicate.min_events",
                    ));
                }
                if *threshold_bps > 10_000 {
                    return Err(ParametricContractError::InvalidField(
                        "predicate.threshold_bps",
                    ));
                }
            }
            Self::DriftSeverity { min_critical } => {
                if *min_critical == 0 {
                    return Err(ParametricContractError::InvalidField(
                        "predicate.min_critical",
                    ));
                }
            }
            Self::SettlementFailureCount { min_failures } => {
                if *min_failures == 0 {
                    return Err(ParametricContractError::InvalidField(
                        "predicate.min_failures",
                    ));
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub const fn magnitude_unit(&self) -> TriggerMagnitudeUnit {
        match self {
            Self::GuardDenialRate { .. } => TriggerMagnitudeUnit::BasisPoints,
            Self::DriftSeverity { .. } | Self::SettlementFailureCount { .. } => {
                TriggerMagnitudeUnit::Count
            }
        }
    }

    const fn required_sources(&self) -> &'static [EvidenceSourceKind] {
        match self {
            Self::GuardDenialRate { .. } => &[EvidenceSourceKind::ReceiptStore],
            Self::DriftSeverity { .. } => &[EvidenceSourceKind::DriftReports],
            Self::SettlementFailureCount { .. } => &[
                EvidenceSourceKind::ReceiptStore,
                EvidenceSourceKind::SettlementReconciliations,
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum PayoutSchedule {
    Fixed {
        amount: MonetaryAmount,
    },
    Linear {
        base: MonetaryAmount,
        per_unit_minor: u64,
        magnitude_unit: TriggerMagnitudeUnit,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ParametricPayoutMode {
    Automatic,
    Contestable { window_seconds: u64 },
}

impl ParametricPayoutMode {
    fn validate(&self) -> Result<(), ParametricContractError> {
        match self {
            Self::Automatic => Ok(()),
            Self::Contestable { window_seconds } if *window_seconds > 0 => Ok(()),
            Self::Contestable { .. } => Err(ParametricContractError::InvalidField(
                "payout_mode.window_seconds",
            )),
        }
    }
}

impl PayoutSchedule {
    pub fn evaluate(
        &self,
        predicate: &TriggerPredicate,
        magnitude: &TriggerMagnitude,
        coverage: &MonetaryAmount,
    ) -> Result<MonetaryAmount, ParametricContractError> {
        self.validate_for(predicate, coverage)?;
        if magnitude.unit() != predicate.magnitude_unit() {
            return Err(ParametricContractError::InvalidField("magnitude.unit"));
        }
        let amount = match self {
            Self::Fixed { amount } => amount.clone(),
            Self::Linear {
                base,
                per_unit_minor,
                ..
            } => MonetaryAmount {
                units: per_unit_minor
                    .checked_mul(magnitude.value())
                    .and_then(|increment| base.units.checked_add(increment))
                    .ok_or(ParametricContractError::ScheduleOverflow)?,
                currency: base.currency.clone(),
            },
        };
        if amount.units == 0 {
            return Err(ParametricContractError::InvalidField(
                "payout_schedule.amount",
            ));
        }
        if amount.units > coverage.units {
            return Err(ParametricContractError::ScheduleExceedsCoverage);
        }
        Ok(amount)
    }

    fn validate_for(
        &self,
        predicate: &TriggerPredicate,
        coverage: &MonetaryAmount,
    ) -> Result<(), ParametricContractError> {
        match self {
            Self::Fixed { amount } => {
                validate_money(amount, "payout_schedule.amount", false)?;
                validate_schedule_currency(amount, coverage)?;
                if amount.units > coverage.units {
                    return Err(ParametricContractError::ScheduleExceedsCoverage);
                }
            }
            Self::Linear {
                base,
                per_unit_minor,
                magnitude_unit,
            } => {
                validate_money(base, "payout_schedule.base", true)?;
                validate_schedule_currency(base, coverage)?;
                if *per_unit_minor == 0 {
                    return Err(ParametricContractError::InvalidField(
                        "payout_schedule.per_unit_minor",
                    ));
                }
                if *magnitude_unit != predicate.magnitude_unit() {
                    return Err(ParametricContractError::InvalidField(
                        "payout_schedule.magnitude_unit",
                    ));
                }
                if base.units > coverage.units {
                    return Err(ParametricContractError::ScheduleExceedsCoverage);
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParametricPayoutRail {
    pub kind: CapitalExecutionRailKind,
    pub rail_id: String,
    pub destination_account_digest: String,
}

impl ParametricPayoutRail {
    fn validate(&self) -> Result<(), ParametricContractError> {
        validate_clean(&self.rail_id, "payout_rail.rail_id")?;
        validate_digest(
            &self.destination_account_digest,
            "payout_rail.destination_account_digest",
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvaluatorAuthorityRef {
    pub authority_id: String,
    pub key_id: String,
    pub key_epoch: u64,
}

impl EvaluatorAuthorityRef {
    fn validate(&self) -> Result<(), ParametricContractError> {
        validate_clean(&self.authority_id, "evaluator_authority.authority_id")?;
        validate_clean(&self.key_id, "evaluator_authority.key_id")?;
        if self.key_epoch == 0 {
            return Err(ParametricContractError::InvalidField(
                "evaluator_authority.key_epoch",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParametricPolicy {
    pub schema: String,
    pub issued_at: u64,
    pub subject_key: String,
    pub bound_coverage_body_digest: String,
    pub bound_coverage_envelope_digest: String,
    pub coverage_authority_id: String,
    pub payer_id: String,
    pub beneficiary_id: String,
    pub funding_facility_id: String,
    pub pre_action_authority_digest: String,
    pub coverage_amount: MonetaryAmount,
    pub effective_from: u64,
    pub effective_until: u64,
    pub window_anchor: u64,
    pub window_seconds: u64,
    pub max_checkpoint_lag_seconds: u64,
    pub predicate: TriggerPredicate,
    pub payout_schedule: PayoutSchedule,
    pub payout_mode: ParametricPayoutMode,
    pub payout_rail: ParametricPayoutRail,
    pub evaluator_authority: EvaluatorAuthorityRef,
}

impl ParametricPolicy {
    pub fn validate(&self) -> Result<(), ParametricContractError> {
        if self.schema != PARAMETRIC_POLICY_SCHEMA {
            return Err(ParametricContractError::UnknownSchema(self.schema.clone()));
        }
        validate_clean(&self.subject_key, "subject_key")?;
        validate_digest(
            &self.bound_coverage_body_digest,
            "bound_coverage_body_digest",
        )?;
        validate_digest(
            &self.bound_coverage_envelope_digest,
            "bound_coverage_envelope_digest",
        )?;
        validate_clean(&self.coverage_authority_id, "coverage_authority_id")?;
        validate_clean(&self.payer_id, "payer_id")?;
        validate_clean(&self.beneficiary_id, "beneficiary_id")?;
        validate_clean(&self.funding_facility_id, "funding_facility_id")?;
        validate_digest(
            &self.pre_action_authority_digest,
            "pre_action_authority_digest",
        )?;
        validate_money(&self.coverage_amount, "coverage_amount", false)?;
        if self.effective_until <= self.effective_from {
            return Err(ParametricContractError::InvalidField("effective_window"));
        }
        if self.window_seconds == 0 {
            return Err(ParametricContractError::InvalidField("window_seconds"));
        }
        if self.max_checkpoint_lag_seconds == 0 {
            return Err(ParametricContractError::InvalidField(
                "max_checkpoint_lag_seconds",
            ));
        }
        if self.window_anchor > self.effective_from {
            return Err(ParametricContractError::InvalidField("window_anchor"));
        }
        let first_offset = self.effective_from - self.window_anchor;
        let last_offset = self.effective_until - self.window_anchor;
        if !first_offset.is_multiple_of(self.window_seconds)
            || !last_offset.is_multiple_of(self.window_seconds)
        {
            return Err(ParametricContractError::InvalidField(
                "effective_window_cadence",
            ));
        }
        self.predicate.validate()?;
        self.payout_schedule
            .validate_for(&self.predicate, &self.coverage_amount)?;
        self.payout_mode.validate()?;
        self.payout_rail.validate()?;
        self.evaluator_authority.validate()
    }

    pub fn window_at(
        &self,
        cutoff: u64,
    ) -> Result<ParametricTriggerWindow, ParametricContractError> {
        self.validate()?;
        if cutoff < self.effective_from || cutoff >= self.effective_until {
            return Err(ParametricContractError::InvalidField("cutoff"));
        }
        let index = (cutoff - self.window_anchor) / self.window_seconds;
        let start_at = self
            .window_anchor
            .checked_add(
                index
                    .checked_mul(self.window_seconds)
                    .ok_or(ParametricContractError::InvalidField("window_index"))?,
            )
            .ok_or(ParametricContractError::InvalidField("window_start"))?;
        let end_at = start_at
            .checked_add(self.window_seconds)
            .ok_or(ParametricContractError::InvalidField("window_end"))?;
        let window = ParametricTriggerWindow { start_at, end_at };
        self.validate_window(&window)?;
        Ok(window)
    }

    fn validate_window(
        &self,
        window: &ParametricTriggerWindow,
    ) -> Result<(), ParametricContractError> {
        window.validate()?;
        if window.start_at < self.effective_from || window.end_at > self.effective_until {
            return Err(ParametricContractError::BindingMismatch(
                "evaluation_window",
            ));
        }
        if window.end_at - window.start_at != self.window_seconds
            || !(window.start_at - self.window_anchor).is_multiple_of(self.window_seconds)
        {
            return Err(ParametricContractError::BindingMismatch(
                "evaluation_window_cadence",
            ));
        }
        Ok(())
    }
}

pub type SignedParametricPolicy = SignedExportEnvelope<ParametricPolicy>;

pub struct ParametricPolicyVerificationContext<'a> {
    pub bound_coverage: &'a SignedLiabilityBoundCoverage,
    pub coverage_authority_id: &'a str,
    pub coverage_authority_key: &'a PublicKey,
    pub policy_signer_key: &'a PublicKey,
    pub payer_id: &'a str,
    pub beneficiary_id: &'a str,
    pub funding_facility_id: &'a str,
    pub pre_action_authority_digest: &'a str,
    pub payout_rail: &'a ParametricPayoutRail,
    pub evaluator_authority: &'a EvaluatorAuthorityRef,
}

#[derive(Debug, Clone)]
pub struct VerifiedParametricPolicy {
    signed: SignedParametricPolicy,
    body_digest: String,
    envelope_digest: String,
}

impl VerifiedParametricPolicy {
    pub fn verify(
        signed: SignedParametricPolicy,
        context: &ParametricPolicyVerificationContext<'_>,
    ) -> Result<Self, ParametricContractError> {
        signed.body.validate()?;
        validate_policy_context(context)?;
        verify_bound_coverage(context)?;
        if &signed.signer_key != context.policy_signer_key {
            return Err(ParametricContractError::UntrustedPolicySigner);
        }
        if !signed
            .verify_signature()
            .map_err(|error| ParametricContractError::Canonicalization(error.to_string()))?
        {
            return Err(ParametricContractError::InvalidSignature);
        }
        verify_policy_bindings(&signed.body, context)?;
        let canonical = canonical_json_bytes(&signed)
            .map_err(|error| ParametricContractError::Canonicalization(error.to_string()))?;
        if canonical.len() > MAX_SIGNED_PARAMETRIC_POLICY_BYTES {
            return Err(ParametricContractError::InvalidField("signed_policy.size"));
        }
        Ok(Self {
            body_digest: canonical_digest(&signed.body)?,
            envelope_digest: sha256_hex(&canonical),
            signed,
        })
    }

    pub fn from_canonical_bytes(
        bytes: &[u8],
        context: &ParametricPolicyVerificationContext<'_>,
    ) -> Result<Self, ParametricContractError> {
        if bytes.is_empty() || bytes.len() > MAX_SIGNED_PARAMETRIC_POLICY_BYTES {
            return Err(ParametricContractError::InvalidField("signed_policy.size"));
        }
        let signed: SignedParametricPolicy = serde_json::from_slice(bytes)
            .map_err(|error| ParametricContractError::Canonicalization(error.to_string()))?;
        let verified = Self::verify(signed, context)?;
        if verified.canonical_bytes()?.as_slice() != bytes {
            return Err(ParametricContractError::Canonicalization(
                "signed parametric policy is not canonical".to_string(),
            ));
        }
        Ok(verified)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ParametricContractError> {
        canonical_json_bytes(&self.signed)
            .map_err(|error| ParametricContractError::Canonicalization(error.to_string()))
    }

    pub fn verify_evidence_corpus(
        &self,
        window: ParametricTriggerWindow,
        proof: EvidenceCorpusProofV1,
        registry: &TrustedEvidenceSourceRegistry,
    ) -> Result<VerifiedEvidenceCorpusV1, ParametricContractError> {
        self.signed.body.validate_window(&window)?;
        VerifiedEvidenceCorpusV1::verify(
            self.body_digest.clone(),
            &self.signed.body.predicate,
            &self.signed.body.subject_key,
            window,
            self.signed.body.max_checkpoint_lag_seconds,
            proof,
            registry,
        )
    }

    pub fn claim_identity(
        &self,
        corpus: &VerifiedEvidenceCorpusV1,
    ) -> Result<ParametricClaimIdentity, ParametricContractError> {
        corpus.ensure_policy(&self.body_digest)?;
        self.signed.body.validate_window(corpus.window())?;
        let key = TriggerInstanceKeyV1 {
            parametric_policy_body_digest: self.body_digest.clone(),
            bound_coverage_body_digest: self.signed.body.bound_coverage_body_digest.clone(),
            subject_key: self.signed.body.subject_key.clone(),
            trigger_predicate_body_digest: domain_digest(
                TRIGGER_PREDICATE_DIGEST_DOMAIN,
                &self.signed.body.predicate,
            )?,
            window_start: corpus.window().start_at,
            window_end: corpus.window().end_at,
            evidence_range_digest: corpus.evidence_range_digest().to_owned(),
        };
        let trigger_instance_id = key.trigger_instance_id()?;
        let claim_id = parametric_claim_id(&trigger_instance_id)?;
        Ok(ParametricClaimIdentity {
            key,
            trigger_instance_id,
            claim_id,
        })
    }

    pub fn evaluate_trigger(
        &self,
        corpus: &VerifiedEvidenceCorpusV1,
    ) -> Result<VerifiedTriggerVerdictV1, ParametricContractError> {
        corpus.ensure_policy(&self.body_digest)?;
        match corpus.evaluate(&self.signed.body.predicate)? {
            Some(magnitude) => Ok(VerifiedTriggerVerdictV1::Fired(Box::new(
                VerifiedFiredTriggerV1::new(
                    self.body_digest.clone(),
                    self.claim_identity(corpus)?,
                    magnitude,
                ),
            ))),
            None => Ok(VerifiedTriggerVerdictV1::NotFired),
        }
    }

    #[must_use]
    pub const fn body(&self) -> &ParametricPolicy {
        &self.signed.body
    }

    #[must_use]
    pub const fn signed(&self) -> &SignedParametricPolicy {
        &self.signed
    }

    #[must_use]
    pub fn body_digest(&self) -> &str {
        &self.body_digest
    }

    #[must_use]
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSourceKind {
    ReceiptStore,
    DriftReports,
    SettlementReconciliations,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParametricTriggerWindow {
    pub start_at: u64,
    pub end_at: u64,
}

impl ParametricTriggerWindow {
    fn validate(&self) -> Result<(), ParametricContractError> {
        if self.end_at <= self.start_at {
            return Err(ParametricContractError::InvalidField("evaluation_window"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InclusiveSequenceRange {
    pub first: u64,
    pub last: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceSourceRangeV1 {
    pub source_kind: EvidenceSourceKind,
    pub source_id: String,
    pub index_namespace: String,
    pub subject_key: String,
    pub window: ParametricTriggerWindow,
    pub sequence_range: Option<InclusiveSequenceRange>,
    pub expected_count: u64,
    pub source_prefix_cutoff: u64,
    pub selected_member_root: String,
    pub anchor_epoch: u64,
    pub signer_key_epoch: u64,
    pub checkpoint_id: String,
    pub checkpoint_root: String,
    pub checkpoint_at: u64,
    pub query_index_root: String,
    pub range_proof_digest: String,
}

impl EvidenceSourceRangeV1 {
    fn validate(
        &self,
        subject_key: &str,
        window: &ParametricTriggerWindow,
        max_checkpoint_lag_seconds: u64,
    ) -> Result<(), ParametricContractError> {
        validate_clean(&self.source_id, "corpus.source_id")?;
        validate_clean(&self.index_namespace, "corpus.index_namespace")?;
        validate_clean(&self.subject_key, "corpus.subject_key")?;
        validate_digest(&self.selected_member_root, "corpus.selected_member_root")?;
        validate_clean(&self.checkpoint_id, "corpus.checkpoint_id")?;
        validate_digest(&self.checkpoint_root, "corpus.checkpoint_root")?;
        validate_digest(&self.query_index_root, "corpus.query_index_root")?;
        validate_digest(&self.range_proof_digest, "corpus.range_proof_digest")?;
        if self.anchor_epoch == 0 || self.signer_key_epoch == 0 {
            return Err(ParametricContractError::InvalidField("corpus.epoch"));
        }
        if self.subject_key != subject_key {
            return Err(ParametricContractError::BindingMismatch(
                "corpus.subject_key",
            ));
        }
        if &self.window != window {
            return Err(ParametricContractError::BindingMismatch("corpus.window"));
        }
        if self.checkpoint_at < window.end_at
            || self.checkpoint_at - window.end_at > max_checkpoint_lag_seconds
        {
            return Err(ParametricContractError::InvalidField(
                "corpus.checkpoint_at",
            ));
        }
        match &self.sequence_range {
            Some(sequence) => {
                if sequence.last < sequence.first || sequence.last > self.source_prefix_cutoff {
                    return Err(ParametricContractError::InvalidField(
                        "corpus.sequence_range",
                    ));
                }
                let span = sequence
                    .last
                    .checked_sub(sequence.first)
                    .and_then(|difference| difference.checked_add(1))
                    .ok_or(ParametricContractError::InvalidField(
                        "corpus.expected_count",
                    ))?;
                if self.expected_count == 0 || self.expected_count > span {
                    return Err(ParametricContractError::InvalidField(
                        "corpus.expected_count",
                    ));
                }
            }
            None if self.expected_count == 0 => {}
            None => {
                return Err(ParametricContractError::InvalidField(
                    "corpus.expected_count",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceCorpusManifestV1 {
    pub ranges: Vec<EvidenceSourceRangeV1>,
}

impl EvidenceCorpusManifestV1 {
    fn semantic_digest(
        &self,
        predicate: &TriggerPredicate,
        subject_key: &str,
        window: &ParametricTriggerWindow,
        max_checkpoint_lag_seconds: u64,
    ) -> Result<String, ParametricContractError> {
        let required = predicate.required_sources();
        if self.ranges.len() != required.len() {
            return Err(ParametricContractError::InvalidField("corpus.source_count"));
        }
        let mut seen = BTreeSet::new();
        let mut identities = Vec::with_capacity(self.ranges.len());
        for range in &self.ranges {
            range.validate(subject_key, window, max_checkpoint_lag_seconds)?;
            if !required.contains(&range.source_kind) || !seen.insert(range.source_kind) {
                return Err(ParametricContractError::InvalidField("corpus.source_kind"));
            }
            identities.push(SemanticEvidenceRange {
                source_kind: range.source_kind,
                source_id: &range.source_id,
                index_namespace: &range.index_namespace,
                subject_key: &range.subject_key,
                window: &range.window,
                sequence_range: &range.sequence_range,
                expected_count: range.expected_count,
                selected_member_root: &range.selected_member_root,
            });
        }
        identities.sort_unstable_by(|left, right| {
            (left.source_kind, left.source_id, left.index_namespace).cmp(&(
                right.source_kind,
                right.source_id,
                right.index_namespace,
            ))
        });
        domain_digest(EVIDENCE_RANGE_DIGEST_DOMAIN, &identities)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SemanticEvidenceRange<'a> {
    source_kind: EvidenceSourceKind,
    source_id: &'a str,
    index_namespace: &'a str,
    subject_key: &'a str,
    window: &'a ParametricTriggerWindow,
    sequence_range: &'a Option<InclusiveSequenceRange>,
    expected_count: u64,
    selected_member_root: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TriggerInstanceKeyV1 {
    pub parametric_policy_body_digest: String,
    pub bound_coverage_body_digest: String,
    pub subject_key: String,
    pub trigger_predicate_body_digest: String,
    pub window_start: u64,
    pub window_end: u64,
    pub evidence_range_digest: String,
}

impl TriggerInstanceKeyV1 {
    pub fn validate(&self) -> Result<(), ParametricContractError> {
        validate_digest(
            &self.parametric_policy_body_digest,
            "trigger_key.parametric_policy_body_digest",
        )?;
        validate_digest(
            &self.bound_coverage_body_digest,
            "trigger_key.bound_coverage_body_digest",
        )?;
        validate_clean(&self.subject_key, "trigger_key.subject_key")?;
        validate_digest(
            &self.trigger_predicate_body_digest,
            "trigger_key.trigger_predicate_body_digest",
        )?;
        validate_digest(
            &self.evidence_range_digest,
            "trigger_key.evidence_range_digest",
        )?;
        if self.window_end <= self.window_start {
            return Err(ParametricContractError::InvalidField("trigger_key.window"));
        }
        Ok(())
    }

    pub fn trigger_instance_id(&self) -> Result<String, ParametricContractError> {
        self.validate()?;
        domain_digest(TRIGGER_INSTANCE_ID_DOMAIN, self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParametricClaimIdentity {
    pub key: TriggerInstanceKeyV1,
    pub trigger_instance_id: String,
    pub claim_id: String,
}

impl ParametricClaimIdentity {
    pub fn validate(&self) -> Result<(), ParametricContractError> {
        self.key.validate()?;
        require_binding(
            self.trigger_instance_id == self.key.trigger_instance_id()?,
            "claim_identity.trigger_instance_id",
        )?;
        require_binding(
            self.claim_id == parametric_claim_id(&self.trigger_instance_id)?,
            "claim_identity.claim_id",
        )
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClaimIdPreimage<'a> {
    trigger_instance_id: &'a str,
}

pub fn parametric_claim_id(trigger_instance_id: &str) -> Result<String, ParametricContractError> {
    validate_digest(trigger_instance_id, "trigger_instance_id")?;
    domain_digest(
        PARAMETRIC_CLAIM_ID_DOMAIN,
        &ClaimIdPreimage {
            trigger_instance_id,
        },
    )
}

fn validate_policy_context(
    context: &ParametricPolicyVerificationContext<'_>,
) -> Result<(), ParametricContractError> {
    validate_clean(
        context.coverage_authority_id,
        "trusted.coverage_authority_id",
    )?;
    validate_clean(context.payer_id, "trusted.payer_id")?;
    validate_clean(context.beneficiary_id, "trusted.beneficiary_id")?;
    validate_clean(context.funding_facility_id, "trusted.funding_facility_id")?;
    validate_digest(
        context.pre_action_authority_digest,
        "trusted.pre_action_authority_digest",
    )?;
    context.payout_rail.validate()?;
    context.evaluator_authority.validate()
}

fn verify_bound_coverage(
    context: &ParametricPolicyVerificationContext<'_>,
) -> Result<(), ParametricContractError> {
    let coverage = context.bound_coverage;
    if coverage.body.schema != LIABILITY_BOUND_COVERAGE_ARTIFACT_SCHEMA {
        return Err(ParametricContractError::UnknownSchema(
            coverage.body.schema.clone(),
        ));
    }
    if !coverage
        .verify_signature()
        .map_err(|error| ParametricContractError::Canonicalization(error.to_string()))?
    {
        return Err(ParametricContractError::InvalidSignature);
    }
    coverage
        .body
        .validate()
        .map_err(|_| ParametricContractError::InvalidField("bound_coverage"))?;
    if coverage.body.bound_at > coverage.body.effective_from {
        return Err(ParametricContractError::InvalidField(
            "bound_coverage.bound_at",
        ));
    }
    if &coverage.signer_key != context.coverage_authority_key {
        return Err(ParametricContractError::UntrustedCoverageAuthority);
    }
    let provider_id = bound_coverage_provider_id(&coverage.body);
    if provider_id != context.coverage_authority_id {
        return Err(ParametricContractError::BindingMismatch(
            "trusted.coverage_authority_id",
        ));
    }
    Ok(())
}

fn verify_policy_bindings(
    policy: &ParametricPolicy,
    context: &ParametricPolicyVerificationContext<'_>,
) -> Result<(), ParametricContractError> {
    let coverage = &context.bound_coverage.body;
    require_binding(
        policy.bound_coverage_body_digest == canonical_digest(coverage)?,
        "bound_coverage_body_digest",
    )?;
    require_binding(
        policy.bound_coverage_envelope_digest == canonical_digest(context.bound_coverage)?,
        "bound_coverage_envelope_digest",
    )?;
    require_binding(
        policy.coverage_authority_id == context.coverage_authority_id,
        "coverage_authority_id",
    )?;
    require_binding(policy.payer_id == context.payer_id, "payer_id")?;
    require_binding(
        policy.beneficiary_id == context.beneficiary_id,
        "beneficiary_id",
    )?;
    require_binding(
        policy.beneficiary_id == bound_coverage_subject_key(coverage),
        "beneficiary_id",
    )?;
    require_binding(
        policy.funding_facility_id == context.funding_facility_id,
        "funding_facility_id",
    )?;
    require_binding(
        policy.pre_action_authority_digest == context.pre_action_authority_digest,
        "pre_action_authority_digest",
    )?;
    require_binding(policy.payout_rail == *context.payout_rail, "payout_rail")?;
    require_binding(
        policy.evaluator_authority == *context.evaluator_authority,
        "evaluator_authority",
    )?;
    require_binding(
        policy.subject_key == bound_coverage_subject_key(coverage),
        "subject_key",
    )?;
    require_binding(
        policy.coverage_amount == coverage.coverage_amount,
        "coverage_amount",
    )?;
    require_binding(
        policy.effective_from == coverage.effective_from
            && policy.effective_until == coverage.effective_until,
        "effective_window",
    )?;
    if policy.issued_at < coverage.bound_at || policy.issued_at > coverage.effective_from {
        return Err(ParametricContractError::BindingMismatch("issued_at"));
    }
    Ok(())
}

fn bound_coverage_provider_id(coverage: &LiabilityBoundCoverageArtifact) -> &str {
    &coverage
        .placement
        .body
        .quote_response
        .body
        .quote_request
        .body
        .provider_policy
        .provider_id
}

fn bound_coverage_subject_key(coverage: &LiabilityBoundCoverageArtifact) -> &str {
    &coverage
        .placement
        .body
        .quote_response
        .body
        .quote_request
        .body
        .risk_package
        .body
        .subject_key
}

fn require_binding(condition: bool, field: &'static str) -> Result<(), ParametricContractError> {
    if condition {
        Ok(())
    } else {
        Err(ParametricContractError::BindingMismatch(field))
    }
}

fn validate_schedule_currency(
    amount: &MonetaryAmount,
    coverage: &MonetaryAmount,
) -> Result<(), ParametricContractError> {
    if amount.currency == coverage.currency {
        Ok(())
    } else {
        Err(ParametricContractError::InvalidField(
            "payout_schedule.currency",
        ))
    }
}

fn validate_money(
    amount: &MonetaryAmount,
    field: &'static str,
    allow_zero: bool,
) -> Result<(), ParametricContractError> {
    if (!allow_zero && amount.units == 0)
        || amount.currency.len() != 3
        || !amount
            .currency
            .bytes()
            .all(|byte| byte.is_ascii_uppercase())
    {
        return Err(ParametricContractError::InvalidField(field));
    }
    Ok(())
}

fn validate_clean(value: &str, field: &'static str) -> Result<(), ParametricContractError> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        Err(ParametricContractError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), ParametricContractError> {
    if is_sha256_hex(value) {
        Ok(())
    } else {
        Err(ParametricContractError::InvalidField(field))
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, ParametricContractError> {
    canonical_json_bytes(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| ParametricContractError::Canonicalization(error.to_string()))
}

fn domain_digest<T: Serialize>(domain: &str, value: &T) -> Result<String, ParametricContractError> {
    let canonical = canonical_json_bytes(value)
        .map_err(|error| ParametricContractError::Canonicalization(error.to_string()))?;
    let mut preimage = Vec::with_capacity(domain.len() + 1 + canonical.len());
    preimage.extend_from_slice(domain.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(&canonical);
    Ok(sha256_hex(&preimage))
}
