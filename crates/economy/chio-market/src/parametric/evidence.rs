use std::collections::{BTreeMap, BTreeSet};

use chio_core_types::{Hash, MerkleProof};
use serde::{Deserialize, Serialize};

use super::{
    canonical_digest, canonical_json_bytes, domain_digest, require_binding, validate_clean,
    validate_digest, EvidenceCorpusManifestV1, EvidenceSourceKind, EvidenceSourceRangeV1,
    InclusiveSequenceRange, ParametricClaimIdentity, ParametricContractError,
    ParametricTriggerWindow, TriggerMagnitude, TriggerPredicate,
};
use crate::crypto::PublicKey;
use crate::receipt::lineage::SignedExportEnvelope;

pub const EVIDENCE_SOURCE_CHECKPOINT_SCHEMA: &str = "chio.parametric.evidence-source-checkpoint.v1";
pub const EVIDENCE_SOURCE_CHECKPOINT_DOMAIN: &str = "chio.parametric.evidence-source-checkpoint.v1";
pub const EVIDENCE_SELECTED_MEMBER_ROOT_DOMAIN: &str = "chio.parametric.selected-member-root.v1";
pub const MAX_EVIDENCE_RANGE_MEMBERS: usize = 10_000;
pub const MAX_EVIDENCE_MERKLE_PATH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedEvidenceSource {
    source_kind: EvidenceSourceKind,
    source_id: String,
    index_namespace: String,
    anchor_epoch: u64,
    signer_key_epoch: u64,
    signature_domain: String,
    signer_key: PublicKey,
}

impl TrustedEvidenceSource {
    pub fn new(
        source_kind: EvidenceSourceKind,
        source_id: String,
        index_namespace: String,
        anchor_epoch: u64,
        signer_key_epoch: u64,
        signature_domain: String,
        signer_key: PublicKey,
    ) -> Result<Self, ParametricContractError> {
        validate_clean(&source_id, "trusted_evidence_source.source_id")?;
        validate_clean(&index_namespace, "trusted_evidence_source.index_namespace")?;
        validate_clean(
            &signature_domain,
            "trusted_evidence_source.signature_domain",
        )?;
        if anchor_epoch == 0 || signer_key_epoch == 0 {
            return Err(ParametricContractError::InvalidField(
                "trusted_evidence_source.epoch",
            ));
        }
        Ok(Self {
            source_kind,
            source_id,
            index_namespace,
            anchor_epoch,
            signer_key_epoch,
            signature_domain,
            signer_key,
        })
    }
}

#[derive(Debug, Clone)]
pub struct TrustedEvidenceSourceRegistry {
    sources: BTreeMap<(EvidenceSourceKind, String), TrustedEvidenceSource>,
}

impl TrustedEvidenceSourceRegistry {
    pub fn new(sources: Vec<TrustedEvidenceSource>) -> Result<Self, ParametricContractError> {
        if sources.is_empty() {
            return Err(ParametricContractError::InvalidField(
                "trusted_evidence_sources",
            ));
        }
        let mut indexed = BTreeMap::new();
        for source in sources {
            let key = (source.source_kind, source.source_id.clone());
            if indexed.insert(key, source).is_some() {
                return Err(ParametricContractError::InvalidField(
                    "trusted_evidence_sources.duplicate",
                ));
            }
        }
        Ok(Self { sources: indexed })
    }

    fn resolve(
        &self,
        source_kind: EvidenceSourceKind,
        source_id: &str,
    ) -> Result<&TrustedEvidenceSource, ParametricContractError> {
        self.sources
            .get(&(source_kind, source_id.to_owned()))
            .ok_or(ParametricContractError::UntrustedEvidenceSource)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum EvidenceObservationV1 {
    GuardDecision { denied: bool },
    DriftReport { critical: bool },
    SettlementReceipt { obligation_id: String },
    SettlementReconciliation { obligation_id: String, failed: bool },
}

impl EvidenceObservationV1 {
    fn validate_for_source(
        &self,
        source_kind: EvidenceSourceKind,
    ) -> Result<(), ParametricContractError> {
        match (source_kind, self) {
            (EvidenceSourceKind::ReceiptStore, Self::GuardDecision { .. }) => Ok(()),
            (EvidenceSourceKind::ReceiptStore, Self::SettlementReceipt { obligation_id })
            | (
                EvidenceSourceKind::SettlementReconciliations,
                Self::SettlementReconciliation { obligation_id, .. },
            ) => validate_clean(obligation_id, "corpus.obligation_id"),
            (EvidenceSourceKind::DriftReports, Self::DriftReport { .. }) => Ok(()),
            _ => Err(ParametricContractError::BindingMismatch(
                "corpus.observation_source",
            )),
        }
    }

    fn matches_predicate(
        &self,
        source_kind: EvidenceSourceKind,
        predicate: &TriggerPredicate,
    ) -> bool {
        matches!(
            (source_kind, predicate, self),
            (
                EvidenceSourceKind::ReceiptStore,
                TriggerPredicate::GuardDenialRate { .. },
                Self::GuardDecision { .. }
            ) | (
                EvidenceSourceKind::DriftReports,
                TriggerPredicate::DriftSeverity { .. },
                Self::DriftReport { .. }
            ) | (
                EvidenceSourceKind::ReceiptStore,
                TriggerPredicate::SettlementFailureCount { .. },
                Self::SettlementReceipt { .. }
            ) | (
                EvidenceSourceKind::SettlementReconciliations,
                TriggerPredicate::SettlementFailureCount { .. },
                Self::SettlementReconciliation { .. }
            )
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceIndexMemberV1 {
    pub sequence: u64,
    pub subject_key: String,
    pub observed_at: u64,
    pub artifact_digest: String,
    pub observation: EvidenceObservationV1,
}

impl EvidenceIndexMemberV1 {
    fn validate(
        &self,
        source_kind: EvidenceSourceKind,
        source_prefix_cutoff: u64,
        checkpoint_at: u64,
    ) -> Result<(), ParametricContractError> {
        validate_clean(&self.subject_key, "corpus.member.subject_key")?;
        validate_digest(&self.artifact_digest, "corpus.member.artifact_digest")?;
        if self.sequence > source_prefix_cutoff || self.observed_at > checkpoint_at {
            return Err(ParametricContractError::InvalidField(
                "corpus.member.position",
            ));
        }
        self.observation.validate_for_source(source_kind)
    }

    fn is_selected(&self, subject_key: &str, window: &ParametricTriggerWindow) -> bool {
        self.subject_key == subject_key
            && self.observed_at >= window.start_at
            && self.observed_at < window.end_at
    }

    fn is_before(&self, subject_key: &str, window: &ParametricTriggerWindow) -> bool {
        self.subject_key.as_str() < subject_key
            || (self.subject_key == subject_key && self.observed_at < window.start_at)
    }

    fn is_after(&self, subject_key: &str, window: &ParametricTriggerWindow) -> bool {
        self.subject_key.as_str() > subject_key
            || (self.subject_key == subject_key && self.observed_at >= window.end_at)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceSourceCheckpointV1 {
    pub schema: String,
    pub signature_domain: String,
    pub source_kind: EvidenceSourceKind,
    pub source_id: String,
    pub index_namespace: String,
    pub anchor_epoch: u64,
    pub signer_key_epoch: u64,
    pub checkpoint_id: String,
    pub checkpoint_at: u64,
    pub source_prefix_cutoff: u64,
    pub query_tree_size: u64,
    pub query_index_root: String,
}

impl EvidenceSourceCheckpointV1 {
    fn validate(&self) -> Result<(), ParametricContractError> {
        if self.schema != EVIDENCE_SOURCE_CHECKPOINT_SCHEMA {
            return Err(ParametricContractError::UnknownSchema(self.schema.clone()));
        }
        validate_clean(&self.signature_domain, "corpus.signature_domain")?;
        validate_clean(&self.source_id, "corpus.source_id")?;
        validate_clean(&self.index_namespace, "corpus.index_namespace")?;
        validate_clean(&self.checkpoint_id, "corpus.checkpoint_id")?;
        validate_digest(&self.query_index_root, "corpus.query_index_root")?;
        if self.anchor_epoch == 0 || self.signer_key_epoch == 0 {
            return Err(ParametricContractError::InvalidField("corpus.epoch"));
        }
        if self.query_tree_size == 0 && self.query_index_root != Hash::zero().to_hex() {
            return Err(ParametricContractError::BindingMismatch(
                "corpus.empty_query_index_root",
            ));
        }
        Ok(())
    }
}

pub type SignedEvidenceSourceCheckpointV1 = SignedExportEnvelope<EvidenceSourceCheckpointV1>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceMerkleProofV1 {
    pub tree_size: u64,
    pub leaf_index: u64,
    pub audit_path: Vec<String>,
}

impl EvidenceMerkleProofV1 {
    fn verify(
        &self,
        member: &EvidenceIndexMemberV1,
        checkpoint: &EvidenceSourceCheckpointV1,
        expected_root: &Hash,
    ) -> Result<(), ParametricContractError> {
        if self.tree_size != checkpoint.query_tree_size
            || self.audit_path.len() > MAX_EVIDENCE_MERKLE_PATH
        {
            return Err(ParametricContractError::InvalidEvidenceRangeProof);
        }
        let tree_size = usize::try_from(self.tree_size)
            .map_err(|_| ParametricContractError::InvalidEvidenceRangeProof)?;
        let leaf_index = usize::try_from(self.leaf_index)
            .map_err(|_| ParametricContractError::InvalidEvidenceRangeProof)?;
        let audit_path = self
            .audit_path
            .iter()
            .map(|hash| {
                Hash::from_hex(hash).map_err(|_| ParametricContractError::InvalidEvidenceRangeProof)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let proof = MerkleProof {
            tree_size,
            leaf_index,
            audit_path,
        };
        let canonical = canonical_json_bytes(member)
            .map_err(|error| ParametricContractError::Canonicalization(error.to_string()))?;
        if !proof.verify(&canonical, expected_root) {
            return Err(ParametricContractError::InvalidEvidenceRangeProof);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProvenEvidenceMemberV1 {
    pub member: EvidenceIndexMemberV1,
    pub proof: EvidenceMerkleProofV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceSourceRangeProofV1 {
    pub checkpoint: SignedEvidenceSourceCheckpointV1,
    pub members: Vec<ProvenEvidenceMemberV1>,
    pub predecessor: Option<ProvenEvidenceMemberV1>,
    pub successor: Option<ProvenEvidenceMemberV1>,
    pub selected_count: u64,
    pub selected_member_root: String,
}

impl EvidenceSourceRangeProofV1 {
    pub fn new(
        checkpoint: SignedEvidenceSourceCheckpointV1,
        members: Vec<ProvenEvidenceMemberV1>,
        predecessor: Option<ProvenEvidenceMemberV1>,
        successor: Option<ProvenEvidenceMemberV1>,
    ) -> Result<Self, ParametricContractError> {
        let selected_count = u64::try_from(members.len())
            .map_err(|_| ParametricContractError::InvalidField("corpus.selected_count"))?;
        let selected_member_root = selected_member_root(&members)?;
        Ok(Self {
            checkpoint,
            members,
            predecessor,
            successor,
            selected_count,
            selected_member_root,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceCorpusProofV1 {
    pub ranges: Vec<EvidenceSourceRangeProofV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEvidenceCorpusV1 {
    policy_body_digest: String,
    window: ParametricTriggerWindow,
    manifest: EvidenceCorpusManifestV1,
    evidence_range_digest: String,
    selected_members: BTreeMap<EvidenceSourceKind, Vec<EvidenceIndexMemberV1>>,
}

impl VerifiedEvidenceCorpusV1 {
    pub(super) fn verify(
        policy_body_digest: String,
        predicate: &TriggerPredicate,
        subject_key: &str,
        window: ParametricTriggerWindow,
        max_checkpoint_lag_seconds: u64,
        proof: EvidenceCorpusProofV1,
        registry: &TrustedEvidenceSourceRegistry,
    ) -> Result<Self, ParametricContractError> {
        let required = predicate.required_sources();
        if proof.ranges.len() != required.len() {
            return Err(ParametricContractError::InvalidField("corpus.source_count"));
        }
        let mut seen = BTreeSet::new();
        let mut ranges = Vec::with_capacity(proof.ranges.len());
        let mut selected_members = BTreeMap::new();
        for range_proof in proof.ranges {
            let source_kind = range_proof.checkpoint.body.source_kind;
            if !required.contains(&source_kind) || !seen.insert(source_kind) {
                return Err(ParametricContractError::InvalidField("corpus.source_kind"));
            }
            let verified = verify_source_range(
                &range_proof,
                predicate,
                subject_key,
                &window,
                max_checkpoint_lag_seconds,
                registry,
            )?;
            ranges.push(verified.range);
            selected_members.insert(source_kind, verified.members);
        }
        let manifest = EvidenceCorpusManifestV1 { ranges };
        let evidence_range_digest = manifest.semantic_digest(
            predicate,
            subject_key,
            &window,
            max_checkpoint_lag_seconds,
        )?;
        Ok(Self {
            policy_body_digest,
            window,
            manifest,
            evidence_range_digest,
            selected_members,
        })
    }

    #[must_use]
    pub const fn manifest(&self) -> &EvidenceCorpusManifestV1 {
        &self.manifest
    }

    #[must_use]
    pub const fn window(&self) -> &ParametricTriggerWindow {
        &self.window
    }

    pub(super) fn ensure_policy(
        &self,
        policy_body_digest: &str,
    ) -> Result<(), ParametricContractError> {
        require_binding(
            self.policy_body_digest == policy_body_digest,
            "corpus.policy_body_digest",
        )
    }

    pub(super) fn evidence_range_digest(&self) -> &str {
        &self.evidence_range_digest
    }

    pub(super) fn evaluate(
        &self,
        predicate: &TriggerPredicate,
    ) -> Result<Option<TriggerMagnitude>, ParametricContractError> {
        match predicate {
            TriggerPredicate::GuardDenialRate {
                min_events,
                threshold_bps,
            } => {
                let members = self.members(EvidenceSourceKind::ReceiptStore)?;
                let total = u64::try_from(members.len())
                    .map_err(|_| ParametricContractError::InvalidField("corpus.member_count"))?;
                let denied = members
                    .iter()
                    .filter(|member| {
                        matches!(
                            &member.observation,
                            EvidenceObservationV1::GuardDecision { denied: true }
                        )
                    })
                    .count();
                let denied = u64::try_from(denied)
                    .map_err(|_| ParametricContractError::InvalidField("corpus.member_count"))?;
                let magnitude = if total == 0 {
                    0
                } else {
                    denied
                        .checked_mul(10_000)
                        .ok_or(ParametricContractError::InvalidField("trigger.magnitude"))?
                        / total
                };
                Ok(
                    (total >= *min_events && magnitude >= u64::from(*threshold_bps))
                        .then_some(TriggerMagnitude::BasisPoints { value: magnitude }),
                )
            }
            TriggerPredicate::DriftSeverity { min_critical } => {
                let members = self.members(EvidenceSourceKind::DriftReports)?;
                let critical = members
                    .iter()
                    .filter(|member| {
                        matches!(
                            &member.observation,
                            EvidenceObservationV1::DriftReport { critical: true }
                        )
                    })
                    .count();
                let critical = u64::try_from(critical)
                    .map_err(|_| ParametricContractError::InvalidField("corpus.member_count"))?;
                Ok((critical >= *min_critical)
                    .then_some(TriggerMagnitude::Count { value: critical }))
            }
            TriggerPredicate::SettlementFailureCount { min_failures } => {
                self.evaluate_settlement_failures(*min_failures)
            }
        }
    }

    fn members(
        &self,
        source_kind: EvidenceSourceKind,
    ) -> Result<&[EvidenceIndexMemberV1], ParametricContractError> {
        self.selected_members
            .get(&source_kind)
            .map(Vec::as_slice)
            .ok_or(ParametricContractError::InvalidField("corpus.source_kind"))
    }

    fn evaluate_settlement_failures(
        &self,
        min_failures: u64,
    ) -> Result<Option<TriggerMagnitude>, ParametricContractError> {
        let receipts = self.members(EvidenceSourceKind::ReceiptStore)?;
        let reconciliations = self.members(EvidenceSourceKind::SettlementReconciliations)?;
        let mut receipt_ids = BTreeSet::new();
        for member in receipts {
            let EvidenceObservationV1::SettlementReceipt { obligation_id } = &member.observation
            else {
                return Err(ParametricContractError::BindingMismatch(
                    "corpus.observation_predicate",
                ));
            };
            if !receipt_ids.insert(obligation_id.as_str()) {
                return Err(ParametricContractError::InvalidField(
                    "corpus.duplicate_obligation",
                ));
            }
        }
        let mut reconciliation_ids = BTreeSet::new();
        let mut failures = 0_u64;
        for member in reconciliations {
            let EvidenceObservationV1::SettlementReconciliation {
                obligation_id,
                failed,
            } = &member.observation
            else {
                return Err(ParametricContractError::BindingMismatch(
                    "corpus.observation_predicate",
                ));
            };
            if !reconciliation_ids.insert(obligation_id.as_str()) {
                return Err(ParametricContractError::InvalidField(
                    "corpus.duplicate_obligation",
                ));
            }
            if *failed {
                failures = failures
                    .checked_add(1)
                    .ok_or(ParametricContractError::InvalidField("trigger.magnitude"))?;
            }
        }
        require_binding(
            receipt_ids == reconciliation_ids,
            "corpus.settlement_completeness",
        )?;
        Ok((failures >= min_failures).then_some(TriggerMagnitude::Count { value: failures }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedTriggerVerdictV1 {
    Fired(Box<VerifiedFiredTriggerV1>),
    NotFired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFiredTriggerV1 {
    policy_body_digest: String,
    identity: ParametricClaimIdentity,
    magnitude: TriggerMagnitude,
}

impl VerifiedFiredTriggerV1 {
    pub(super) fn new(
        policy_body_digest: String,
        identity: ParametricClaimIdentity,
        magnitude: TriggerMagnitude,
    ) -> Self {
        Self {
            policy_body_digest,
            identity,
            magnitude,
        }
    }

    #[must_use]
    pub const fn identity(&self) -> &ParametricClaimIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn magnitude(&self) -> &TriggerMagnitude {
        &self.magnitude
    }

    pub(super) fn ensure_policy(
        &self,
        policy_body_digest: &str,
    ) -> Result<(), ParametricContractError> {
        require_binding(
            self.policy_body_digest == policy_body_digest,
            "trigger.policy_body_digest",
        )
    }
}

struct VerifiedSourceRange {
    range: EvidenceSourceRangeV1,
    members: Vec<EvidenceIndexMemberV1>,
}

fn verify_source_range(
    proof: &EvidenceSourceRangeProofV1,
    predicate: &TriggerPredicate,
    subject_key: &str,
    window: &ParametricTriggerWindow,
    max_checkpoint_lag_seconds: u64,
    registry: &TrustedEvidenceSourceRegistry,
) -> Result<VerifiedSourceRange, ParametricContractError> {
    let checkpoint = &proof.checkpoint.body;
    checkpoint.validate()?;
    let trusted = registry.resolve(checkpoint.source_kind, &checkpoint.source_id)?;
    require_binding(
        checkpoint.index_namespace == trusted.index_namespace,
        "corpus.index_namespace",
    )?;
    require_binding(
        checkpoint.signature_domain == trusted.signature_domain,
        "corpus.signature_domain",
    )?;
    if checkpoint.anchor_epoch != trusted.anchor_epoch {
        return Err(ParametricContractError::StaleEvidenceAnchorEpoch);
    }
    if checkpoint.signer_key_epoch != trusted.signer_key_epoch {
        return Err(ParametricContractError::StaleEvidenceSignerEpoch);
    }
    if proof.checkpoint.signer_key != trusted.signer_key {
        return Err(ParametricContractError::UntrustedEvidenceSigner);
    }
    if !proof
        .checkpoint
        .verify_signature()
        .map_err(|error| ParametricContractError::Canonicalization(error.to_string()))?
    {
        return Err(ParametricContractError::InvalidSignature);
    }
    if checkpoint.checkpoint_at < window.end_at
        || checkpoint.checkpoint_at - window.end_at > max_checkpoint_lag_seconds
    {
        return Err(ParametricContractError::InvalidField(
            "corpus.checkpoint_at",
        ));
    }
    let expected_root = Hash::from_hex(&checkpoint.query_index_root)
        .map_err(|_| ParametricContractError::InvalidEvidenceRangeProof)?;
    let members = verify_range_members(
        proof,
        predicate,
        subject_key,
        window,
        checkpoint,
        &expected_root,
    )?;
    let derived_count = u64::try_from(members.len())
        .map_err(|_| ParametricContractError::InvalidField("corpus.selected_count"))?;
    require_binding(
        proof.selected_count == derived_count,
        "corpus.selected_count",
    )?;
    let derived_member_root = selected_member_root(&proof.members)?;
    require_binding(
        proof.selected_member_root == derived_member_root,
        "corpus.selected_member_root",
    )?;
    let first_sequence = members.iter().map(|member| member.sequence).min();
    let last_sequence = members.iter().map(|member| member.sequence).max();
    let sequence_range = first_sequence
        .zip(last_sequence)
        .map(|(first, last)| InclusiveSequenceRange { first, last });
    let range = EvidenceSourceRangeV1 {
        source_kind: checkpoint.source_kind,
        source_id: checkpoint.source_id.clone(),
        index_namespace: checkpoint.index_namespace.clone(),
        subject_key: subject_key.to_owned(),
        window: window.clone(),
        sequence_range,
        expected_count: derived_count,
        source_prefix_cutoff: checkpoint.source_prefix_cutoff,
        selected_member_root: derived_member_root,
        anchor_epoch: checkpoint.anchor_epoch,
        signer_key_epoch: checkpoint.signer_key_epoch,
        checkpoint_id: checkpoint.checkpoint_id.clone(),
        checkpoint_root: canonical_digest(checkpoint)?,
        checkpoint_at: checkpoint.checkpoint_at,
        query_index_root: checkpoint.query_index_root.clone(),
        range_proof_digest: canonical_digest(proof)?,
    };
    range.validate(subject_key, window, max_checkpoint_lag_seconds)?;
    Ok(VerifiedSourceRange { range, members })
}

fn verify_range_members(
    proof: &EvidenceSourceRangeProofV1,
    predicate: &TriggerPredicate,
    subject_key: &str,
    window: &ParametricTriggerWindow,
    checkpoint: &EvidenceSourceCheckpointV1,
    expected_root: &Hash,
) -> Result<Vec<EvidenceIndexMemberV1>, ParametricContractError> {
    if proof.members.len() > MAX_EVIDENCE_RANGE_MEMBERS {
        return Err(ParametricContractError::InvalidField(
            "corpus.selected_count",
        ));
    }
    for proven in &proof.members {
        verify_proven_member(proven, checkpoint, expected_root)?;
        if !proven.member.is_selected(subject_key, window)
            || !proven
                .member
                .observation
                .matches_predicate(checkpoint.source_kind, predicate)
        {
            return Err(ParametricContractError::BindingMismatch(
                "corpus.selected_member",
            ));
        }
    }
    for pair in proof.members.windows(2) {
        if pair[0].proof.leaf_index.checked_add(1) != Some(pair[1].proof.leaf_index) {
            return Err(ParametricContractError::IncompleteEvidenceBoundaries);
        }
    }
    verify_boundaries(proof, subject_key, window, checkpoint, expected_root)?;
    Ok(proof
        .members
        .iter()
        .map(|proven| proven.member.clone())
        .collect())
}

fn verify_boundaries(
    proof: &EvidenceSourceRangeProofV1,
    subject_key: &str,
    window: &ParametricTriggerWindow,
    checkpoint: &EvidenceSourceCheckpointV1,
    expected_root: &Hash,
) -> Result<(), ParametricContractError> {
    if let Some(predecessor) = &proof.predecessor {
        verify_proven_member(predecessor, checkpoint, expected_root)?;
        if !predecessor.member.is_before(subject_key, window) {
            return Err(ParametricContractError::IncompleteEvidenceBoundaries);
        }
    }
    if let Some(successor) = &proof.successor {
        verify_proven_member(successor, checkpoint, expected_root)?;
        if !successor.member.is_after(subject_key, window) {
            return Err(ParametricContractError::IncompleteEvidenceBoundaries);
        }
    }
    match (proof.members.first(), proof.members.last()) {
        (Some(first), Some(last)) => {
            let predecessor_matches = match &proof.predecessor {
                Some(predecessor) => {
                    predecessor.proof.leaf_index.checked_add(1) == Some(first.proof.leaf_index)
                }
                None => first.proof.leaf_index == 0,
            };
            let successor_matches = match &proof.successor {
                Some(successor) => {
                    last.proof.leaf_index.checked_add(1) == Some(successor.proof.leaf_index)
                }
                None => last.proof.leaf_index.checked_add(1) == Some(checkpoint.query_tree_size),
            };
            if !predecessor_matches || !successor_matches {
                return Err(ParametricContractError::IncompleteEvidenceBoundaries);
            }
        }
        (None, None) => verify_empty_boundaries(proof, checkpoint)?,
        _ => return Err(ParametricContractError::IncompleteEvidenceBoundaries),
    }
    Ok(())
}

fn verify_empty_boundaries(
    proof: &EvidenceSourceRangeProofV1,
    checkpoint: &EvidenceSourceCheckpointV1,
) -> Result<(), ParametricContractError> {
    let complete = match (&proof.predecessor, &proof.successor) {
        (Some(predecessor), Some(successor)) => {
            predecessor.proof.leaf_index.checked_add(1) == Some(successor.proof.leaf_index)
        }
        (None, Some(successor)) => successor.proof.leaf_index == 0,
        (Some(predecessor), None) => {
            predecessor.proof.leaf_index.checked_add(1) == Some(checkpoint.query_tree_size)
        }
        (None, None) => checkpoint.query_tree_size == 0,
    };
    if complete {
        Ok(())
    } else {
        Err(ParametricContractError::IncompleteEvidenceBoundaries)
    }
}

fn verify_proven_member(
    proven: &ProvenEvidenceMemberV1,
    checkpoint: &EvidenceSourceCheckpointV1,
    expected_root: &Hash,
) -> Result<(), ParametricContractError> {
    proven.member.validate(
        checkpoint.source_kind,
        checkpoint.source_prefix_cutoff,
        checkpoint.checkpoint_at,
    )?;
    proven
        .proof
        .verify(&proven.member, checkpoint, expected_root)
}

fn selected_member_root(
    members: &[ProvenEvidenceMemberV1],
) -> Result<String, ParametricContractError> {
    let selected = members
        .iter()
        .map(|proven| &proven.member)
        .collect::<Vec<_>>();
    domain_digest(EVIDENCE_SELECTED_MEMBER_ROOT_DOMAIN, &selected)
}
