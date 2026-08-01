use std::collections::{BTreeMap, BTreeSet};

use chio_core::{canonical_json_bytes, sha256_hex};
use chio_kernel::checkpoint::{
    validate_checkpoint_transparency, verify_checkpoint_transparency_records,
    CheckpointTransparencySummary,
};
use chio_kernel::evidence_export::{
    build_evidence_transparency_claims, EvidenceExportBundle, EvidenceTransparencyClaims,
};
use chio_kernel::{is_supported_checkpoint_schema, verify_checkpoint_signature};
use serde::{Deserialize, Serialize};

use crate::bundle::MercuryBundleManifest;
use crate::receipt_metadata::{
    MercuryApprovalState, MercuryContractError, MercuryDisclosurePolicy, MercuryReceiptMetadata,
};
use crate::validation::ensure_non_empty;

pub const MERCURY_PUBLICATION_PROFILE_SCHEMA: &str = "chio.mercury.publication_profile.v1";
pub const MERCURY_PROOF_PACKAGE_SCHEMA: &str = "chio.mercury.proof_package.v1";
pub const MERCURY_INQUIRY_PACKAGE_SCHEMA: &str = "chio.mercury.inquiry_package.v1";
const CHECKPOINT_CONTINUITY_AUDIT_ONLY: &str = "audit_only";
const CHECKPOINT_CONTINUITY_TRANSPARENCY_PREVIEW: &str = "transparency_preview";
const CHECKPOINT_CONTINUITY_APPEND_ONLY: &str = "append_only";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryPublicationProfile {
    pub schema: String,
    pub checkpoint_continuity: String,
    pub inclusion_proofs_required: bool,
    pub checkpoint_signatures_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_record: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_anchor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_material: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_material: Option<String>,
    pub completeness_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freshness_window_secs: Option<u64>,
}

impl MercuryPublicationProfile {
    #[must_use]
    pub fn pilot_default() -> Self {
        Self {
            schema: MERCURY_PUBLICATION_PROFILE_SCHEMA.to_string(),
            checkpoint_continuity: CHECKPOINT_CONTINUITY_TRANSPARENCY_PREVIEW.to_string(),
            inclusion_proofs_required: true,
            checkpoint_signatures_required: true,
            witness_record: None,
            trust_anchor: None,
            rotation_material: None,
            revocation_material: None,
            completeness_mode: "best_effort".to_string(),
            freshness_window_secs: None,
        }
    }

    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_PUBLICATION_PROFILE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_PUBLICATION_PROFILE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty(
            "publication_profile.checkpoint_continuity",
            &self.checkpoint_continuity,
        )?;
        match self.checkpoint_continuity.as_str() {
            CHECKPOINT_CONTINUITY_AUDIT_ONLY | CHECKPOINT_CONTINUITY_TRANSPARENCY_PREVIEW => {
                if self
                    .trust_anchor
                    .as_deref()
                    .map(str::trim)
                    .filter(|anchor| !anchor.is_empty())
                    .is_some()
                {
                    return Err(MercuryContractError::Validation(
                        "publication_profile.trust_anchor is only valid when publication_profile.checkpoint_continuity=append_only".to_string(),
                    ));
                }
            }
            CHECKPOINT_CONTINUITY_APPEND_ONLY => {
                let trust_anchor = self.trust_anchor.as_deref().ok_or_else(|| {
                    MercuryContractError::Validation(
                        "publication_profile.checkpoint_continuity=append_only requires publication_profile.trust_anchor".to_string(),
                    )
                })?;
                ensure_non_empty("publication_profile.trust_anchor", trust_anchor)?;
            }
            other => {
                return Err(MercuryContractError::Validation(format!(
                    "unsupported publication_profile.checkpoint_continuity: {other}"
                )));
            }
        }
        ensure_non_empty(
            "publication_profile.completeness_mode",
            &self.completeness_mode,
        )
    }
}

impl Default for MercuryPublicationProfile {
    fn default() -> Self {
        Self::pilot_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryProofReceiptRecord {
    pub receipt_id: String,
    pub seq: u64,
    pub metadata: MercuryReceiptMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MercuryProofPackage {
    pub schema: String,
    pub package_id: String,
    pub created_at: u64,
    pub evidence_export_manifest_hash: String,
    pub evidence_export_schema: String,
    pub evidence_exported_at: u64,
    pub workflow_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desk_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy_id: Option<String>,
    pub publication_profile: MercuryPublicationProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication_claim_boundary: Option<EvidenceTransparencyClaims>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_transparency: Option<CheckpointTransparencySummary>,
    pub receipt_records: Vec<MercuryProofReceiptRecord>,
    pub bundle_manifests: Vec<MercuryBundleManifest>,
    pub chio_bundle: EvidenceExportBundle,
}

impl MercuryProofPackage {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        chio_bundle: EvidenceExportBundle,
        evidence_export_manifest_hash: impl Into<String>,
        evidence_export_schema: impl Into<String>,
        evidence_exported_at: u64,
        created_at: u64,
        publication_profile: MercuryPublicationProfile,
        checkpoint_transparency: Option<CheckpointTransparencySummary>,
        bundle_manifests: Vec<MercuryBundleManifest>,
    ) -> Result<Self, MercuryContractError> {
        if chio_bundle.tool_receipts.is_empty() {
            return Err(MercuryContractError::MissingField(
                "chio_bundle.tool_receipts",
            ));
        }

        let receipt_records = chio_bundle
            .tool_receipts
            .iter()
            .map(|record| {
                let metadata =
                    MercuryReceiptMetadata::from_receipt(&record.receipt)?.ok_or_else(|| {
                        MercuryContractError::Validation(format!(
                            "tool receipt {} is missing receipt.metadata.mercury",
                            record.receipt.id
                        ))
                    })?;
                Ok(MercuryProofReceiptRecord {
                    receipt_id: record.receipt.id.clone(),
                    seq: record.seq,
                    metadata,
                })
            })
            .collect::<Result<Vec<_>, MercuryContractError>>()?;

        let first = receipt_records
            .first()
            .ok_or(MercuryContractError::MissingField("receipt_records"))?;
        let workflow_id = first.metadata.business_ids.workflow_id.clone();
        for record in &receipt_records {
            if record.metadata.business_ids.workflow_id != workflow_id {
                return Err(MercuryContractError::Validation(
                    "all proof-package receipts must share one workflow_id".to_string(),
                ));
            }
        }

        let mut publication_profile = publication_profile;
        if chio_bundle.uncheckpointed_receipts.is_empty() {
            publication_profile.completeness_mode = "full_checkpoint_coverage".to_string();
        }
        publication_profile.validate()?;

        let evidence_export_manifest_hash = evidence_export_manifest_hash.into();
        let evidence_export_schema = evidence_export_schema.into();
        let package_id = build_hash_id(
            "proof",
            &serde_json::json!({
                "createdAt": created_at,
                "evidenceExportManifestHash": evidence_export_manifest_hash.clone(),
                "workflowId": workflow_id.clone(),
                "receiptIds": receipt_records.iter().map(|record| record.receipt_id.clone()).collect::<Vec<_>>(),
            }),
        )?;
        if publication_profile.checkpoint_continuity == CHECKPOINT_CONTINUITY_APPEND_ONLY
            && checkpoint_transparency.is_none()
        {
            return Err(MercuryContractError::Validation(
                "append_only proof packages must carry checkpoint_transparency publication records"
                    .to_string(),
            ));
        }
        let (checkpoint_transparency, publication_claim_boundary) =
            derive_publication_materials_with_summary(
                &chio_bundle,
                &publication_profile,
                checkpoint_transparency.as_ref(),
            )?;

        let package = Self {
            schema: MERCURY_PROOF_PACKAGE_SCHEMA.to_string(),
            package_id,
            created_at,
            evidence_export_manifest_hash,
            evidence_export_schema,
            evidence_exported_at,
            workflow_id,
            account_id: shared_optional_value(
                receipt_records
                    .iter()
                    .map(|record| record.metadata.business_ids.account_id.as_deref()),
            ),
            desk_id: shared_optional_value(
                receipt_records
                    .iter()
                    .map(|record| record.metadata.business_ids.desk_id.as_deref()),
            ),
            strategy_id: shared_optional_value(
                receipt_records
                    .iter()
                    .map(|record| record.metadata.business_ids.strategy_id.as_deref()),
            ),
            publication_profile,
            publication_claim_boundary: Some(publication_claim_boundary),
            checkpoint_transparency,
            receipt_records,
            bundle_manifests,
            chio_bundle,
        };
        package.validate()?;
        Ok(package)
    }

    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_PROOF_PACKAGE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_PROOF_PACKAGE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("package_id", &self.package_id)?;
        ensure_non_empty("workflow_id", &self.workflow_id)?;
        ensure_non_empty(
            "evidence_export_manifest_hash",
            &self.evidence_export_manifest_hash,
        )?;
        ensure_non_empty("evidence_export_schema", &self.evidence_export_schema)?;
        self.publication_profile.validate()?;
        let (derived_checkpoint_transparency, derived_publication_claim_boundary) =
            derive_publication_materials_with_summary(
                &self.chio_bundle,
                &self.publication_profile,
                self.checkpoint_transparency.as_ref(),
            )?;
        if self.publication_profile.checkpoint_continuity == CHECKPOINT_CONTINUITY_APPEND_ONLY
            && self.checkpoint_transparency.is_none()
        {
            return Err(MercuryContractError::Validation(
                "append_only proof packages must carry checkpoint_transparency publication records"
                    .to_string(),
            ));
        }
        if let Some(publication_claim_boundary) = self.publication_claim_boundary.as_ref() {
            publication_claim_boundary
                .validate()
                .map_err(MercuryContractError::Validation)?;
            if publication_claim_boundary != &derived_publication_claim_boundary {
                return Err(MercuryContractError::Validation(
                    "publication_claim_boundary does not match the Chio bundle and publication_profile".to_string(),
                ));
            }
        } else if self.publication_profile.checkpoint_continuity
            == CHECKPOINT_CONTINUITY_APPEND_ONLY
        {
            return Err(MercuryContractError::Validation(
                "append_only proof packages must carry publication_claim_boundary".to_string(),
            ));
        }
        if self.checkpoint_transparency.as_ref() != derived_checkpoint_transparency.as_ref() {
            return Err(MercuryContractError::Validation(
                "checkpoint_transparency does not match the Chio bundle and publication_profile"
                    .to_string(),
            ));
        }
        if self.receipt_records.is_empty() {
            return Err(MercuryContractError::MissingField("receipt_records"));
        }
        if self.bundle_manifests.is_empty() {
            return Err(MercuryContractError::MissingField("bundle_manifests"));
        }
        if self.receipt_records.len() != self.chio_bundle.tool_receipts.len() {
            return Err(MercuryContractError::Validation(
                "receipt_records must align one-for-one with chio_bundle.tool_receipts".to_string(),
            ));
        }
        for manifest in &self.bundle_manifests {
            manifest.validate()?;
            if manifest.business_ids.workflow_id != self.workflow_id {
                return Err(MercuryContractError::Validation(format!(
                    "bundle manifest {} does not match proof-package workflow_id {}",
                    manifest.bundle_id, self.workflow_id
                )));
            }
        }
        for (record, tool_receipt) in self
            .receipt_records
            .iter()
            .zip(&self.chio_bundle.tool_receipts)
        {
            if record.receipt_id != tool_receipt.receipt.id || record.seq != tool_receipt.seq {
                return Err(MercuryContractError::Validation(
                    "receipt_records are out of sync with chio_bundle.tool_receipts".to_string(),
                ));
            }
            let actual_metadata = MercuryReceiptMetadata::from_receipt(&tool_receipt.receipt)?
                .ok_or_else(|| {
                    MercuryContractError::Validation(format!(
                        "tool receipt {} is missing receipt.metadata.mercury",
                        tool_receipt.receipt.id
                    ))
                })?;
            if actual_metadata != record.metadata {
                return Err(MercuryContractError::Validation(format!(
                    "tool receipt {} metadata does not match proof-package summary",
                    tool_receipt.receipt.id
                )));
            }
        }
        Ok(())
    }

    pub fn verify(
        &self,
        verified_at: u64,
    ) -> Result<MercuryVerificationReport, MercuryContractError> {
        self.validate()?;
        verify_chio_bundle(
            &self.chio_bundle,
            &self.publication_profile,
            self.checkpoint_transparency.as_ref(),
        )?;
        Ok(MercuryVerificationReport {
            schema: self.schema.clone(),
            package_kind: MercuryPackageKind::Proof,
            verified_at,
            package_id: self.package_id.clone(),
            workflow_id: self.workflow_id.clone(),
            receipt_count: self.receipt_records.len() as u64,
            verifier_equivalent: true,
            steps: vec![
                MercuryVerificationStep {
                    name: "package_contract".to_string(),
                    detail: "proof package schema, workflow scope, and manifest bindings are valid"
                        .to_string(),
                },
                MercuryVerificationStep {
                    name: "chio_bundle_integrity".to_string(),
                    detail: "receipts, checkpoints, inclusion proofs, and lineage verified"
                        .to_string(),
                },
            ],
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MercuryInquiryPackage {
    pub schema: String,
    pub inquiry_id: String,
    pub created_at: u64,
    pub audience: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction_profile: Option<String>,
    pub verifier_equivalent: bool,
    pub rendered_export_sha256: String,
    pub rendered_export: serde_json::Value,
    pub disclosure: MercuryDisclosurePolicy,
    pub approval_state: MercuryApprovalState,
    pub proof_package: MercuryProofPackage,
}

#[derive(Debug, Clone)]
pub struct MercuryInquiryPackageArgs {
    pub created_at: u64,
    pub audience: String,
    pub redaction_profile: Option<String>,
    pub rendered_export: serde_json::Value,
    pub disclosure: MercuryDisclosurePolicy,
    pub approval_state: MercuryApprovalState,
    pub verifier_equivalent: bool,
}

impl MercuryInquiryPackage {
    pub fn build(
        proof_package: MercuryProofPackage,
        args: MercuryInquiryPackageArgs,
    ) -> Result<Self, MercuryContractError> {
        let MercuryInquiryPackageArgs {
            created_at,
            audience,
            redaction_profile,
            rendered_export,
            disclosure,
            approval_state,
            verifier_equivalent,
        } = args;
        let rendered_export_sha256 =
            sha256_hex(&canonical_json(&rendered_export, "rendered_export")?);
        let inquiry_id = build_hash_id(
            "inquiry",
            &serde_json::json!({
                "createdAt": created_at,
                "proofPackageId": proof_package.package_id.clone(),
                "audience": audience.clone(),
                "renderedExportSha256": rendered_export_sha256.clone(),
            }),
        )?;
        let package = Self {
            schema: MERCURY_INQUIRY_PACKAGE_SCHEMA.to_string(),
            inquiry_id,
            created_at,
            audience,
            redaction_profile,
            verifier_equivalent,
            rendered_export_sha256,
            rendered_export,
            disclosure,
            approval_state,
            proof_package,
        };
        package.validate()?;
        Ok(package)
    }

    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_INQUIRY_PACKAGE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_INQUIRY_PACKAGE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("inquiry_id", &self.inquiry_id)?;
        ensure_non_empty("audience", &self.audience)?;
        self.disclosure.validate()?;
        self.proof_package.validate()?;
        let expected_hash = sha256_hex(&canonical_json(&self.rendered_export, "rendered_export")?);
        if self.rendered_export_sha256 != expected_hash {
            return Err(MercuryContractError::Validation(
                "rendered_export_sha256 does not match rendered_export".to_string(),
            ));
        }
        Ok(())
    }

    pub fn verify(
        &self,
        verified_at: u64,
    ) -> Result<MercuryVerificationReport, MercuryContractError> {
        self.validate()?;
        self.proof_package.verify(verified_at)?;
        Ok(MercuryVerificationReport {
            schema: self.schema.clone(),
            package_kind: MercuryPackageKind::Inquiry,
            verified_at,
            package_id: self.inquiry_id.clone(),
            workflow_id: self.proof_package.workflow_id.clone(),
            receipt_count: self.proof_package.receipt_records.len() as u64,
            verifier_equivalent: self.verifier_equivalent,
            steps: vec![
                MercuryVerificationStep {
                    name: "proof_package".to_string(),
                    detail: "underlying proof package verified successfully".to_string(),
                },
                MercuryVerificationStep {
                    name: "inquiry_contract".to_string(),
                    detail:
                        "audience, disclosure, approval state, and rendered export digest are valid"
                            .to_string(),
                },
            ],
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryPackageKind {
    Proof,
    Inquiry,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryVerificationStep {
    pub name: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryVerificationReport {
    pub schema: String,
    pub package_kind: MercuryPackageKind,
    pub verified_at: u64,
    pub package_id: String,
    pub workflow_id: String,
    pub receipt_count: u64,
    pub verifier_equivalent: bool,
    pub steps: Vec<MercuryVerificationStep>,
}

fn verify_chio_bundle(
    bundle: &EvidenceExportBundle,
    publication_profile: &MercuryPublicationProfile,
    checkpoint_transparency: Option<&CheckpointTransparencySummary>,
) -> Result<(), MercuryContractError> {
    let mut tool_receipts_by_seq = BTreeMap::new();
    for record in &bundle.tool_receipts {
        if tool_receipts_by_seq
            .insert(record.seq, &record.receipt)
            .is_some()
        {
            return Err(MercuryContractError::Validation(format!(
                "duplicate tool receipt seq in proof package: {}",
                record.seq
            )));
        }
        if !record
            .receipt
            .verify_signature()
            .map_err(|error| MercuryContractError::Validation(error.to_string()))?
        {
            return Err(MercuryContractError::Validation(format!(
                "tool receipt signature verification failed: {}",
                record.receipt.id
            )));
        }
        if !record
            .receipt
            .action
            .verify_hash()
            .map_err(|error| MercuryContractError::Validation(error.to_string()))?
        {
            return Err(MercuryContractError::Validation(format!(
                "tool receipt action hash verification failed: {}",
                record.receipt.id
            )));
        }
    }

    let mut child_receipt_seqs = BTreeSet::new();
    for record in &bundle.child_receipts {
        if !child_receipt_seqs.insert(record.seq) {
            return Err(MercuryContractError::Validation(format!(
                "duplicate child receipt seq in proof package: {}",
                record.seq
            )));
        }
        if !record
            .receipt
            .verify_signature()
            .map_err(|error| MercuryContractError::Validation(error.to_string()))?
        {
            return Err(MercuryContractError::Validation(format!(
                "child receipt signature verification failed: {}",
                record.receipt.id
            )));
        }
    }

    let mut checkpoints_by_seq = BTreeMap::new();
    for checkpoint in &bundle.checkpoints {
        if !is_supported_checkpoint_schema(&checkpoint.body.schema) {
            return Err(MercuryContractError::Validation(format!(
                "unsupported checkpoint schema in proof package: {}",
                checkpoint.body.schema
            )));
        }
        if publication_profile.checkpoint_signatures_required
            && !verify_checkpoint_signature(checkpoint)
                .map_err(|error| MercuryContractError::Validation(error.to_string()))?
        {
            return Err(MercuryContractError::Validation(format!(
                "checkpoint signature verification failed: {}",
                checkpoint.body.checkpoint_seq
            )));
        }
        if checkpoints_by_seq
            .insert(checkpoint.body.checkpoint_seq, checkpoint)
            .is_some()
        {
            return Err(MercuryContractError::Validation(format!(
                "duplicate checkpoint seq in proof package: {}",
                checkpoint.body.checkpoint_seq
            )));
        }
    }
    let _ = derive_publication_materials_with_summary(
        bundle,
        publication_profile,
        checkpoint_transparency,
    )?;

    let mut lineage_ids = BTreeSet::new();
    for snapshot in &bundle.capability_lineage {
        if !lineage_ids.insert(snapshot.capability_id.as_str()) {
            return Err(MercuryContractError::Validation(format!(
                "duplicate capability lineage snapshot in proof package: {}",
                snapshot.capability_id
            )));
        }
    }

    if publication_profile.inclusion_proofs_required && bundle.inclusion_proofs.is_empty() {
        return Err(MercuryContractError::Validation(
            "proof package requires inclusion proofs but none were provided".to_string(),
        ));
    }

    let mut proved_receipts = BTreeSet::new();
    for proof in &bundle.inclusion_proofs {
        let checkpoint = checkpoints_by_seq
            .get(&proof.checkpoint_seq)
            .ok_or_else(|| {
                MercuryContractError::Validation(format!(
                    "inclusion proof references missing checkpoint {}",
                    proof.checkpoint_seq
                ))
            })?;
        let receipt = tool_receipts_by_seq
            .get(&proof.receipt_seq)
            .ok_or_else(|| {
                MercuryContractError::Validation(format!(
                    "inclusion proof references missing receipt seq {}",
                    proof.receipt_seq
                ))
            })?;
        if proof.merkle_root != checkpoint.body.merkle_root {
            return Err(MercuryContractError::Validation(format!(
                "inclusion proof root mismatch for receipt seq {}",
                proof.receipt_seq
            )));
        }
        let canonical = canonical_json_bytes(*receipt)
            .map_err(|error| MercuryContractError::Json(error.to_string()))?;
        if !proof.verify(&canonical, &checkpoint.body.merkle_root) {
            return Err(MercuryContractError::Validation(format!(
                "inclusion proof verification failed for receipt seq {}",
                proof.receipt_seq
            )));
        }
        if !proved_receipts.insert(proof.receipt_seq) {
            return Err(MercuryContractError::Validation(format!(
                "duplicate inclusion proof for receipt seq {}",
                proof.receipt_seq
            )));
        }
    }

    let mut declared_uncheckpointed = BTreeSet::new();
    for record in &bundle.uncheckpointed_receipts {
        if !tool_receipts_by_seq.contains_key(&record.seq) {
            return Err(MercuryContractError::Validation(format!(
                "uncheckpointed receipt seq {} is not present in tool receipts",
                record.seq
            )));
        }
        if !declared_uncheckpointed.insert(record.seq) {
            return Err(MercuryContractError::Validation(format!(
                "duplicate uncheckpointed receipt seq in proof package: {}",
                record.seq
            )));
        }
    }

    let derived_uncheckpointed = tool_receipts_by_seq
        .keys()
        .filter(|seq| !proved_receipts.contains(seq))
        .copied()
        .collect::<BTreeSet<_>>();
    if declared_uncheckpointed != derived_uncheckpointed {
        return Err(MercuryContractError::Validation(
            "declared uncheckpointed receipts do not match derived checkpoint coverage".to_string(),
        ));
    }

    Ok(())
}

fn shared_optional_value<'a>(values: impl Iterator<Item = Option<&'a str>>) -> Option<String> {
    let mut first = None::<Option<&'a str>>;
    for value in values {
        if let Some(expected) = first {
            if expected != value {
                return None;
            }
        } else {
            first = Some(value);
        }
    }
    first.flatten().map(ToOwned::to_owned)
}

fn publication_claim_trust_anchor(
    publication_profile: &MercuryPublicationProfile,
) -> Result<Option<&str>, MercuryContractError> {
    publication_profile.validate()?;
    Ok(
        if publication_profile.checkpoint_continuity == CHECKPOINT_CONTINUITY_APPEND_ONLY {
            publication_profile
                .trust_anchor
                .as_deref()
                .map(str::trim)
                .filter(|anchor| !anchor.is_empty())
        } else {
            None
        },
    )
}

fn derive_publication_materials_with_summary(
    bundle: &EvidenceExportBundle,
    publication_profile: &MercuryPublicationProfile,
    checkpoint_transparency: Option<&CheckpointTransparencySummary>,
) -> Result<
    (
        Option<CheckpointTransparencySummary>,
        EvidenceTransparencyClaims,
    ),
    MercuryContractError,
> {
    let normalized_transparency = match checkpoint_transparency {
        Some(summary) => Some(
            verify_checkpoint_transparency_records(&bundle.checkpoints, summary).map_err(
                |error| {
                    MercuryContractError::Validation(format!(
                        "checkpoint transparency verification failed: {error}"
                    ))
                },
            )?,
        ),
        None => None,
    };
    let transparency = match normalized_transparency.as_ref() {
        Some(summary) => summary.clone(),
        None => validate_checkpoint_transparency(&bundle.checkpoints).map_err(|error| {
            MercuryContractError::Validation(format!(
                "checkpoint transparency verification failed: {error}"
            ))
        })?,
    };
    let claim_boundary = build_evidence_transparency_claims(
        bundle,
        &transparency,
        publication_claim_trust_anchor(publication_profile)?,
    );
    claim_boundary
        .validate()
        .map_err(MercuryContractError::Validation)?;
    if publication_profile.checkpoint_continuity == CHECKPOINT_CONTINUITY_APPEND_ONLY
        && !claim_boundary.is_trust_anchored()
    {
        return Err(MercuryContractError::Validation(
            "append_only publication claims require a trust anchor; the Chio bundle still contains only transparency-preview log claims".to_string(),
        ));
    }
    Ok((normalized_transparency, claim_boundary))
}

fn build_hash_id(prefix: &str, value: &serde_json::Value) -> Result<String, MercuryContractError> {
    Ok(format!(
        "{prefix}-{}",
        sha256_hex(&canonical_json(value, "hash_input")?)
    ))
}

fn canonical_json(
    value: &impl Serialize,
    field: &'static str,
) -> Result<Vec<u8>, MercuryContractError> {
    canonical_json_bytes(value)
        .map_err(|error| MercuryContractError::Validation(format!("{field}: {error}")))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use chio_core::crypto::Keypair;
    use chio_core::merkle::MerkleTree;
    use chio_core::receipt::{
        body::ChioReceipt, body::ChioReceiptBody, checkpoint::CheckpointPublicationIdentity,
        checkpoint::CheckpointPublicationIdentityKind,
        checkpoint::CheckpointPublicationTrustAnchorBinding,
        checkpoint::CheckpointTrustAnchorIdentity, checkpoint::CheckpointTrustAnchorIdentityKind,
        decision::Decision, decision::ToolCallAction,
    };
    use chio_kernel::checkpoint::{
        build_checkpoint, build_checkpoint_with_previous, build_inclusion_proof,
        build_trust_anchored_checkpoint_publication, validate_checkpoint_transparency,
        CheckpointTransparencySummary,
    };
    use chio_kernel::evidence_export::{
        EvidenceChildReceiptScope, EvidenceExportQuery, EvidenceRetentionMetadata,
        EvidenceToolReceiptRecord,
    };

    use crate::fixtures::{sample_mercury_bundle_manifest, sample_mercury_receipt_metadata};

    use super::*;

    fn sample_receipt(sequence: u64) -> ChioReceipt {
        let keypair = Keypair::generate();
        let metadata = sample_mercury_receipt_metadata()
            .into_receipt_metadata_value()
            .expect("metadata value");
        ChioReceipt::sign(
            ChioReceiptBody {
                id: format!("receipt-proof-{sequence}"),
                timestamp: 1_775_137_625 + sequence,
                capability_id: format!("cap-proof-{sequence}"),
                tool_server: "mercury".to_string(),
                tool_name: "release_control".to_string(),
                action: ToolCallAction::from_parameters(
                    serde_json::json!({"release": format!("candidate-{sequence}")}),
                )
                .expect("action"),
                decision: Some(Decision::Allow),
                receipt_kind: Default::default(),
                boundary_class: Default::default(),
                observation_outcome: None,
                tool_origin: Default::default(),
                redaction_mode: Default::default(),
                actor_chain: Vec::new(),
                content_hash: format!("content-proof-{sequence}"),
                policy_hash: format!("policy-proof-{sequence}"),
                evidence: Vec::new(),
                metadata: Some(metadata),
                trust_level: chio_core::receipt::kinds::TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
                bbs_projection_version: None,
            },
            &keypair,
        )
        .expect("sign receipt")
    }

    fn sample_bundle() -> EvidenceExportBundle {
        let receipt = sample_receipt(1);
        let canonical = canonical_json_bytes(&receipt).expect("canonical receipt");
        let checkpoint_keypair = Keypair::generate();
        let checkpoint = build_checkpoint(
            1,
            1,
            1,
            std::slice::from_ref(&canonical),
            &checkpoint_keypair,
        )
        .expect("checkpoint");
        let tree = MerkleTree::from_leaves(&[canonical]).expect("merkle tree");
        let proof =
            build_inclusion_proof(&tree, 0, checkpoint.body.checkpoint_seq, 1).expect("proof");
        EvidenceExportBundle {
            query: EvidenceExportQuery::default(),
            tool_receipts: vec![EvidenceToolReceiptRecord { seq: 1, receipt }],
            child_receipts: Vec::new(),
            child_receipt_scope: EvidenceChildReceiptScope::OmittedNoJoinPath,
            checkpoints: vec![checkpoint],
            capability_lineage: Vec::new(),
            inclusion_proofs: vec![proof],
            uncheckpointed_receipts: Vec::new(),
            retention: EvidenceRetentionMetadata {
                live_db_size_bytes: Some(1_024),
                oldest_live_receipt_timestamp: Some(1_775_137_626),
            },
        }
    }

    fn sample_bundle_with_publication_records(
    ) -> (EvidenceExportBundle, CheckpointTransparencySummary) {
        let first_receipt = sample_receipt(1);
        let second_receipt = sample_receipt(2);
        let first_canonical = canonical_json_bytes(&first_receipt).expect("first canonical");
        let second_canonical = canonical_json_bytes(&second_receipt).expect("second canonical");
        let checkpoint_keypair = Keypair::generate();
        let first_checkpoint = build_checkpoint(
            1,
            1,
            1,
            std::slice::from_ref(&first_canonical),
            &checkpoint_keypair,
        )
        .expect("first checkpoint");
        let second_checkpoint = build_checkpoint_with_previous(
            2,
            2,
            2,
            std::slice::from_ref(&second_canonical),
            &checkpoint_keypair,
            Some(&first_checkpoint),
            &[
                chio_kernel::checkpoint::checkpoint_chain_leaf_hash(&first_checkpoint.body)
                    .expect("first chain leaf"),
            ],
        )
        .expect("second checkpoint");
        let first_tree =
            MerkleTree::from_leaves(std::slice::from_ref(&first_canonical)).expect("first tree");
        let second_tree =
            MerkleTree::from_leaves(std::slice::from_ref(&second_canonical)).expect("second tree");
        let first_proof =
            build_inclusion_proof(&first_tree, 0, first_checkpoint.body.checkpoint_seq, 1)
                .expect("first proof");
        let second_proof =
            build_inclusion_proof(&second_tree, 0, second_checkpoint.body.checkpoint_seq, 2)
                .expect("second proof");
        let bundle = EvidenceExportBundle {
            query: EvidenceExportQuery::default(),
            tool_receipts: vec![
                EvidenceToolReceiptRecord {
                    seq: 1,
                    receipt: first_receipt,
                },
                EvidenceToolReceiptRecord {
                    seq: 2,
                    receipt: second_receipt,
                },
            ],
            child_receipts: Vec::new(),
            child_receipt_scope: EvidenceChildReceiptScope::OmittedNoJoinPath,
            checkpoints: vec![first_checkpoint.clone(), second_checkpoint.clone()],
            capability_lineage: Vec::new(),
            inclusion_proofs: vec![first_proof, second_proof],
            uncheckpointed_receipts: Vec::new(),
            retention: EvidenceRetentionMetadata {
                live_db_size_bytes: Some(2_048),
                oldest_live_receipt_timestamp: Some(1_775_137_626),
            },
        };
        let mut transparency = validate_checkpoint_transparency(&[
            first_checkpoint.clone(),
            second_checkpoint.clone(),
        ])
        .expect("transparency");
        let binding = CheckpointPublicationTrustAnchorBinding {
            publication_identity: CheckpointPublicationIdentity::new(
                CheckpointPublicationIdentityKind::LocalLog,
                transparency.publications[0].log_id.clone(),
            ),
            trust_anchor_identity: CheckpointTrustAnchorIdentity::new(
                CheckpointTrustAnchorIdentityKind::TransparencyRoot,
                "root-set-1",
            ),
            trust_anchor_ref: "anchor-root-1".to_string(),
            signer_cert_ref: "cert-chain-1".to_string(),
            publication_profile_version: "phase4-pilot".to_string(),
        };
        transparency.publications = vec![
            build_trust_anchored_checkpoint_publication(&first_checkpoint, binding.clone())
                .expect("first anchored publication"),
            build_trust_anchored_checkpoint_publication(&second_checkpoint, binding)
                .expect("second anchored publication"),
        ];
        (bundle, transparency)
    }

    #[test]
    fn proof_package_build_and_verify_passes() {
        let package = MercuryProofPackage::build(
            sample_bundle(),
            "manifest-sha256-proof",
            "chio.evidence_export_manifest.v1",
            1_775_137_700,
            1_775_137_800,
            MercuryPublicationProfile::pilot_default(),
            None,
            vec![sample_mercury_bundle_manifest()],
        )
        .expect("proof package");
        let claim_boundary = package
            .publication_claim_boundary
            .as_ref()
            .expect("publication claim boundary");
        assert_eq!(
            claim_boundary.publication_state.as_str(),
            "transparency_preview"
        );
        assert!(claim_boundary.trust_anchor.is_none());

        let report = package.verify(1_775_137_900).expect("verification report");
        assert_eq!(report.package_kind, MercuryPackageKind::Proof);
        assert_eq!(report.workflow_id, "workflow-release-control");
        assert_eq!(report.receipt_count, 1);
    }

    #[test]
    fn proof_package_rejects_padded_package_id() {
        let mut package = MercuryProofPackage::build(
            sample_bundle(),
            "manifest-sha256-proof",
            "chio.evidence_export_manifest.v1",
            1_775_137_700,
            1_775_137_800,
            MercuryPublicationProfile::pilot_default(),
            None,
            vec![sample_mercury_bundle_manifest()],
        )
        .expect("proof package");
        package.package_id = format!(" {} ", package.package_id);

        let error = package.validate().expect_err("padded package id");

        assert!(matches!(
            error,
            MercuryContractError::PaddedField("package_id")
        ));
    }

    #[test]
    fn mercury_proof_package_requires_trust_anchor_for_append_only_claim() {
        let mut profile = MercuryPublicationProfile::pilot_default();
        profile.checkpoint_continuity = "append_only".to_string();

        let error = MercuryProofPackage::build(
            sample_bundle(),
            "manifest-sha256-proof",
            "chio.evidence_export_manifest.v1",
            1_775_137_700,
            1_775_137_800,
            profile,
            None,
            vec![sample_mercury_bundle_manifest()],
        )
        .expect_err("append_only profile without trust anchor should fail");

        assert!(
            error
                .to_string()
                .contains("requires publication_profile.trust_anchor"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn mercury_preview_profile_rejects_trust_anchor_material() {
        let mut profile = MercuryPublicationProfile::pilot_default();
        profile.trust_anchor = Some("anchor-root-1".to_string());

        let error = profile
            .validate()
            .expect_err("preview profiles should not carry trust anchors");

        assert!(
            error
                .to_string()
                .contains("only valid when publication_profile.checkpoint_continuity=append_only"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn append_only_proof_package_fails_closed_without_publication_records() {
        let mut profile = MercuryPublicationProfile::pilot_default();
        profile.checkpoint_continuity = "append_only".to_string();
        profile.trust_anchor = Some("anchor-root-1".to_string());

        let error = MercuryProofPackage::build(
            sample_bundle(),
            "manifest-sha256-proof",
            "chio.evidence_export_manifest.v1",
            1_775_137_700,
            1_775_137_800,
            profile,
            None,
            vec![sample_mercury_bundle_manifest()],
        )
        .expect_err("append_only proof package without packaged publication records should fail");

        assert!(
            error
                .to_string()
                .contains("must carry checkpoint_transparency publication records"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn proof_package_carries_publication_record_and_optional_consistency_chain() {
        let (bundle, transparency) = sample_bundle_with_publication_records();
        let mut profile = MercuryPublicationProfile::pilot_default();
        profile.checkpoint_continuity = "append_only".to_string();
        profile.trust_anchor = Some("anchor-root-1".to_string());

        let package = MercuryProofPackage::build(
            bundle,
            "manifest-sha256-proof",
            "chio.evidence_export_manifest.v1",
            1_775_137_700,
            1_775_137_800,
            profile,
            Some(transparency),
            vec![sample_mercury_bundle_manifest()],
        )
        .expect("proof package with publication records");

        let packaged = package
            .checkpoint_transparency
            .as_ref()
            .expect("checkpoint transparency");
        assert_eq!(packaged.publications.len(), 2);
        assert_eq!(packaged.consistency_proofs.len(), 1);
        assert_eq!(
            packaged.publications[0]
                .trust_anchor_binding
                .as_ref()
                .expect("binding")
                .trust_anchor_ref,
            "anchor-root-1"
        );
        assert_eq!(
            package
                .publication_claim_boundary
                .as_ref()
                .expect("claim boundary")
                .trust_anchor
                .as_deref(),
            Some("anchor-root-1")
        );

        package.verify(1_775_137_900).expect("verification report");
    }

    #[test]
    fn inquiry_package_build_and_verify_passes() {
        let proof_package = MercuryProofPackage::build(
            sample_bundle(),
            "manifest-sha256-proof",
            "chio.evidence_export_manifest.v1",
            1_775_137_700,
            1_775_137_800,
            MercuryPublicationProfile::pilot_default(),
            None,
            vec![sample_mercury_bundle_manifest()],
        )
        .expect("proof package");
        let metadata = proof_package.receipt_records[0].metadata.clone();
        let inquiry = MercuryInquiryPackage::build(
            proof_package,
            MercuryInquiryPackageArgs {
                created_at: 1_775_137_901,
                audience: "compliance".to_string(),
                redaction_profile: Some("internal-default".to_string()),
                rendered_export: serde_json::json!({
                    "workflowId": "workflow-release-control",
                    "receiptIds": ["receipt-proof-1"],
                    "audience": "compliance",
                }),
                disclosure: metadata.disclosure,
                approval_state: metadata.approval_state,
                verifier_equivalent: false,
            },
        )
        .expect("inquiry package");

        let report = inquiry.verify(1_775_137_902).expect("verification report");
        assert_eq!(report.package_kind, MercuryPackageKind::Inquiry);
        assert!(!report.verifier_equivalent);
    }
}
