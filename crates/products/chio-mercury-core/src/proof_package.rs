use std::collections::{BTreeMap, BTreeSet};

use chio_core::receipt::{
    body::ChioReceipt,
    decision::Decision,
    kinds::{ReceiptKind, TrustLevel},
};
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

use crate::bundle::{MercuryBundleManifest, MercuryBundleReference};
use crate::receipt_metadata::{
    MercuryApprovalState, MercuryApprovalStatus, MercuryContractError, MercuryDisclosurePolicy,
    MercuryReceiptMetadata,
};
use crate::validation::ensure_non_empty;

pub const MERCURY_PUBLICATION_PROFILE_SCHEMA: &str = "chio.mercury.publication_profile.v1";
pub const MERCURY_PROOF_PACKAGE_SCHEMA: &str = "chio.mercury.proof_package.v1";
pub const MERCURY_INQUIRY_PACKAGE_SCHEMA: &str = "chio.mercury.inquiry_package.v1";
const CHECKPOINT_CONTINUITY_AUDIT_ONLY: &str = "audit_only";
const CHECKPOINT_CONTINUITY_TRANSPARENCY_PREVIEW: &str = "transparency_preview";
const CHECKPOINT_CONTINUITY_APPEND_ONLY: &str = "append_only";
const COMPLETENESS_BEST_EFFORT: &str = "best_effort";
const COMPLETENESS_FULL_CHECKPOINT_COVERAGE: &str = "full_checkpoint_coverage";

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
            completeness_mode: COMPLETENESS_BEST_EFFORT.to_string(),
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
        match self.completeness_mode.as_str() {
            COMPLETENESS_BEST_EFFORT | COMPLETENESS_FULL_CHECKPOINT_COVERAGE => Ok(()),
            other => Err(MercuryContractError::Validation(format!(
                "unsupported publication_profile.completeness_mode: {other}"
            ))),
        }
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
        publication_profile.completeness_mode = derived_completeness_mode(&chio_bundle).to_string();
        publication_profile.validate()?;

        let evidence_export_manifest_hash = evidence_export_manifest_hash.into();
        let evidence_export_schema = evidence_export_schema.into();
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

        let mut package = Self {
            schema: MERCURY_PROOF_PACKAGE_SCHEMA.to_string(),
            package_id: String::new(),
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
        package.refresh_package_id()?;
        package.validate()?;
        Ok(package)
    }

    pub fn refresh_package_id(&mut self) -> Result<(), MercuryContractError> {
        self.package_id = derive_proof_package_id(self)?;
        Ok(())
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
        let expected_completeness_mode = derived_completeness_mode(&self.chio_bundle);
        if self.publication_profile.completeness_mode != expected_completeness_mode {
            return Err(MercuryContractError::Validation(format!(
                "publication_profile.completeness_mode must be {expected_completeness_mode} for the Chio bundle checkpoint coverage"
            )));
        }
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
        validate_checkpoint_receipt_sequence_bindings(&self.chio_bundle)?;
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
            if actual_metadata.business_ids.workflow_id != self.workflow_id {
                return Err(MercuryContractError::Validation(format!(
                    "tool receipt {} workflow_id does not match proof-package workflow_id {}",
                    tool_receipt.receipt.id, self.workflow_id
                )));
            }
            validate_mercury_tool_receipt(&tool_receipt.receipt, &actual_metadata)?;
        }
        let derived_account_id = shared_optional_value(
            self.receipt_records
                .iter()
                .map(|record| record.metadata.business_ids.account_id.as_deref()),
        );
        if self.account_id != derived_account_id {
            return Err(MercuryContractError::Validation(
                "account_id does not match the signed receipt metadata summary".to_string(),
            ));
        }
        let derived_desk_id = shared_optional_value(
            self.receipt_records
                .iter()
                .map(|record| record.metadata.business_ids.desk_id.as_deref()),
        );
        if self.desk_id != derived_desk_id {
            return Err(MercuryContractError::Validation(
                "desk_id does not match the signed receipt metadata summary".to_string(),
            ));
        }
        let derived_strategy_id = shared_optional_value(
            self.receipt_records
                .iter()
                .map(|record| record.metadata.business_ids.strategy_id.as_deref()),
        );
        if self.strategy_id != derived_strategy_id {
            return Err(MercuryContractError::Validation(
                "strategy_id does not match the signed receipt metadata summary".to_string(),
            ));
        }
        let expected_package_id = derive_proof_package_id(self)?;
        if self.package_id != expected_package_id {
            return Err(MercuryContractError::Validation(
                "package_id does not match the deterministic proof-package identity".to_string(),
            ));
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
            verifier_equivalent: false,
            steps: vec![
                MercuryVerificationStep {
                    name: "package_contract".to_string(),
                    detail: "proof package identity content-addresses the export descriptor annotations (not independently attested provenance), workflow scope, receipt action bindings, and manifest structure".to_string(),
                },
                MercuryVerificationStep {
                    name: "chio_bundle_integrity".to_string(),
                    detail: "tool and child receipt self-signatures, required checkpoint signatures, inclusion proofs, and unsigned capability-lineage ID uniqueness checks passed".to_string(),
                },
                MercuryVerificationStep {
                    name: "kernel_authority".to_string(),
                    detail: "kernel signer authority was not evaluated against a trusted Mercury key set".to_string(),
                },
            ],
        })
    }

    pub fn verify_with_trusted_kernel_keys(
        &self,
        verified_at: u64,
        trusted_kernel_keys: &BTreeSet<String>,
    ) -> Result<MercuryVerificationReport, MercuryContractError> {
        self.validate()?;
        verify_trusted_checkpoint_requirements(&self.chio_bundle, &self.publication_profile)?;
        verify_chio_bundle(
            &self.chio_bundle,
            &self.publication_profile,
            self.checkpoint_transparency.as_ref(),
        )?;
        verify_mercury_kernel_authority(&self.chio_bundle, trusted_kernel_keys)?;
        verify_signed_bundle_manifest_coverage(&self.receipt_records, &self.bundle_manifests)?;
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
                    detail: "proof package identity content-addresses the export descriptor annotations (not independently attested provenance), signed workflow scope, receipt action bindings, and signed bundle-reference coverage".to_string(),
                },
                MercuryVerificationStep {
                    name: "chio_bundle_integrity".to_string(),
                    detail: "tool and child receipt self-signatures, checkpoint signatures, full inclusion-proof coverage, and unsigned capability-lineage ID uniqueness checks passed".to_string(),
                },
                MercuryVerificationStep {
                    name: "kernel_authority".to_string(),
                    detail: "every tool receipt, child receipt, and checkpoint signer is present in the trusted Mercury kernel-key set".to_string(),
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
            verifier_equivalent,
        } = args;
        proof_package.validate()?;
        let authoritative = authoritative_receipt(&proof_package)?;
        let disclosure = authoritative.metadata.disclosure.clone();
        let approval_state = authoritative.metadata.approval_state.clone();
        let verifier_equivalent = verifier_equivalent
            && inquiry_metadata_allows_equivalence(
                &approval_state,
                &disclosure,
                &audience,
                redaction_profile.as_deref(),
            );
        let authoritative_receipt_id = authoritative.receipt_id.clone();
        let receipt_ids = ordered_receipt_ids(&proof_package);
        let projection = InquiryProjection {
            proof_package: &proof_package,
            authoritative_receipt_id: &authoritative_receipt_id,
            receipt_ids: &receipt_ids,
            audience: &audience,
            redaction_profile: redaction_profile.as_deref(),
            verifier_equivalent,
            disclosure: &disclosure,
            approval_state: &approval_state,
        };
        let inquiry_id = build_inquiry_id(created_at, &projection)?;
        let rendered_export = render_inquiry_export(&inquiry_id, &projection);
        let rendered_export_sha256 =
            sha256_hex(&canonical_json(&rendered_export, "rendered_export")?);
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
        let authoritative = authoritative_receipt(&self.proof_package)?;
        if self.disclosure != authoritative.metadata.disclosure {
            return Err(MercuryContractError::Validation(
                "inquiry disclosure does not match the authoritative signed receipt".to_string(),
            ));
        }
        if self.approval_state != authoritative.metadata.approval_state {
            return Err(MercuryContractError::Validation(
                "inquiry approval_state does not match the authoritative signed receipt"
                    .to_string(),
            ));
        }
        if self.verifier_equivalent
            && !inquiry_metadata_allows_equivalence(
                &self.approval_state,
                &self.disclosure,
                &self.audience,
                self.redaction_profile.as_deref(),
            )
        {
            return Err(MercuryContractError::Validation(
                "inquiry verifier_equivalent elevates beyond the authoritative signed approval, disclosure, or audience/redaction scope".to_string(),
            ));
        }
        let receipt_ids = ordered_receipt_ids(&self.proof_package);
        let projection = InquiryProjection {
            proof_package: &self.proof_package,
            authoritative_receipt_id: &authoritative.receipt_id,
            receipt_ids: &receipt_ids,
            audience: &self.audience,
            redaction_profile: self.redaction_profile.as_deref(),
            verifier_equivalent: self.verifier_equivalent,
            disclosure: &self.disclosure,
            approval_state: &self.approval_state,
        };
        let expected_inquiry_id = build_inquiry_id(self.created_at, &projection)?;
        if self.inquiry_id != expected_inquiry_id {
            return Err(MercuryContractError::Validation(
                "inquiry_id does not match the deterministic inquiry projection".to_string(),
            ));
        }
        let expected_export = render_inquiry_export(&self.inquiry_id, &projection);
        if self.rendered_export != expected_export {
            return Err(MercuryContractError::Validation(
                "rendered_export is not the exact deterministic inquiry projection".to_string(),
            ));
        }
        let expected_hash = sha256_hex(&canonical_json(&expected_export, "rendered_export")?);
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
        let proof_report = self.proof_package.verify(verified_at)?;
        Ok(MercuryVerificationReport {
            schema: self.schema.clone(),
            package_kind: MercuryPackageKind::Inquiry,
            verified_at,
            package_id: self.inquiry_id.clone(),
            workflow_id: self.proof_package.workflow_id.clone(),
            receipt_count: self.proof_package.receipt_records.len() as u64,
            verifier_equivalent: self.verifier_equivalent && proof_report.verifier_equivalent,
            steps: vec![
                MercuryVerificationStep {
                    name: "proof_package".to_string(),
                    detail: "underlying proof package passed structural verification without trusted signer authority".to_string(),
                },
                MercuryVerificationStep {
                    name: "inquiry_contract".to_string(),
                    detail: "signed authoritative approval and disclosure bindings, audience/redaction scope, and the exact rendered export projection are valid".to_string(),
                },
            ],
        })
    }

    pub fn verify_with_trusted_kernel_keys(
        &self,
        verified_at: u64,
        trusted_kernel_keys: &BTreeSet<String>,
    ) -> Result<MercuryVerificationReport, MercuryContractError> {
        self.validate()?;
        let proof_report = self
            .proof_package
            .verify_with_trusted_kernel_keys(verified_at, trusted_kernel_keys)?;
        Ok(MercuryVerificationReport {
            schema: self.schema.clone(),
            package_kind: MercuryPackageKind::Inquiry,
            verified_at,
            package_id: self.inquiry_id.clone(),
            workflow_id: self.proof_package.workflow_id.clone(),
            receipt_count: self.proof_package.receipt_records.len() as u64,
            verifier_equivalent: self.verifier_equivalent && proof_report.verifier_equivalent,
            steps: vec![
                MercuryVerificationStep {
                    name: "proof_package".to_string(),
                    detail: "underlying proof package verified against trusted Mercury kernel keys"
                        .to_string(),
                },
                MercuryVerificationStep {
                    name: "inquiry_contract".to_string(),
                    detail: "signed authoritative approval and disclosure bindings, audience/redaction scope, and the exact rendered export projection are valid".to_string(),
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

fn derive_proof_package_id(
    proof_package: &MercuryProofPackage,
) -> Result<String, MercuryContractError> {
    let receipt_ids = ordered_receipt_ids(proof_package);
    let mut bundle_manifest_refs = proof_package
        .bundle_manifests
        .iter()
        .map(MercuryBundleReference::from_manifest)
        .collect::<Result<Vec<_>, _>>()?;
    bundle_manifest_refs.sort_by(|left, right| {
        left.bundle_id
            .cmp(&right.bundle_id)
            .then_with(|| left.manifest_sha256.cmp(&right.manifest_sha256))
            .then_with(|| left.artifact_count.cmp(&right.artifact_count))
            .then_with(|| left.retention_class.cmp(&right.retention_class))
    });
    let chio_bundle_sha256 =
        sha256_hex(&canonical_json(&proof_package.chio_bundle, "chio_bundle")?);
    build_hash_id(
        "proof",
        &serde_json::json!({
            "schema": proof_package.schema,
            "createdAt": proof_package.created_at,
            "evidenceExportManifestHash": proof_package.evidence_export_manifest_hash,
            "evidenceExportSchema": proof_package.evidence_export_schema,
            "evidenceExportedAt": proof_package.evidence_exported_at,
            "workflowId": proof_package.workflow_id,
            "accountId": proof_package.account_id,
            "deskId": proof_package.desk_id,
            "strategyId": proof_package.strategy_id,
            "publicationProfile": proof_package.publication_profile,
            "publicationClaimBoundary": proof_package.publication_claim_boundary,
            "checkpointTransparency": proof_package.checkpoint_transparency,
            "receiptIds": receipt_ids,
            "bundleManifestReferences": bundle_manifest_refs,
            "chioBundleSha256": chio_bundle_sha256,
        }),
    )
}

struct InquiryProjection<'a> {
    proof_package: &'a MercuryProofPackage,
    authoritative_receipt_id: &'a str,
    receipt_ids: &'a [String],
    audience: &'a str,
    redaction_profile: Option<&'a str>,
    verifier_equivalent: bool,
    disclosure: &'a MercuryDisclosurePolicy,
    approval_state: &'a MercuryApprovalState,
}

fn authoritative_receipt(
    proof_package: &MercuryProofPackage,
) -> Result<&MercuryProofReceiptRecord, MercuryContractError> {
    let max_seq = proof_package
        .receipt_records
        .iter()
        .map(|record| record.seq)
        .max()
        .ok_or(MercuryContractError::MissingField("receipt_records"))?;
    let mut authoritative = proof_package
        .receipt_records
        .iter()
        .filter(|record| record.seq == max_seq);
    let record = authoritative
        .next()
        .ok_or(MercuryContractError::MissingField("receipt_records"))?;
    if authoritative.next().is_some() {
        return Err(MercuryContractError::Validation(format!(
            "authoritative receipt sequence {max_seq} is not unique"
        )));
    }
    authenticate_authoritative_receipt_order(proof_package, record)?;
    Ok(record)
}

fn authenticate_authoritative_receipt_order(
    proof_package: &MercuryProofPackage,
    record: &MercuryProofReceiptRecord,
) -> Result<(), MercuryContractError> {
    if proof_package
        .chio_bundle
        .uncheckpointed_receipts
        .iter()
        .any(|uncheckpointed| {
            uncheckpointed.seq == record.seq && uncheckpointed.receipt_id == record.receipt_id
        })
    {
        return Err(MercuryContractError::Validation(format!(
            "authoritative receipt sequence {} is not checkpoint-authenticated",
            record.seq
        )));
    }

    let tool_receipt = proof_package
        .chio_bundle
        .tool_receipts
        .iter()
        .find(|candidate| candidate.seq == record.seq && candidate.receipt.id == record.receipt_id)
        .ok_or_else(|| {
            MercuryContractError::Validation(format!(
                "authoritative receipt sequence {} does not match a tool receipt",
                record.seq
            ))
        })?;
    let mut matching_proofs = proof_package
        .chio_bundle
        .inclusion_proofs
        .iter()
        .filter(|proof| proof.receipt_seq == record.seq);
    let proof = matching_proofs.next().ok_or_else(|| {
        MercuryContractError::Validation(format!(
            "authoritative receipt sequence {} is not checkpoint-authenticated",
            record.seq
        ))
    })?;
    if matching_proofs.next().is_some() {
        return Err(MercuryContractError::Validation(format!(
            "authoritative receipt sequence {} has multiple inclusion proofs",
            record.seq
        )));
    }

    let mut matching_checkpoints = proof_package
        .chio_bundle
        .checkpoints
        .iter()
        .filter(|checkpoint| checkpoint.body.checkpoint_seq == proof.checkpoint_seq);
    let checkpoint = matching_checkpoints.next().ok_or_else(|| {
        MercuryContractError::Validation(format!(
            "authoritative receipt sequence {} references missing checkpoint {}",
            record.seq, proof.checkpoint_seq
        ))
    })?;
    if matching_checkpoints.next().is_some() {
        return Err(MercuryContractError::Validation(format!(
            "authoritative receipt sequence {} references duplicate checkpoint {}",
            record.seq, proof.checkpoint_seq
        )));
    }
    if !is_supported_checkpoint_schema(&checkpoint.body.schema)
        || !verify_checkpoint_signature(checkpoint)
            .map_err(|error| MercuryContractError::Validation(error.to_string()))?
    {
        return Err(MercuryContractError::Validation(format!(
            "authoritative receipt sequence {} is not bound to a valid signed checkpoint",
            record.seq
        )));
    }
    if proof.merkle_root != checkpoint.body.merkle_root
        || proof.leaf_index != proof.proof.leaf_index
    {
        return Err(MercuryContractError::Validation(format!(
            "authoritative receipt sequence {} has an invalid checkpoint proof binding",
            record.seq
        )));
    }
    let leaf_offset = u64::try_from(proof.leaf_index).map_err(|_| {
        MercuryContractError::Validation(format!(
            "authoritative receipt sequence {} has an out-of-range checkpoint leaf index",
            record.seq
        ))
    })?;
    let checkpoint_receipt_seq = checkpoint
        .body
        .batch_start_seq
        .checked_add(leaf_offset)
        .ok_or_else(|| {
            MercuryContractError::Validation(format!(
                "authoritative receipt sequence {} checkpoint sequence binding overflowed",
                record.seq
            ))
        })?;
    if proof.receipt_seq != checkpoint_receipt_seq
        || proof.receipt_seq > checkpoint.body.batch_end_seq
    {
        return Err(MercuryContractError::Validation(format!(
            "authoritative receipt sequence {} does not match signed checkpoint leaf sequence {}",
            record.seq, checkpoint_receipt_seq
        )));
    }
    let canonical_receipt = canonical_json_bytes(&tool_receipt.receipt)
        .map_err(|error| MercuryContractError::Json(error.to_string()))?;
    if !proof.verify(&canonical_receipt, &checkpoint.body.merkle_root) {
        return Err(MercuryContractError::Validation(format!(
            "authoritative receipt sequence {} failed checkpoint inclusion verification",
            record.seq
        )));
    }
    Ok(())
}

fn ordered_receipt_ids(proof_package: &MercuryProofPackage) -> Vec<String> {
    let mut records = proof_package.receipt_records.iter().collect::<Vec<_>>();
    records.sort_by(|left, right| {
        left.seq
            .cmp(&right.seq)
            .then_with(|| left.receipt_id.cmp(&right.receipt_id))
    });
    records
        .into_iter()
        .map(|record| record.receipt_id.clone())
        .collect()
}

fn inquiry_metadata_allows_equivalence(
    approval_state: &MercuryApprovalState,
    disclosure: &MercuryDisclosurePolicy,
    audience: &str,
    redaction_profile: Option<&str>,
) -> bool {
    approval_state.state == MercuryApprovalStatus::Approved
        && disclosure.verifier_equivalent
        && disclosure.reviewed_export_approved
        && disclosure.audience.as_deref() == Some(audience)
        && disclosure.redaction_profile.as_deref() == redaction_profile
}

fn build_inquiry_id(
    created_at: u64,
    projection: &InquiryProjection<'_>,
) -> Result<String, MercuryContractError> {
    build_hash_id(
        "inquiry",
        &serde_json::json!({
            "createdAt": created_at,
            "proofPackageId": projection.proof_package.package_id,
            "workflowId": projection.proof_package.workflow_id,
            "authoritativeReceiptId": projection.authoritative_receipt_id,
            "receiptIds": projection.receipt_ids,
            "audience": projection.audience,
            "redactionProfile": projection.redaction_profile,
            "verifierEquivalent": projection.verifier_equivalent,
            "disclosure": projection.disclosure,
            "approvalState": projection.approval_state,
        }),
    )
}

fn render_inquiry_export(
    inquiry_id: &str,
    projection: &InquiryProjection<'_>,
) -> serde_json::Value {
    serde_json::json!({
        "inquiryId": inquiry_id,
        "proofPackageId": projection.proof_package.package_id,
        "workflowId": projection.proof_package.workflow_id,
        "authoritativeReceiptId": projection.authoritative_receipt_id,
        "receiptIds": projection.receipt_ids,
        "audience": projection.audience,
        "redactionProfile": projection.redaction_profile,
        "verifierEquivalent": projection.verifier_equivalent,
        "disclosure": projection.disclosure,
        "approvalState": projection.approval_state,
    })
}

fn validate_mercury_tool_receipt(
    receipt: &ChioReceipt,
    metadata: &MercuryReceiptMetadata,
) -> Result<(), MercuryContractError> {
    if receipt.receipt_kind != ReceiptKind::MediatedDecision
        || receipt.trust_level != TrustLevel::Mediated
    {
        return Err(MercuryContractError::Validation(format!(
            "tool receipt {} must be a kernel-mediated decision receipt",
            receipt.id
        )));
    }
    if !matches!(receipt.decision.as_ref(), Some(Decision::Allow)) {
        return Err(MercuryContractError::Validation(format!(
            "tool receipt {} must carry an allow decision",
            receipt.id
        )));
    }
    if receipt.tool_server != "mercury" {
        return Err(MercuryContractError::Validation(format!(
            "tool receipt {} must target the mercury tool server",
            receipt.id
        )));
    }
    if !receipt
        .action
        .verify_hash()
        .map_err(|error| MercuryContractError::Validation(error.to_string()))?
    {
        return Err(MercuryContractError::Validation(format!(
            "tool receipt action hash verification failed: {}",
            receipt.id
        )));
    }
    let parameters = receipt.action.parameters.as_object().ok_or_else(|| {
        MercuryContractError::Validation(format!(
            "tool receipt {} action parameters must be an object",
            receipt.id
        ))
    })?;
    let expected_bindings = [
        (
            "workflowId",
            serde_json::Value::String(metadata.business_ids.workflow_id.clone()),
        ),
        (
            "eventId",
            serde_json::Value::String(metadata.chronology.event_id.clone()),
        ),
        (
            "decisionType",
            serde_json::Value::String(metadata.decision_context.decision_type.as_str().to_string()),
        ),
        (
            "stage",
            serde_json::to_value(metadata.chronology.stage)
                .map_err(|error| MercuryContractError::Json(error.to_string()))?,
        ),
    ];
    for (field, expected) in expected_bindings {
        if parameters.get(field) != Some(&expected) {
            return Err(MercuryContractError::Validation(format!(
                "tool receipt {} action parameter {field} does not match Mercury metadata",
                receipt.id
            )));
        }
    }
    if parameters
        .get("toolName")
        .and_then(serde_json::Value::as_str)
        != Some(receipt.tool_name.as_str())
    {
        return Err(MercuryContractError::Validation(format!(
            "tool receipt {} action parameter toolName does not match the receipt tool name",
            receipt.id
        )));
    }
    Ok(())
}

fn derived_completeness_mode(bundle: &EvidenceExportBundle) -> &'static str {
    if !bundle.uncheckpointed_receipts.is_empty()
        || bundle.tool_receipts.is_empty()
        || bundle.checkpoints.is_empty()
    {
        return COMPLETENESS_BEST_EFFORT;
    }

    let tool_receipt_seqs = bundle
        .tool_receipts
        .iter()
        .map(|record| record.seq)
        .collect::<BTreeSet<_>>();
    if tool_receipt_seqs.len() != bundle.tool_receipts.len() {
        return COMPLETENESS_BEST_EFFORT;
    }

    let mut checkpoints_by_seq = BTreeMap::new();
    for checkpoint in &bundle.checkpoints {
        if checkpoints_by_seq
            .insert(checkpoint.body.checkpoint_seq, checkpoint)
            .is_some()
        {
            return COMPLETENESS_BEST_EFFORT;
        }
    }

    let mut proved_receipt_seqs = BTreeSet::new();
    for proof in &bundle.inclusion_proofs {
        if !tool_receipt_seqs.contains(&proof.receipt_seq)
            || !proved_receipt_seqs.insert(proof.receipt_seq)
        {
            return COMPLETENESS_BEST_EFFORT;
        }
        let Some(checkpoint) = checkpoints_by_seq.get(&proof.checkpoint_seq) else {
            return COMPLETENESS_BEST_EFFORT;
        };
        if proof.leaf_index != proof.proof.leaf_index {
            return COMPLETENESS_BEST_EFFORT;
        }
        let Ok(leaf_offset) = u64::try_from(proof.leaf_index) else {
            return COMPLETENESS_BEST_EFFORT;
        };
        let Some(expected_receipt_seq) = checkpoint.body.batch_start_seq.checked_add(leaf_offset)
        else {
            return COMPLETENESS_BEST_EFFORT;
        };
        if proof.merkle_root != checkpoint.body.merkle_root
            || proof.receipt_seq != expected_receipt_seq
            || proof.receipt_seq > checkpoint.body.batch_end_seq
        {
            return COMPLETENESS_BEST_EFFORT;
        }
    }

    if proved_receipt_seqs == tool_receipt_seqs {
        COMPLETENESS_FULL_CHECKPOINT_COVERAGE
    } else {
        COMPLETENESS_BEST_EFFORT
    }
}

fn verify_mercury_kernel_authority(
    bundle: &EvidenceExportBundle,
    trusted_kernel_keys: &BTreeSet<String>,
) -> Result<(), MercuryContractError> {
    for record in &bundle.tool_receipts {
        let kernel_key = record.receipt.kernel_key.to_hex();
        if !trusted_kernel_keys.contains(&kernel_key) {
            return Err(MercuryContractError::Validation(format!(
                "tool receipt {} was signed by an untrusted Mercury kernel key",
                record.receipt.id
            )));
        }
    }
    for record in &bundle.child_receipts {
        let kernel_key = record.receipt.kernel_key.to_hex();
        if !trusted_kernel_keys.contains(&kernel_key) {
            return Err(MercuryContractError::Validation(format!(
                "child receipt {} was signed by an untrusted Mercury kernel key",
                record.receipt.id
            )));
        }
    }
    for checkpoint in &bundle.checkpoints {
        let kernel_key = checkpoint.body.kernel_key.to_hex();
        if !trusted_kernel_keys.contains(&kernel_key) {
            return Err(MercuryContractError::Validation(format!(
                "checkpoint {} was signed by an untrusted Mercury kernel key",
                checkpoint.body.checkpoint_seq
            )));
        }
    }
    Ok(())
}

fn verify_trusted_checkpoint_requirements(
    bundle: &EvidenceExportBundle,
    publication_profile: &MercuryPublicationProfile,
) -> Result<(), MercuryContractError> {
    if bundle.checkpoints.is_empty() {
        return Err(MercuryContractError::Validation(
            "trusted Mercury verification requires at least one checkpoint".to_string(),
        ));
    }
    if bundle.inclusion_proofs.is_empty() {
        return Err(MercuryContractError::Validation(
            "trusted Mercury verification requires inclusion proofs".to_string(),
        ));
    }
    if !bundle.uncheckpointed_receipts.is_empty() {
        return Err(MercuryContractError::Validation(
            "trusted Mercury verification requires full checkpoint coverage".to_string(),
        ));
    }
    if !publication_profile.checkpoint_signatures_required {
        return Err(MercuryContractError::Validation(
            "trusted Mercury verification requires checkpoint_signatures_required=true".to_string(),
        ));
    }
    if !publication_profile.inclusion_proofs_required {
        return Err(MercuryContractError::Validation(
            "trusted Mercury verification requires inclusion_proofs_required=true".to_string(),
        ));
    }
    for checkpoint in &bundle.checkpoints {
        if !verify_checkpoint_signature(checkpoint)
            .map_err(|error| MercuryContractError::Validation(error.to_string()))?
        {
            return Err(MercuryContractError::Validation(format!(
                "checkpoint signature verification failed: {}",
                checkpoint.body.checkpoint_seq
            )));
        }
    }
    Ok(())
}

fn verify_signed_bundle_manifest_coverage(
    receipt_records: &[MercuryProofReceiptRecord],
    bundle_manifests: &[MercuryBundleManifest],
) -> Result<(), MercuryContractError> {
    let mut manifests_by_id = BTreeMap::new();
    for manifest in bundle_manifests {
        let reference = MercuryBundleReference::from_manifest(manifest)?;
        if manifests_by_id
            .insert(reference.bundle_id.clone(), reference)
            .is_some()
        {
            return Err(MercuryContractError::Validation(format!(
                "duplicate Mercury bundle manifest id: {}",
                manifest.bundle_id
            )));
        }
    }

    let mut signed_refs_by_id = BTreeMap::new();
    for record in receipt_records {
        for bundle_ref in &record.metadata.bundle_refs {
            if let Some(existing) = signed_refs_by_id.get(&bundle_ref.bundle_id) {
                if *existing != bundle_ref {
                    return Err(MercuryContractError::Validation(format!(
                        "conflicting signed Mercury bundle reference: {}",
                        bundle_ref.bundle_id
                    )));
                }
            } else {
                signed_refs_by_id.insert(bundle_ref.bundle_id.clone(), bundle_ref);
            }
        }
    }

    for (bundle_id, bundle_ref) in &signed_refs_by_id {
        let manifest_ref = manifests_by_id.get(bundle_id).ok_or_else(|| {
            MercuryContractError::Validation(format!(
                "signed Mercury bundle reference has no packaged manifest: {bundle_id}"
            ))
        })?;
        if bundle_ref.manifest_sha256 != manifest_ref.manifest_sha256
            || bundle_ref.artifact_count != manifest_ref.artifact_count
            || bundle_ref.retention_class != manifest_ref.retention_class
        {
            return Err(MercuryContractError::Validation(format!(
                "signed Mercury bundle reference does not match packaged manifest id/hash/artifact_count/retention_class: {bundle_id}"
            )));
        }
    }
    for bundle_id in manifests_by_id.keys() {
        if !signed_refs_by_id.contains_key(bundle_id) {
            return Err(MercuryContractError::Validation(format!(
                "packaged Mercury bundle manifest has no signed receipt reference: {bundle_id}"
            )));
        }
    }
    Ok(())
}

fn validate_checkpoint_receipt_sequence_bindings(
    bundle: &EvidenceExportBundle,
) -> Result<(), MercuryContractError> {
    let checkpoints_by_seq = bundle
        .checkpoints
        .iter()
        .map(|checkpoint| (checkpoint.body.checkpoint_seq, checkpoint))
        .collect::<BTreeMap<_, _>>();
    for proof in &bundle.inclusion_proofs {
        let checkpoint = checkpoints_by_seq
            .get(&proof.checkpoint_seq)
            .ok_or_else(|| {
                MercuryContractError::Validation(format!(
                    "inclusion proof references missing checkpoint {}",
                    proof.checkpoint_seq
                ))
            })?;
        if proof.leaf_index != proof.proof.leaf_index {
            return Err(MercuryContractError::Validation(format!(
                "inclusion proof outer leaf index {} does not match embedded leaf index {} for receipt seq {}",
                proof.leaf_index, proof.proof.leaf_index, proof.receipt_seq
            )));
        }
        let leaf_offset = u64::try_from(proof.leaf_index).map_err(|_| {
            MercuryContractError::Validation(format!(
                "inclusion proof leaf index is out of range for receipt seq {}",
                proof.receipt_seq
            ))
        })?;
        let expected_receipt_seq = checkpoint
            .body
            .batch_start_seq
            .checked_add(leaf_offset)
            .ok_or_else(|| {
                MercuryContractError::Validation(format!(
                    "inclusion proof sequence binding overflow for receipt seq {}",
                    proof.receipt_seq
                ))
            })?;
        if proof.receipt_seq != expected_receipt_seq
            || proof.receipt_seq > checkpoint.body.batch_end_seq
        {
            return Err(MercuryContractError::Validation(format!(
                "inclusion proof receipt seq {} does not match checkpoint leaf sequence {}",
                proof.receipt_seq, expected_receipt_seq
            )));
        }
    }
    Ok(())
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
        if proof.leaf_index != proof.proof.leaf_index {
            return Err(MercuryContractError::Validation(format!(
                "inclusion proof outer leaf index {} does not match embedded leaf index {} for receipt seq {}",
                proof.leaf_index, proof.proof.leaf_index, proof.receipt_seq
            )));
        }
        let leaf_offset = u64::try_from(proof.leaf_index).map_err(|_| {
            MercuryContractError::Validation(format!(
                "inclusion proof leaf index is out of range for receipt seq {}",
                proof.receipt_seq
            ))
        })?;
        let expected_receipt_seq = checkpoint
            .body
            .batch_start_seq
            .checked_add(leaf_offset)
            .ok_or_else(|| {
                MercuryContractError::Validation(format!(
                    "inclusion proof sequence binding overflow for receipt seq {}",
                    proof.receipt_seq
                ))
            })?;
        if proof.receipt_seq != expected_receipt_seq
            || proof.receipt_seq > checkpoint.body.batch_end_seq
        {
            return Err(MercuryContractError::Validation(format!(
                "inclusion proof receipt seq {} does not match checkpoint leaf sequence {}",
                proof.receipt_seq, expected_receipt_seq
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
        let receipt = tool_receipts_by_seq.get(&record.seq).ok_or_else(|| {
            MercuryContractError::Validation(format!(
                "uncheckpointed receipt seq {} is not present in tool receipts",
                record.seq
            ))
        })?;
        if record.receipt_id != receipt.id {
            return Err(MercuryContractError::Validation(format!(
                "uncheckpointed receipt id {} does not match tool receipt {} at seq {}",
                record.receipt_id, receipt.id, record.seq
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
        decision::Decision, decision::ToolCallAction, lineage::ChildRequestReceipt,
        lineage::ChildRequestReceiptBody,
    };
    use chio_core::session::{OperationKind, OperationTerminalState, RequestId, SessionId};
    use chio_kernel::checkpoint::{
        build_checkpoint, build_checkpoint_with_previous, build_inclusion_proof,
        build_trust_anchored_checkpoint_publication, validate_checkpoint_transparency,
        CheckpointTransparencySummary,
    };
    use chio_kernel::evidence_export::{
        EvidenceChildReceiptRecord, EvidenceChildReceiptScope, EvidenceExportQuery,
        EvidenceRetentionMetadata, EvidenceToolReceiptRecord, EvidenceUncheckpointedReceipt,
    };

    use crate::fixtures::{sample_mercury_bundle_manifest, sample_mercury_receipt_metadata};

    use super::*;

    fn sample_receipt(sequence: u64) -> ChioReceipt {
        let keypair = Keypair::generate();
        sample_receipt_with_key(sequence, &keypair)
    }

    fn sample_receipt_with_key(sequence: u64, keypair: &Keypair) -> ChioReceipt {
        let mercury_metadata = sample_mercury_receipt_metadata();
        sample_receipt_with_metadata(sequence, keypair, mercury_metadata)
    }

    fn sample_receipt_with_metadata(
        sequence: u64,
        keypair: &Keypair,
        mercury_metadata: MercuryReceiptMetadata,
    ) -> ChioReceipt {
        let action_parameters = mercury_action_parameters(&mercury_metadata);
        let action = ToolCallAction::from_parameters(action_parameters).expect("action");
        signed_sample_receipt_with_action_and_metadata(
            sequence,
            keypair,
            Some(Decision::Allow),
            "mercury",
            "release_control",
            action,
            mercury_metadata,
        )
    }

    fn mercury_action_parameters(metadata: &MercuryReceiptMetadata) -> serde_json::Value {
        serde_json::json!({
            "workflowId": metadata.business_ids.workflow_id,
            "eventId": metadata.chronology.event_id,
            "decisionType": metadata.decision_context.decision_type.as_str(),
            "stage": metadata.chronology.stage,
            "toolName": "release_control",
        })
    }

    fn signed_sample_receipt(
        sequence: u64,
        keypair: &Keypair,
        decision: Option<Decision>,
        tool_server: &str,
        action_parameters: serde_json::Value,
    ) -> ChioReceipt {
        let action = ToolCallAction::from_parameters(action_parameters).expect("action");
        signed_sample_receipt_with_action(
            sequence,
            keypair,
            decision,
            tool_server,
            "release_control",
            action,
        )
    }

    fn signed_sample_receipt_with_action(
        sequence: u64,
        keypair: &Keypair,
        decision: Option<Decision>,
        tool_server: &str,
        tool_name: &str,
        action: ToolCallAction,
    ) -> ChioReceipt {
        let mercury_metadata = sample_mercury_receipt_metadata();
        signed_sample_receipt_with_action_and_metadata(
            sequence,
            keypair,
            decision,
            tool_server,
            tool_name,
            action,
            mercury_metadata,
        )
    }

    fn signed_sample_receipt_with_action_and_metadata(
        sequence: u64,
        keypair: &Keypair,
        decision: Option<Decision>,
        tool_server: &str,
        tool_name: &str,
        action: ToolCallAction,
        mercury_metadata: MercuryReceiptMetadata,
    ) -> ChioReceipt {
        let metadata = mercury_metadata
            .into_receipt_metadata_value()
            .expect("metadata value");
        ChioReceipt::sign(
            ChioReceiptBody {
                id: format!("receipt-proof-{sequence}"),
                timestamp: 1_775_137_625 + sequence,
                capability_id: format!("cap-proof-{sequence}"),
                tool_server: tool_server.to_string(),
                tool_name: tool_name.to_string(),
                action,
                decision,
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
            keypair,
        )
        .expect("sign receipt")
    }

    fn sample_bundle() -> EvidenceExportBundle {
        sample_bundle_with_receipt(sample_receipt(1))
    }

    fn sample_bundle_with_receipt(receipt: ChioReceipt) -> EvidenceExportBundle {
        let checkpoint_keypair = Keypair::generate();
        sample_bundle_with_records(
            vec![EvidenceToolReceiptRecord { seq: 1, receipt }],
            Vec::new(),
            &checkpoint_keypair,
        )
    }

    fn sample_bundle_with_records(
        tool_receipts: Vec<EvidenceToolReceiptRecord>,
        child_receipts: Vec<EvidenceChildReceiptRecord>,
        checkpoint_keypair: &Keypair,
    ) -> EvidenceExportBundle {
        let canonical = tool_receipts
            .iter()
            .map(|record| canonical_json_bytes(&record.receipt).expect("canonical receipt"))
            .collect::<Vec<_>>();
        let batch_start_seq = tool_receipts
            .iter()
            .map(|record| record.seq)
            .min()
            .expect("tool receipts");
        let batch_end_seq = tool_receipts
            .iter()
            .map(|record| record.seq)
            .max()
            .expect("tool receipts");
        let checkpoint = build_checkpoint(
            1,
            batch_start_seq,
            batch_end_seq,
            &canonical,
            checkpoint_keypair,
        )
        .expect("checkpoint");
        let tree = MerkleTree::from_leaves(&canonical).expect("merkle tree");
        let inclusion_proofs = tool_receipts
            .iter()
            .enumerate()
            .map(|(index, record)| {
                build_inclusion_proof(&tree, index, checkpoint.body.checkpoint_seq, record.seq)
                    .expect("proof")
            })
            .collect();
        EvidenceExportBundle {
            query: EvidenceExportQuery::default(),
            tool_receipts,
            child_receipt_scope: if child_receipts.is_empty() {
                EvidenceChildReceiptScope::OmittedNoJoinPath
            } else {
                EvidenceChildReceiptScope::FullQueryWindow
            },
            child_receipts,
            checkpoints: vec![checkpoint],
            capability_lineage: Vec::new(),
            inclusion_proofs,
            uncheckpointed_receipts: Vec::new(),
            retention: EvidenceRetentionMetadata {
                live_db_size_bytes: Some(1_024),
                oldest_live_receipt_timestamp: Some(1_775_137_626),
            },
        }
    }

    fn sample_child_receipt(sequence: u64, keypair: &Keypair) -> ChildRequestReceipt {
        ChildRequestReceipt::sign(
            ChildRequestReceiptBody {
                id: format!("child-receipt-{sequence}"),
                timestamp: 1_775_137_650 + sequence,
                session_id: SessionId::new(format!("session-{sequence}")),
                parent_request_id: RequestId::new(format!("parent-request-{sequence}")),
                request_id: RequestId::new(format!("child-request-{sequence}")),
                operation_kind: OperationKind::CreateMessage,
                terminal_state: OperationTerminalState::Completed,
                outcome_hash: format!("outcome-{sequence}"),
                policy_hash: format!("policy-child-{sequence}"),
                metadata: None,
                kernel_key: keypair.public_key(),
            },
            keypair,
        )
        .expect("child receipt")
    }

    fn metadata_with_bundle_refs(
        bundle_refs: Vec<MercuryBundleReference>,
    ) -> MercuryReceiptMetadata {
        let mut metadata = sample_mercury_receipt_metadata();
        metadata.bundle_refs = bundle_refs;
        metadata
    }

    fn trusted_authority_keys(bundle: &EvidenceExportBundle) -> BTreeSet<String> {
        bundle
            .tool_receipts
            .iter()
            .map(|record| record.receipt.kernel_key.to_hex())
            .chain(
                bundle
                    .child_receipts
                    .iter()
                    .map(|record| record.receipt.kernel_key.to_hex()),
            )
            .chain(
                bundle
                    .checkpoints
                    .iter()
                    .map(|checkpoint| checkpoint.body.kernel_key.to_hex()),
            )
            .collect()
    }

    fn build_sample_proof_package(
        bundle: EvidenceExportBundle,
    ) -> Result<MercuryProofPackage, MercuryContractError> {
        MercuryProofPackage::build(
            bundle,
            "manifest-sha256-proof",
            "chio.evidence_export_manifest.v1",
            1_775_137_700,
            1_775_137_800,
            MercuryPublicationProfile::pilot_default(),
            None,
            vec![sample_mercury_bundle_manifest()],
        )
    }

    fn build_partial_checkpoint_sample_package() -> MercuryProofPackage {
        let mut bundle = sample_bundle();
        let receipt_id = bundle.tool_receipts[0].receipt.id.clone();
        bundle.checkpoints.clear();
        bundle.inclusion_proofs.clear();
        bundle.uncheckpointed_receipts = vec![EvidenceUncheckpointedReceipt { seq: 1, receipt_id }];
        let mut profile = MercuryPublicationProfile::pilot_default();
        profile.checkpoint_continuity = CHECKPOINT_CONTINUITY_AUDIT_ONLY.to_string();
        profile.checkpoint_signatures_required = false;
        profile.inclusion_proofs_required = false;
        MercuryProofPackage::build(
            bundle,
            "manifest-sha256-proof",
            "chio.evidence_export_manifest.v1",
            1_775_137_700,
            1_775_137_800,
            profile,
            None,
            vec![sample_mercury_bundle_manifest()],
        )
        .expect("partial checkpoint proof package")
    }

    fn proof_package_with_signed_refs(
        bundle_refs: Vec<MercuryBundleReference>,
        manifests: Vec<MercuryBundleManifest>,
    ) -> MercuryProofPackage {
        let receipt_keypair = Keypair::generate();
        let receipt = sample_receipt_with_metadata(
            1,
            &receipt_keypair,
            metadata_with_bundle_refs(bundle_refs),
        );
        MercuryProofPackage::build(
            sample_bundle_with_receipt(receipt),
            "manifest-sha256-proof",
            "chio.evidence_export_manifest.v1",
            1_775_137_700,
            1_775_137_800,
            MercuryPublicationProfile::pilot_default(),
            None,
            manifests,
        )
        .expect("proof package")
    }

    fn full_trusted_sample_package() -> MercuryProofPackage {
        let manifest = sample_mercury_bundle_manifest();
        let bundle_ref = MercuryBundleReference::from_manifest(&manifest).expect("bundle ref");
        let receipt_keypair = Keypair::generate();
        let child_keypair = Keypair::generate();
        let checkpoint_keypair = Keypair::generate();
        let receipt = sample_receipt_with_metadata(
            1,
            &receipt_keypair,
            metadata_with_bundle_refs(vec![bundle_ref]),
        );
        let child_receipt = sample_child_receipt(1, &child_keypair);
        let bundle = sample_bundle_with_records(
            vec![EvidenceToolReceiptRecord { seq: 1, receipt }],
            vec![EvidenceChildReceiptRecord {
                seq: 1,
                receipt: child_receipt,
            }],
            &checkpoint_keypair,
        );
        MercuryProofPackage::build(
            bundle,
            "manifest-sha256-proof",
            "chio.evidence_export_manifest.v1",
            1_775_137_700,
            1_775_137_800,
            MercuryPublicationProfile::pilot_default(),
            None,
            vec![manifest],
        )
        .expect("full trusted proof package")
    }

    fn inquiry_package_with_metadata(
        mut metadata: MercuryReceiptMetadata,
        audience: &str,
        redaction_profile: Option<&str>,
        verifier_equivalent: bool,
    ) -> MercuryInquiryPackage {
        let manifest = sample_mercury_bundle_manifest();
        metadata.bundle_refs =
            vec![MercuryBundleReference::from_manifest(&manifest).expect("bundle ref")];
        let receipt_keypair = Keypair::generate();
        let receipt = sample_receipt_with_metadata(1, &receipt_keypair, metadata);
        let proof_package = MercuryProofPackage::build(
            sample_bundle_with_receipt(receipt),
            "manifest-sha256-proof",
            "chio.evidence_export_manifest.v1",
            1_775_137_700,
            1_775_137_800,
            MercuryPublicationProfile::pilot_default(),
            None,
            vec![manifest],
        )
        .expect("proof package");
        MercuryInquiryPackage::build(
            proof_package,
            MercuryInquiryPackageArgs {
                created_at: 1_775_137_901,
                audience: audience.to_string(),
                redaction_profile: redaction_profile.map(ToOwned::to_owned),
                verifier_equivalent,
            },
        )
        .expect("inquiry package")
    }

    fn sample_bundle_with_publication_records(
    ) -> (EvidenceExportBundle, CheckpointTransparencySummary) {
        let manifest = sample_mercury_bundle_manifest();
        let bundle_ref = MercuryBundleReference::from_manifest(&manifest).expect("bundle ref");
        let first_keypair = Keypair::generate();
        let first_receipt = sample_receipt_with_metadata(
            1,
            &first_keypair,
            metadata_with_bundle_refs(vec![bundle_ref]),
        );
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
        assert!(!report.verifier_equivalent);
    }

    #[test]
    fn proof_package_rejects_partial_checkpoint_bundle_claiming_full_coverage() {
        let mut package = build_partial_checkpoint_sample_package();
        assert_eq!(
            package.publication_profile.completeness_mode,
            COMPLETENESS_BEST_EFFORT
        );
        package.publication_profile.completeness_mode =
            COMPLETENESS_FULL_CHECKPOINT_COVERAGE.to_string();
        package.refresh_package_id().expect("refresh package id");

        let error = package
            .validate()
            .expect_err("partial checkpoint coverage cannot claim full coverage");

        assert!(
            error
                .to_string()
                .contains("completeness_mode must be best_effort"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn proof_package_rejects_full_coverage_when_inclusion_proof_is_missing() {
        let mut incomplete_bundle = sample_bundle();
        incomplete_bundle.inclusion_proofs.clear();
        assert!(incomplete_bundle.uncheckpointed_receipts.is_empty());
        assert_eq!(
            derived_completeness_mode(&incomplete_bundle),
            COMPLETENESS_BEST_EFFORT
        );

        let mut package =
            build_sample_proof_package(incomplete_bundle).expect("best-effort proof package");
        assert_eq!(
            package.publication_profile.completeness_mode,
            COMPLETENESS_BEST_EFFORT
        );
        package.publication_profile.inclusion_proofs_required = false;
        package.refresh_package_id().expect("refresh package id");

        let error = package
            .verify(1_775_137_923)
            .expect_err("verification must derive the missing checkpoint coverage");
        assert!(
            error.to_string().contains(
                "declared uncheckpointed receipts do not match derived checkpoint coverage"
            ),
            "unexpected error: {error}"
        );

        package.publication_profile.completeness_mode =
            COMPLETENESS_FULL_CHECKPOINT_COVERAGE.to_string();
        package.refresh_package_id().expect("refresh package id");

        let error = package
            .validate()
            .expect_err("validation cannot trust an empty uncheckpointed declaration");
        assert!(
            error
                .to_string()
                .contains("completeness_mode must be best_effort"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn proof_package_rejects_mismatched_outer_and_embedded_leaf_indexes() {
        let mut bundle = sample_bundle();
        let embedded_leaf_index = bundle.inclusion_proofs[0].proof.leaf_index;
        bundle.inclusion_proofs[0].leaf_index = embedded_leaf_index.saturating_add(1);

        assert_eq!(derived_completeness_mode(&bundle), COMPLETENESS_BEST_EFFORT);
        let error = match validate_checkpoint_receipt_sequence_bindings(&bundle) {
            Ok(()) => panic!("outer and embedded proof indexes must match"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("does not match embedded leaf index"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn proof_package_rejects_uncheckpointed_receipt_id_mismatch() {
        let mut package = build_partial_checkpoint_sample_package();
        package.chio_bundle.uncheckpointed_receipts[0].receipt_id =
            "receipt-sha256-attacker".to_string();
        package.refresh_package_id().expect("refresh package id");

        let error = package
            .verify(1_775_137_923)
            .expect_err("uncheckpointed receipt id must bind to its tool receipt");
        assert!(
            error.to_string().contains("uncheckpointed receipt id"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn proof_package_rejects_false_or_unknown_full_coverage_labels() {
        let package = build_sample_proof_package(sample_bundle()).expect("proof package");
        assert_eq!(
            package.publication_profile.completeness_mode,
            COMPLETENESS_FULL_CHECKPOINT_COVERAGE
        );

        let mut best_effort = package.clone();
        best_effort.publication_profile.completeness_mode = COMPLETENESS_BEST_EFFORT.to_string();
        best_effort
            .refresh_package_id()
            .expect("refresh package id");
        let error = best_effort
            .validate()
            .expect_err("full checkpoint coverage cannot claim best effort");
        assert!(
            error
                .to_string()
                .contains("completeness_mode must be full_checkpoint_coverage"),
            "unexpected error: {error}"
        );

        let mut arbitrary = package;
        arbitrary.publication_profile.completeness_mode = "arbitrary".to_string();
        arbitrary.refresh_package_id().expect("refresh package id");
        let error = arbitrary
            .validate()
            .expect_err("full checkpoint coverage cannot use an unknown label");
        assert!(
            error
                .to_string()
                .contains("unsupported publication_profile.completeness_mode: arbitrary"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn proof_package_rejects_package_id_tampering() {
        let mut package = build_sample_proof_package(sample_bundle()).expect("proof package");
        package.package_id = "proof-attacker-selected".to_string();

        let error = package.validate().expect_err("tampered package id");

        assert!(
            error
                .to_string()
                .contains("does not match the deterministic proof-package identity"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn proof_package_rejects_mixed_signed_receipt_workflows() {
        let manifest = sample_mercury_bundle_manifest();
        let bundle_ref = MercuryBundleReference::from_manifest(&manifest).expect("bundle ref");
        let first_keypair = Keypair::generate();
        let second_keypair = Keypair::generate();
        let checkpoint_keypair = Keypair::generate();
        let first_receipt = sample_receipt_with_metadata(
            1,
            &first_keypair,
            metadata_with_bundle_refs(vec![bundle_ref]),
        );
        let second_receipt = sample_receipt_with_key(2, &second_keypair);
        let initial_bundle = sample_bundle_with_records(
            vec![
                EvidenceToolReceiptRecord {
                    seq: 1,
                    receipt: first_receipt,
                },
                EvidenceToolReceiptRecord {
                    seq: 2,
                    receipt: second_receipt,
                },
            ],
            Vec::new(),
            &checkpoint_keypair,
        );
        let mut package = MercuryProofPackage::build(
            initial_bundle,
            "manifest-sha256-proof",
            "chio.evidence_export_manifest.v1",
            1_775_137_700,
            1_775_137_800,
            MercuryPublicationProfile::pilot_default(),
            None,
            vec![manifest],
        )
        .expect("initial proof package");

        let mut second_metadata = sample_mercury_receipt_metadata();
        second_metadata.business_ids.workflow_id = "workflow-other".to_string();
        let mixed_receipt =
            sample_receipt_with_metadata(2, &second_keypair, second_metadata.clone());
        package.chio_bundle = sample_bundle_with_records(
            vec![
                package.chio_bundle.tool_receipts[0].clone(),
                EvidenceToolReceiptRecord {
                    seq: 2,
                    receipt: mixed_receipt.clone(),
                },
            ],
            Vec::new(),
            &checkpoint_keypair,
        );
        package.receipt_records[1] = MercuryProofReceiptRecord {
            receipt_id: mixed_receipt.id.clone(),
            seq: 2,
            metadata: second_metadata,
        };
        let (checkpoint_transparency, publication_claim_boundary) =
            derive_publication_materials_with_summary(
                &package.chio_bundle,
                &package.publication_profile,
                None,
            )
            .expect("publication materials");
        package.checkpoint_transparency = checkpoint_transparency;
        package.publication_claim_boundary = Some(publication_claim_boundary);
        package.package_id = derive_proof_package_id(&package).expect("package id");

        let error = package
            .validate()
            .expect_err("mixed signed receipt workflows");

        assert!(
            error
                .to_string()
                .contains("workflow_id does not match proof-package workflow_id"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn proof_package_rejects_optional_business_id_tampering_after_identity_recomputation() {
        let mut account_package =
            build_sample_proof_package(sample_bundle()).expect("account package");
        account_package.account_id = Some("account-attacker".to_string());
        account_package.package_id =
            derive_proof_package_id(&account_package).expect("account package id");
        let error = account_package.validate().expect_err("tampered account id");
        assert!(
            error
                .to_string()
                .contains("account_id does not match the signed receipt metadata summary"),
            "unexpected error: {error}"
        );

        let mut desk_package = build_sample_proof_package(sample_bundle()).expect("desk package");
        desk_package.desk_id = Some("desk-attacker".to_string());
        desk_package.package_id = derive_proof_package_id(&desk_package).expect("desk package id");
        let error = desk_package.validate().expect_err("tampered desk id");
        assert!(
            error
                .to_string()
                .contains("desk_id does not match the signed receipt metadata summary"),
            "unexpected error: {error}"
        );

        let mut strategy_package =
            build_sample_proof_package(sample_bundle()).expect("strategy package");
        strategy_package.strategy_id = Some("strategy-attacker".to_string());
        strategy_package.package_id =
            derive_proof_package_id(&strategy_package).expect("strategy package id");
        let error = strategy_package
            .validate()
            .expect_err("tampered strategy id");
        assert!(
            error
                .to_string()
                .contains("strategy_id does not match the signed receipt metadata summary"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn proof_package_rejects_export_descriptor_tampering_without_identity_recomputation() {
        let package = build_sample_proof_package(sample_bundle()).expect("proof package");

        let mut hash_tamper = package.clone();
        hash_tamper.evidence_export_manifest_hash = "manifest-attacker".to_string();
        let error = hash_tamper
            .validate()
            .expect_err("tampered export manifest hash");
        assert!(
            error
                .to_string()
                .contains("does not match the deterministic proof-package identity"),
            "unexpected error: {error}"
        );

        let mut schema_tamper = package.clone();
        schema_tamper.evidence_export_schema = "attacker.schema.v1".to_string();
        let error = schema_tamper
            .validate()
            .expect_err("tampered export schema");
        assert!(
            error
                .to_string()
                .contains("does not match the deterministic proof-package identity"),
            "unexpected error: {error}"
        );

        let mut timestamp_tamper = package;
        timestamp_tamper.evidence_exported_at += 1;
        let error = timestamp_tamper
            .validate()
            .expect_err("tampered export timestamp");
        assert!(
            error
                .to_string()
                .contains("does not match the deterministic proof-package identity"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn proof_package_rejects_signed_deny_receipt() {
        let keypair = Keypair::generate();
        let metadata = sample_mercury_receipt_metadata();
        let receipt = signed_sample_receipt(
            1,
            &keypair,
            Some(Decision::Deny {
                reason: "approval missing".to_string(),
                guard: "approval".to_string(),
            }),
            "mercury",
            mercury_action_parameters(&metadata),
        );

        let error = build_sample_proof_package(sample_bundle_with_receipt(receipt))
            .expect_err("signed deny receipt");

        assert!(
            error.to_string().contains("must carry an allow decision"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn proof_package_rejects_signed_observation_as_mercury_authorization() {
        use chio_core::receipt::kinds::{BoundaryClass, ObservationOutcome};

        let keypair = Keypair::generate();
        let mut body = sample_receipt_with_key(1, &keypair).body();
        body.decision = None;
        body.receipt_kind = ReceiptKind::TraceObservation;
        body.boundary_class = BoundaryClass::DetectOnly;
        body.observation_outcome = Some(ObservationOutcome::Observed);
        body.trust_level = TrustLevel::Verified;
        let observation = ChioReceipt::sign(body, &keypair).expect("signed observation receipt");
        assert!(observation.verify_signature().expect("verify observation"));

        let error = build_sample_proof_package(sample_bundle_with_receipt(observation))
            .expect_err("observation receipt cannot authorize Mercury action");

        assert!(
            error
                .to_string()
                .contains("must be a kernel-mediated decision receipt"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn proof_package_rejects_wrong_tool_server() {
        let keypair = Keypair::generate();
        let metadata = sample_mercury_receipt_metadata();
        let receipt = signed_sample_receipt(
            1,
            &keypair,
            Some(Decision::Allow),
            "other-server",
            mercury_action_parameters(&metadata),
        );

        let error = build_sample_proof_package(sample_bundle_with_receipt(receipt))
            .expect_err("wrong tool server");

        assert!(
            error
                .to_string()
                .contains("must target the mercury tool server"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn proof_package_rejects_tool_action_metadata_mismatches() {
        for field in ["workflowId", "eventId", "decisionType", "stage"] {
            let keypair = Keypair::generate();
            let metadata = sample_mercury_receipt_metadata();
            let mut action_parameters = mercury_action_parameters(&metadata);
            action_parameters[field] = serde_json::Value::String("wrong-binding".to_string());
            let receipt = signed_sample_receipt(
                1,
                &keypair,
                Some(Decision::Allow),
                "mercury",
                action_parameters,
            );

            let error = build_sample_proof_package(sample_bundle_with_receipt(receipt))
                .expect_err("action metadata mismatch");

            assert!(
                error.to_string().contains(field),
                "unexpected error for {field}: {error}"
            );
        }
    }

    #[test]
    fn proof_package_rejects_unverified_tool_action() {
        let keypair = Keypair::generate();
        let metadata = sample_mercury_receipt_metadata();
        let mut action =
            ToolCallAction::from_parameters(mercury_action_parameters(&metadata)).expect("action");
        action.parameter_hash = "invalid-action-hash".to_string();
        let receipt = signed_sample_receipt_with_action(
            1,
            &keypair,
            Some(Decision::Allow),
            "mercury",
            "release_control",
            action,
        );

        let error = build_sample_proof_package(sample_bundle_with_receipt(receipt))
            .expect_err("unverified tool action");

        assert!(
            error
                .to_string()
                .contains("action hash verification failed"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn proof_package_rejects_tool_name_action_mismatch() {
        let keypair = Keypair::generate();
        let metadata = sample_mercury_receipt_metadata();
        let action =
            ToolCallAction::from_parameters(mercury_action_parameters(&metadata)).expect("action");
        let receipt = signed_sample_receipt_with_action(
            1,
            &keypair,
            Some(Decision::Allow),
            "mercury",
            "rollback_control",
            action,
        );

        let error = build_sample_proof_package(sample_bundle_with_receipt(receipt))
            .expect_err("tool name action mismatch");

        assert!(
            error.to_string().contains("toolName"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn proof_package_requires_explicitly_trusted_mercury_signer_for_equivalence() {
        let mercury_keypair = Keypair::generate();
        let manifest = sample_mercury_bundle_manifest();
        let bundle_ref = MercuryBundleReference::from_manifest(&manifest).expect("bundle ref");
        let receipt = sample_receipt_with_metadata(
            1,
            &mercury_keypair,
            metadata_with_bundle_refs(vec![bundle_ref]),
        );
        let bundle = sample_bundle_with_receipt(receipt);
        let trusted_keys = trusted_authority_keys(&bundle);
        let package = MercuryProofPackage::build(
            bundle,
            "manifest-sha256-proof",
            "chio.evidence_export_manifest.v1",
            1_775_137_700,
            1_775_137_800,
            MercuryPublicationProfile::pilot_default(),
            None,
            vec![manifest],
        )
        .expect("proof package");

        let structural_report = package.verify(1_775_137_900).expect("structural report");
        assert!(!structural_report.verifier_equivalent);

        let untrusted_keypair = Keypair::generate();
        let untrusted_keys = BTreeSet::from([untrusted_keypair.public_key().to_hex()]);
        let error = package
            .verify_with_trusted_kernel_keys(1_775_137_901, &untrusted_keys)
            .expect_err("self-signed untrusted receipt");
        assert!(
            error.to_string().contains("untrusted Mercury kernel key"),
            "unexpected error: {error}"
        );

        let trusted_report = package
            .verify_with_trusted_kernel_keys(1_775_137_902, &trusted_keys)
            .expect("trusted verification report");
        assert!(trusted_report.verifier_equivalent);
    }

    #[test]
    fn trusted_proof_verification_requires_exact_signed_manifest_coverage() {
        let manifest = sample_mercury_bundle_manifest();
        let bundle_ref = MercuryBundleReference::from_manifest(&manifest).expect("bundle ref");

        let duplicate_ref_package = proof_package_with_signed_refs(
            vec![bundle_ref.clone(), bundle_ref.clone()],
            vec![manifest.clone()],
        );
        let trusted_keys = trusted_authority_keys(&duplicate_ref_package.chio_bundle);
        duplicate_ref_package
            .verify_with_trusted_kernel_keys(1_775_137_910, &trusted_keys)
            .expect("identical signed refs are deduplicated across receipts");

        let mut conflicting_ref = bundle_ref.clone();
        conflicting_ref.artifact_count = conflicting_ref.artifact_count.saturating_add(1);
        let conflicting_ref_package = proof_package_with_signed_refs(
            vec![bundle_ref.clone(), conflicting_ref],
            vec![manifest.clone()],
        );
        let trusted_keys = trusted_authority_keys(&conflicting_ref_package.chio_bundle);
        let error = conflicting_ref_package
            .verify_with_trusted_kernel_keys(1_775_137_910, &trusted_keys)
            .expect_err("conflicting signed refs");
        assert!(
            error
                .to_string()
                .contains("conflicting signed Mercury bundle reference"),
            "unexpected error: {error}"
        );

        let mut missing_ref = bundle_ref.clone();
        missing_ref.bundle_id = "bundle-missing".to_string();
        let missing_manifest_package =
            proof_package_with_signed_refs(vec![missing_ref], vec![manifest.clone()]);
        let trusted_keys = trusted_authority_keys(&missing_manifest_package.chio_bundle);
        let error = missing_manifest_package
            .verify_with_trusted_kernel_keys(1_775_137_911, &trusted_keys)
            .expect_err("missing packaged manifest");
        assert!(
            error.to_string().contains("has no packaged manifest"),
            "unexpected error: {error}"
        );

        let mut unreferenced_manifest = manifest.clone();
        unreferenced_manifest.bundle_id = "bundle-unreferenced".to_string();
        let unreferenced_manifest_package = proof_package_with_signed_refs(
            vec![bundle_ref.clone()],
            vec![manifest.clone(), unreferenced_manifest],
        );
        let trusted_keys = trusted_authority_keys(&unreferenced_manifest_package.chio_bundle);
        let error = unreferenced_manifest_package
            .verify_with_trusted_kernel_keys(1_775_137_912, &trusted_keys)
            .expect_err("unreferenced packaged manifest");
        assert!(
            error
                .to_string()
                .contains("has no signed receipt reference"),
            "unexpected error: {error}"
        );

        let duplicate_manifest_package =
            proof_package_with_signed_refs(vec![bundle_ref], vec![manifest.clone(), manifest]);
        let trusted_keys = trusted_authority_keys(&duplicate_manifest_package.chio_bundle);
        let error = duplicate_manifest_package
            .verify_with_trusted_kernel_keys(1_775_137_913, &trusted_keys)
            .expect_err("duplicate packaged manifests");
        assert!(
            error
                .to_string()
                .contains("duplicate Mercury bundle manifest id"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn trusted_proof_verification_binds_manifest_hash_artifact_count_and_retention_class() {
        let mutations: [fn(&mut MercuryBundleReference); 3] = [
            |bundle_ref: &mut MercuryBundleReference| {
                bundle_ref.manifest_sha256 = "wrong-manifest-hash".to_string();
            },
            |bundle_ref: &mut MercuryBundleReference| {
                bundle_ref.artifact_count += 1;
            },
            |bundle_ref: &mut MercuryBundleReference| {
                bundle_ref.retention_class = Some("wrong-retention-class".to_string());
            },
        ];
        for mutate in mutations {
            let manifest = sample_mercury_bundle_manifest();
            let mut bundle_ref =
                MercuryBundleReference::from_manifest(&manifest).expect("bundle ref");
            mutate(&mut bundle_ref);
            let package = proof_package_with_signed_refs(vec![bundle_ref], vec![manifest]);
            let trusted_keys = trusted_authority_keys(&package.chio_bundle);
            let error = package
                .verify_with_trusted_kernel_keys(1_775_137_914, &trusted_keys)
                .expect_err("manifest reference mismatch");
            assert!(
                error.to_string().contains(
                    "does not match packaged manifest id/hash/artifact_count/retention_class"
                ),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn trusted_proof_verification_accepts_full_trusted_authority_scope() {
        let package = full_trusted_sample_package();
        let trusted_keys = trusted_authority_keys(&package.chio_bundle);

        let report = package
            .verify_with_trusted_kernel_keys(1_775_137_920, &trusted_keys)
            .expect("full trusted authority scope");

        assert!(report.verifier_equivalent);
    }

    #[test]
    fn trusted_proof_verification_rejects_untrusted_child_signer() {
        let package = full_trusted_sample_package();
        let child_key = package.chio_bundle.child_receipts[0]
            .receipt
            .kernel_key
            .to_hex();
        let mut trusted_keys = trusted_authority_keys(&package.chio_bundle);
        trusted_keys.remove(&child_key);

        let error = package
            .verify_with_trusted_kernel_keys(1_775_137_921, &trusted_keys)
            .expect_err("untrusted child signer");

        assert!(
            error
                .to_string()
                .contains("child receipt child-receipt-1 was signed by an untrusted"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn trusted_proof_verification_rejects_untrusted_checkpoint_signer() {
        let package = full_trusted_sample_package();
        let checkpoint_key = package.chio_bundle.checkpoints[0].body.kernel_key.to_hex();
        let mut trusted_keys = trusted_authority_keys(&package.chio_bundle);
        trusted_keys.remove(&checkpoint_key);

        let error = package
            .verify_with_trusted_kernel_keys(1_775_137_922, &trusted_keys)
            .expect_err("untrusted checkpoint signer");

        assert!(
            error
                .to_string()
                .contains("checkpoint 1 was signed by an untrusted"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn trusted_proof_verification_rejects_invalid_checkpoint_when_profile_flag_is_false() {
        let mut package = full_trusted_sample_package();
        package.publication_profile.checkpoint_signatures_required = false;
        package.chio_bundle.checkpoints[0].signature = Keypair::generate().sign(b"invalid");
        let trusted_keys = trusted_authority_keys(&package.chio_bundle);

        let error = package
            .verify_with_trusted_kernel_keys(1_775_137_923, &trusted_keys)
            .expect_err("invalid checkpoint signature");

        assert!(
            error
                .to_string()
                .contains("checkpoint transparency verification failed"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn trusted_proof_verification_rejects_checkpoint_free_audit_only_package() {
        let manifest = sample_mercury_bundle_manifest();
        let bundle_ref = MercuryBundleReference::from_manifest(&manifest).expect("bundle ref");
        let receipt_keypair = Keypair::generate();
        let receipt = sample_receipt_with_metadata(
            1,
            &receipt_keypair,
            metadata_with_bundle_refs(vec![bundle_ref]),
        );
        let receipt_id = receipt.id.clone();
        let mut bundle = sample_bundle_with_receipt(receipt);
        bundle.checkpoints.clear();
        bundle.inclusion_proofs.clear();
        bundle.uncheckpointed_receipts = vec![EvidenceUncheckpointedReceipt { seq: 1, receipt_id }];
        let trusted_keys = trusted_authority_keys(&bundle);
        let mut profile = MercuryPublicationProfile::pilot_default();
        profile.checkpoint_continuity = CHECKPOINT_CONTINUITY_AUDIT_ONLY.to_string();
        profile.checkpoint_signatures_required = false;
        profile.inclusion_proofs_required = false;
        let package = MercuryProofPackage::build(
            bundle,
            "manifest-sha256-proof",
            "chio.evidence_export_manifest.v1",
            1_775_137_700,
            1_775_137_800,
            profile,
            None,
            vec![manifest],
        )
        .expect("checkpoint-free audit package");
        let structural_report = package.verify(1_775_137_923).expect("structural report");
        assert!(!structural_report.verifier_equivalent);

        let error = package
            .verify_with_trusted_kernel_keys(1_775_137_924, &trusted_keys)
            .expect_err("checkpoint-free trusted verification");

        assert!(
            error
                .to_string()
                .contains("trusted Mercury verification requires at least one checkpoint"),
            "unexpected error: {error}"
        );
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

        let first_signer_only = BTreeSet::from([package.chio_bundle.tool_receipts[0]
            .receipt
            .kernel_key
            .to_hex()]);
        package
            .verify_with_trusted_kernel_keys(1_775_137_901, &first_signer_only)
            .expect_err("every Mercury receipt signer must be trusted");

        let all_signers = trusted_authority_keys(&package.chio_bundle);
        let trusted_report = package
            .verify_with_trusted_kernel_keys(1_775_137_902, &all_signers)
            .expect("all Mercury receipt signers are trusted");
        assert!(trusted_report.verifier_equivalent);
    }

    #[test]
    fn inquiry_package_build_and_verify_passes() {
        let manifest = sample_mercury_bundle_manifest();
        let bundle_ref = MercuryBundleReference::from_manifest(&manifest).expect("bundle ref");
        let receipt_keypair = Keypair::generate();
        let receipt = sample_receipt_with_metadata(
            1,
            &receipt_keypair,
            metadata_with_bundle_refs(vec![bundle_ref]),
        );
        let bundle = sample_bundle_with_receipt(receipt);
        let trusted_keys = trusted_authority_keys(&bundle);
        let proof_package = MercuryProofPackage::build(
            bundle,
            "manifest-sha256-proof",
            "chio.evidence_export_manifest.v1",
            1_775_137_700,
            1_775_137_800,
            MercuryPublicationProfile::pilot_default(),
            None,
            vec![manifest],
        )
        .expect("proof package");
        let inquiry = MercuryInquiryPackage::build(
            proof_package,
            MercuryInquiryPackageArgs {
                created_at: 1_775_137_901,
                audience: "compliance".to_string(),
                redaction_profile: Some("internal-default".to_string()),
                verifier_equivalent: true,
            },
        )
        .expect("inquiry package");

        let report = inquiry.verify(1_775_137_902).expect("verification report");
        assert_eq!(report.package_kind, MercuryPackageKind::Inquiry);
        assert!(!report.verifier_equivalent);

        let trusted_report = inquiry
            .verify_with_trusted_kernel_keys(1_775_137_903, &trusted_keys)
            .expect("trusted inquiry verification report");
        assert!(trusted_report.verifier_equivalent);
    }

    #[test]
    fn inquiry_rejects_arbitrary_rendered_export_even_with_matching_self_hash() {
        let mut inquiry = inquiry_package_with_metadata(
            sample_mercury_receipt_metadata(),
            "compliance",
            Some("internal-default"),
            true,
        );
        inquiry.rendered_export = serde_json::json!({"attackerControlled": true});
        inquiry.rendered_export_sha256 = sha256_hex(
            &canonical_json(&inquiry.rendered_export, "rendered_export").expect("canonical export"),
        );

        let error = inquiry
            .validate()
            .expect_err("arbitrary export with self-consistent hash");

        assert!(
            error
                .to_string()
                .contains("not the exact deterministic inquiry projection"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn inquiry_uses_unique_max_sequence_receipt_when_signed_receipts_are_reordered() {
        let manifest = sample_mercury_bundle_manifest();
        let bundle_ref = MercuryBundleReference::from_manifest(&manifest).expect("bundle ref");
        let older_keypair = Keypair::generate();
        let newer_keypair = Keypair::generate();
        let checkpoint_keypair = Keypair::generate();
        let older = sample_receipt_with_metadata(
            1,
            &older_keypair,
            metadata_with_bundle_refs(vec![bundle_ref]),
        );
        let older_receipt_id = older.id.clone();
        let mut newer_metadata = sample_mercury_receipt_metadata();
        newer_metadata.approval_state.state = MercuryApprovalStatus::Denied;
        let newer = sample_receipt_with_metadata(2, &newer_keypair, newer_metadata.clone());
        let newer_receipt_id = newer.id.clone();
        let mut bundle = sample_bundle_with_records(
            vec![
                EvidenceToolReceiptRecord {
                    seq: 1,
                    receipt: older,
                },
                EvidenceToolReceiptRecord {
                    seq: 2,
                    receipt: newer,
                },
            ],
            Vec::new(),
            &checkpoint_keypair,
        );
        bundle.tool_receipts.swap(0, 1);
        let trusted_keys = trusted_authority_keys(&bundle);
        let proof_package = MercuryProofPackage::build(
            bundle,
            "manifest-sha256-proof",
            "chio.evidence_export_manifest.v1",
            1_775_137_700,
            1_775_137_800,
            MercuryPublicationProfile::pilot_default(),
            None,
            vec![manifest],
        )
        .expect("reordered proof package");
        let inquiry = MercuryInquiryPackage::build(
            proof_package,
            MercuryInquiryPackageArgs {
                created_at: 1_775_137_901,
                audience: "compliance".to_string(),
                redaction_profile: Some("internal-default".to_string()),
                verifier_equivalent: true,
            },
        )
        .expect("reordered inquiry package");

        assert_eq!(inquiry.approval_state, newer_metadata.approval_state);
        assert!(!inquiry.verifier_equivalent);
        assert_eq!(
            inquiry.rendered_export["authoritativeReceiptId"],
            newer_receipt_id
        );
        assert_eq!(
            inquiry.rendered_export["receiptIds"],
            serde_json::json!([older_receipt_id, newer_receipt_id])
        );
        let report = inquiry
            .verify_with_trusted_kernel_keys(1_775_137_902, &trusted_keys)
            .expect("trusted reordered inquiry");
        assert!(!report.verifier_equivalent);
    }

    #[test]
    fn inquiry_rejects_stale_receipt_sequence_manipulation() {
        let checkpoint_keypair = Keypair::generate();
        let older = sample_receipt(1);
        let newer = sample_receipt(2);
        let bundle = sample_bundle_with_records(
            vec![
                EvidenceToolReceiptRecord {
                    seq: 1,
                    receipt: older,
                },
                EvidenceToolReceiptRecord {
                    seq: 2,
                    receipt: newer,
                },
            ],
            Vec::new(),
            &checkpoint_keypair,
        );
        let mut proof_package = build_sample_proof_package(bundle).expect("proof package");
        proof_package.receipt_records.swap(0, 1);
        proof_package.chio_bundle.tool_receipts.swap(0, 1);
        proof_package.receipt_records[0].seq = 1;
        proof_package.receipt_records[1].seq = 2;
        proof_package.chio_bundle.tool_receipts[0].seq = 1;
        proof_package.chio_bundle.tool_receipts[1].seq = 2;
        proof_package.chio_bundle.inclusion_proofs[0].receipt_seq = 2;
        proof_package.chio_bundle.inclusion_proofs[1].receipt_seq = 1;
        proof_package.publication_profile.completeness_mode = COMPLETENESS_BEST_EFFORT.to_string();

        let error = MercuryInquiryPackage::build(
            proof_package,
            MercuryInquiryPackageArgs {
                created_at: 1_775_137_901,
                audience: "compliance".to_string(),
                redaction_profile: Some("internal-default".to_string()),
                verifier_equivalent: true,
            },
        )
        .expect_err("stale receipt sequence manipulation");

        assert!(
            error
                .to_string()
                .contains("does not match checkpoint leaf sequence"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn inquiry_rejects_duplicate_max_sequence_authority() {
        let checkpoint_keypair = Keypair::generate();
        let bundle = sample_bundle_with_records(
            vec![
                EvidenceToolReceiptRecord {
                    seq: 1,
                    receipt: sample_receipt(1),
                },
                EvidenceToolReceiptRecord {
                    seq: 2,
                    receipt: sample_receipt(2),
                },
            ],
            Vec::new(),
            &checkpoint_keypair,
        );
        let mut proof_package = build_sample_proof_package(bundle).expect("proof package");
        proof_package.receipt_records[0].seq = 2;
        proof_package.chio_bundle.tool_receipts[0].seq = 2;
        proof_package.publication_profile.completeness_mode = COMPLETENESS_BEST_EFFORT.to_string();
        proof_package.package_id =
            derive_proof_package_id(&proof_package).expect("recomputed package id");

        let error = MercuryInquiryPackage::build(
            proof_package,
            MercuryInquiryPackageArgs {
                created_at: 1_775_137_901,
                audience: "compliance".to_string(),
                redaction_profile: Some("internal-default".to_string()),
                verifier_equivalent: true,
            },
        )
        .expect_err("duplicate max sequence");

        assert!(
            error
                .to_string()
                .contains("authoritative receipt sequence 2 is not unique"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn inquiry_rejects_uncheckpointed_max_sequence_authority() {
        let checkpoint_keypair = Keypair::generate();
        let older = sample_receipt(1);
        let newer = sample_receipt(2);
        let newer_receipt_id = newer.id.clone();
        let mut bundle = sample_bundle_with_records(
            vec![
                EvidenceToolReceiptRecord {
                    seq: 1,
                    receipt: older,
                },
                EvidenceToolReceiptRecord {
                    seq: 2,
                    receipt: newer,
                },
            ],
            Vec::new(),
            &checkpoint_keypair,
        );
        bundle
            .inclusion_proofs
            .retain(|proof| proof.receipt_seq == 1);
        bundle.uncheckpointed_receipts = vec![EvidenceUncheckpointedReceipt {
            seq: 2,
            receipt_id: newer_receipt_id,
        }];
        let proof_package = build_sample_proof_package(bundle).expect("proof package");

        let error = MercuryInquiryPackage::build(
            proof_package,
            MercuryInquiryPackageArgs {
                created_at: 1_775_137_901,
                audience: "compliance".to_string(),
                redaction_profile: Some("internal-default".to_string()),
                verifier_equivalent: true,
            },
        )
        .expect_err("uncheckpointed maximum sequence");

        assert!(
            error
                .to_string()
                .contains("authoritative receipt sequence 2 is not checkpoint-authenticated"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn inquiry_rejects_approval_disclosure_and_equivalence_elevation() {
        let mut signed_metadata = sample_mercury_receipt_metadata();
        signed_metadata.approval_state.state = MercuryApprovalStatus::Denied;
        signed_metadata.disclosure.verifier_equivalent = false;
        signed_metadata.disclosure.reviewed_export_approved = false;
        let inquiry = inquiry_package_with_metadata(
            signed_metadata,
            "compliance",
            Some("internal-default"),
            true,
        );
        assert!(!inquiry.verifier_equivalent);

        let mut approval_elevation = inquiry.clone();
        approval_elevation.approval_state.state = MercuryApprovalStatus::Approved;
        let error = approval_elevation
            .validate()
            .expect_err("approval elevation");
        assert!(
            error
                .to_string()
                .contains("approval_state does not match the authoritative signed receipt"),
            "unexpected error: {error}"
        );

        let mut disclosure_elevation = inquiry.clone();
        disclosure_elevation.disclosure.verifier_equivalent = true;
        disclosure_elevation.disclosure.reviewed_export_approved = true;
        let error = disclosure_elevation
            .validate()
            .expect_err("disclosure elevation");
        assert!(
            error
                .to_string()
                .contains("disclosure does not match the authoritative signed receipt"),
            "unexpected error: {error}"
        );

        let mut equivalence_elevation = inquiry;
        equivalence_elevation.verifier_equivalent = true;
        let error = equivalence_elevation
            .validate()
            .expect_err("equivalence elevation");
        assert!(
            error
                .to_string()
                .contains("verifier_equivalent elevates beyond"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn inquiry_equivalence_requires_matching_signed_audience_and_redaction() {
        let audience_mismatch = inquiry_package_with_metadata(
            sample_mercury_receipt_metadata(),
            "external-review",
            Some("internal-default"),
            true,
        );
        assert!(!audience_mismatch.verifier_equivalent);

        let redaction_mismatch = inquiry_package_with_metadata(
            sample_mercury_receipt_metadata(),
            "compliance",
            Some("external-default"),
            true,
        );
        assert!(!redaction_mismatch.verifier_equivalent);

        let explicit_downgrade = inquiry_package_with_metadata(
            sample_mercury_receipt_metadata(),
            "compliance",
            Some("internal-default"),
            false,
        );
        assert!(!explicit_downgrade.verifier_equivalent);
    }
}
