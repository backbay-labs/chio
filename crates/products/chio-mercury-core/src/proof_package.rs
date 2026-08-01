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
    build_evidence_transparency_claims, EvidenceExportBundle, EvidenceExportQuery,
    EvidenceTransparencyClaims,
};
use chio_kernel::{
    is_supported_checkpoint_schema, verify_checkpoint_signature, ReceiptReadBoundary,
};
use serde::{Deserialize, Serialize};

use crate::bundle::{MercuryBundleManifest, MercuryBundleReference};
use crate::receipt_metadata::{
    MercuryApprovalState, MercuryContractError, MercuryDisclosurePolicy, MercuryReceiptMetadata,
};
use crate::validation::ensure_non_empty;

pub const MERCURY_PUBLICATION_PROFILE_SCHEMA: &str = "chio.mercury.publication_profile.v1";
pub const MERCURY_PROOF_PACKAGE_SCHEMA_V1: &str = "chio.mercury.proof_package.v1";
pub const MERCURY_PROOF_PACKAGE_SCHEMA: &str = "chio.mercury.proof_package.v2";
pub const MERCURY_INQUIRY_PACKAGE_SCHEMA: &str = "chio.mercury.inquiry_package.v1";
const CHECKPOINT_CONTINUITY_AUDIT_ONLY: &str = "audit_only";
const CHECKPOINT_CONTINUITY_TRANSPARENCY_PREVIEW: &str = "transparency_preview";
const CHECKPOINT_CONTINUITY_APPEND_ONLY: &str = "append_only";
const COMPLETENESS_BEST_EFFORT: &str = "best_effort";
const COMPLETENESS_FULL_CHECKPOINT_COVERAGE: &str = "full_checkpoint_coverage";
const COMPLETENESS_SELECTED_RECEIPT_COVERAGE: &str = "selected_receipt_coverage";

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
            COMPLETENESS_BEST_EFFORT
            | COMPLETENESS_FULL_CHECKPOINT_COVERAGE
            | COMPLETENESS_SELECTED_RECEIPT_COVERAGE => Ok(()),
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
        self.package_id = derive_proof_package_id_for_schema(self)?;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if !matches!(
            self.schema.as_str(),
            MERCURY_PROOF_PACKAGE_SCHEMA_V1 | MERCURY_PROOF_PACKAGE_SCHEMA
        ) {
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
        let expected_package_id = derive_proof_package_id_for_schema(self)?;
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
            // Trusted keys authenticate bundled receipts and checkpoints, not
            // the unsigned export query or the source log snapshot boundary.
            verifier_equivalent: false,
            steps: vec![
                MercuryVerificationStep {
                    name: "package_contract".to_string(),
                    detail: "proof package identity validates under its declared schema version; signed workflow scope, receipt action bindings, and manifest structure were validated independently".to_string(),
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
        let bundled_checkpoint_prefix_covered =
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
            verifier_equivalent: false,
            steps: vec![
                MercuryVerificationStep {
                    name: "package_contract".to_string(),
                    detail: "proof package identity validates under its declared schema version; the unsigned export descriptor, signed workflow scope, receipt action bindings, and signed bundle-reference coverage were validated independently".to_string(),
                },
                MercuryVerificationStep {
                    name: "chio_bundle_integrity".to_string(),
                    detail: if bundled_checkpoint_prefix_covered {
                        "tool and child receipt self-signatures, checkpoint signatures, and exactly one verified packaged tool receipt for every leaf in the bundled checkpoint prefix passed; this bundled-prefix result does not establish the current source log tip or exclude a later uncheckpointed suffix".to_string()
                    } else {
                        "tool and child receipt self-signatures and checkpoint signatures passed; exactly one verified proof covers every selected packaged tool receipt; zero-proof checkpoint-prefix context is permitted, so source-population completeness and verifier equivalence were not established".to_string()
                    },
                },
                MercuryVerificationStep {
                    name: "kernel_authority".to_string(),
                    detail: "every tool receipt, child receipt, and checkpoint signer is present in the trusted Mercury kernel-key set".to_string(),
                },
                MercuryVerificationStep {
                    name: "portable_export_boundary".to_string(),
                    detail: "the export query and descriptor are content-addressed but are not signed by a trusted exporter, so portable verification does not claim source-population verifier equivalence".to_string(),
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
            verifier_equivalent: _requested_verifier_equivalent,
        } = args;
        proof_package.validate()?;
        let authoritative = authoritative_receipt(&proof_package)?;
        let disclosure = authoritative.metadata.disclosure.clone();
        let approval_state = authoritative.metadata.approval_state.clone();
        // Portable inquiry packages have no authenticated export descriptor or
        // source snapshot boundary, so a requested equivalence claim is always
        // downgraded.
        let verifier_equivalent = false;
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
        if self.verifier_equivalent {
            return Err(MercuryContractError::Validation(
                "portable inquiry cannot claim verifier equivalence without authenticated export provenance"
                    .to_string(),
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

fn derive_legacy_v1_proof_package_id(
    proof_package: &MercuryProofPackage,
) -> Result<String, MercuryContractError> {
    build_hash_id(
        "proof",
        &serde_json::json!({
            "createdAt": proof_package.created_at,
            "evidenceExportManifestHash": proof_package.evidence_export_manifest_hash,
            "workflowId": proof_package.workflow_id,
            "receiptIds": ordered_receipt_ids(proof_package),
        }),
    )
}

fn derive_proof_package_id_for_schema(
    proof_package: &MercuryProofPackage,
) -> Result<String, MercuryContractError> {
    match proof_package.schema.as_str() {
        MERCURY_PROOF_PACKAGE_SCHEMA_V1 => derive_legacy_v1_proof_package_id(proof_package),
        MERCURY_PROOF_PACKAGE_SCHEMA => derive_proof_package_id(proof_package),
        _ => Err(MercuryContractError::InvalidSchema {
            expected: MERCURY_PROOF_PACKAGE_SCHEMA,
            actual: proof_package.schema.clone(),
        }),
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EvidenceQueryCoverageScope {
    Invalid,
    Selected,
    UnfilteredAdminAll,
}

fn evidence_query_coverage_scope(query: &EvidenceExportQuery) -> EvidenceQueryCoverageScope {
    let EvidenceExportQuery {
        capability_id,
        agent_subject,
        since,
        until,
        tenant,
        read_boundary,
    } = query;
    if query.validate_read_boundary().is_err()
        || capability_id
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        || agent_subject
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        || since
            .zip(*until)
            .is_some_and(|(since, until)| since > until)
    {
        return EvidenceQueryCoverageScope::Invalid;
    }

    match read_boundary.as_ref() {
        Some(ReceiptReadBoundary::AdminAll)
            if capability_id.is_none()
                && agent_subject.is_none()
                && since.is_none()
                && until.is_none()
                && tenant.is_none() =>
        {
            EvidenceQueryCoverageScope::UnfilteredAdminAll
        }
        Some(ReceiptReadBoundary::AdminAll | ReceiptReadBoundary::TenantScoped { .. }) => {
            EvidenceQueryCoverageScope::Selected
        }
        None => EvidenceQueryCoverageScope::Invalid,
    }
}

fn derived_completeness_mode(bundle: &EvidenceExportBundle) -> &'static str {
    // These modes describe only the receipts and checkpoints in this bundle.
    // They do not authenticate the export query or prove the current log tip.
    if !bundle.uncheckpointed_receipts.is_empty()
        || bundle.tool_receipts.is_empty()
        || bundle.checkpoints.is_empty()
    {
        return COMPLETENESS_BEST_EFFORT;
    }
    let query_coverage_scope = evidence_query_coverage_scope(&bundle.query);
    if query_coverage_scope == EvidenceQueryCoverageScope::Invalid {
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
        let Some(covered_entry_count) = checkpoint
            .body
            .batch_end_seq
            .checked_sub(checkpoint.body.batch_start_seq)
            .and_then(|difference| difference.checked_add(1))
        else {
            return COMPLETENESS_BEST_EFFORT;
        };
        if usize::try_from(covered_entry_count).ok() != Some(checkpoint.body.tree_size) {
            return COMPLETENESS_BEST_EFFORT;
        }
        if checkpoints_by_seq
            .insert(checkpoint.body.checkpoint_seq, checkpoint)
            .is_some()
        {
            return COMPLETENESS_BEST_EFFORT;
        }
    }

    let mut proved_receipt_seqs = BTreeSet::new();
    let mut proved_receipt_seqs_by_checkpoint = checkpoints_by_seq
        .keys()
        .map(|checkpoint_seq| (*checkpoint_seq, BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
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
        let Some(checkpoint_receipt_seqs) =
            proved_receipt_seqs_by_checkpoint.get_mut(&proof.checkpoint_seq)
        else {
            return COMPLETENESS_BEST_EFFORT;
        };
        if !checkpoint_receipt_seqs.insert(proof.receipt_seq) {
            return COMPLETENESS_BEST_EFFORT;
        }
    }

    if proved_receipt_seqs != tool_receipt_seqs {
        return COMPLETENESS_BEST_EFFORT;
    }
    let every_checkpoint_leaf_is_packaged =
        checkpoints_by_seq
            .iter()
            .all(|(checkpoint_seq, checkpoint)| {
                proved_receipt_seqs_by_checkpoint
                    .get(checkpoint_seq)
                    .is_some_and(|checkpoint_receipt_seqs| {
                        checkpoint_receipt_seqs.len() == checkpoint.body.tree_size
                            && checkpoint_receipt_seqs.first().copied()
                                == Some(checkpoint.body.batch_start_seq)
                            && checkpoint_receipt_seqs.last().copied()
                                == Some(checkpoint.body.batch_end_seq)
                    })
            });

    match query_coverage_scope {
        EvidenceQueryCoverageScope::UnfilteredAdminAll if every_checkpoint_leaf_is_packaged => {
            COMPLETENESS_FULL_CHECKPOINT_COVERAGE
        }
        EvidenceQueryCoverageScope::Selected => COMPLETENESS_SELECTED_RECEIPT_COVERAGE,
        EvidenceQueryCoverageScope::Invalid | EvidenceQueryCoverageScope::UnfilteredAdminAll => {
            COMPLETENESS_BEST_EFFORT
        }
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
) -> Result<bool, MercuryContractError> {
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
            "trusted Mercury verification requires every packaged receipt to have exactly one checkpoint proof"
                .to_string(),
        ));
    }
    let derived_completeness = derived_completeness_mode(bundle);
    if publication_profile.completeness_mode != derived_completeness {
        return Err(MercuryContractError::Validation(
            "trusted Mercury verification requires the declared coverage mode to match re-derived bundled evidence coverage"
                .to_string(),
        ));
    }
    let bundled_checkpoint_prefix_covered = match derived_completeness {
        COMPLETENESS_FULL_CHECKPOINT_COVERAGE => true,
        COMPLETENESS_SELECTED_RECEIPT_COVERAGE => false,
        _ => {
            return Err(MercuryContractError::Validation(
                "trusted Mercury verification requires exact scoped selected-receipt proof coverage or unfiltered admin-all coverage of every leaf in the bundled checkpoint prefix; bundled-prefix coverage does not establish the current source log tip or exclude a later uncheckpointed suffix"
                    .to_string(),
            ));
        }
    };
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
    Ok(bundled_checkpoint_prefix_covered)
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
#[path = "proof_package/tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
