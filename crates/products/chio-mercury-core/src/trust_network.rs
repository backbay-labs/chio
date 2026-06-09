use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::{
    assurance_suite::MercuryAssuranceReviewerPopulation, receipt_metadata::MercuryContractError,
};

pub const MERCURY_TRUST_NETWORK_PROFILE_SCHEMA: &str = "chio.mercury.trust_network_profile.v1";
pub const MERCURY_TRUST_NETWORK_PACKAGE_SCHEMA: &str = "chio.mercury.trust_network_package.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryTrustNetworkSponsorBoundary {
    CounterpartyReviewExchange,
}

impl MercuryTrustNetworkSponsorBoundary {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CounterpartyReviewExchange => "counterparty_review_exchange",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryTrustNetworkTrustAnchor {
    ChioCheckpointWitnessChain,
}

impl MercuryTrustNetworkTrustAnchor {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChioCheckpointWitnessChain => "chio_checkpoint_witness_chain",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MercuryTrustNetworkInteropSurface {
    ProofInquiryBundleExchange,
}

impl MercuryTrustNetworkInteropSurface {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProofInquiryBundleExchange => "proof_inquiry_bundle_exchange",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MercuryTrustNetworkWitnessStep {
    CheckpointPublication,
    IndependentWitnessRecord,
    CounterpartyResolution,
}

impl MercuryTrustNetworkWitnessStep {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CheckpointPublication => "checkpoint_publication",
            Self::IndependentWitnessRecord => "independent_witness_record",
            Self::CounterpartyResolution => "counterparty_resolution",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryTrustNetworkProfile {
    pub schema: String,
    pub profile_id: String,
    pub workflow_id: String,
    pub sponsor_boundary: MercuryTrustNetworkSponsorBoundary,
    pub trust_anchor: MercuryTrustNetworkTrustAnchor,
    pub interop_surface: MercuryTrustNetworkInteropSurface,
    pub reviewer_population: MercuryAssuranceReviewerPopulation,
    pub witness_steps: Vec<MercuryTrustNetworkWitnessStep>,
    pub retained_artifact_policy: String,
    pub intended_use: String,
    pub fail_closed: bool,
}

impl MercuryTrustNetworkProfile {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_TRUST_NETWORK_PROFILE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_TRUST_NETWORK_PROFILE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("trust_network_profile.profile_id", &self.profile_id)?;
        ensure_non_empty("trust_network_profile.workflow_id", &self.workflow_id)?;
        ensure_non_empty(
            "trust_network_profile.retained_artifact_policy",
            &self.retained_artifact_policy,
        )?;
        ensure_non_empty("trust_network_profile.intended_use", &self.intended_use)?;
        ensure_unique_steps(&self.witness_steps)?;
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "trust_network_profile.fail_closed must remain true".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MercuryTrustNetworkArtifactKind {
    SharedProofPackage,
    SharedReviewPackage,
    SharedInquiryPackage,
    InquiryVerification,
    InteroperabilityManifest,
    WitnessRecord,
    TrustAnchorRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryTrustNetworkArtifact {
    pub artifact_kind: MercuryTrustNetworkArtifactKind,
    pub relative_path: String,
}

impl MercuryTrustNetworkArtifact {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        ensure_non_empty(
            "trust_network_package.artifacts[].relative_path",
            &self.relative_path,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MercuryTrustNetworkPackage {
    pub schema: String,
    pub package_id: String,
    pub workflow_id: String,
    pub same_workflow_boundary: String,
    pub sponsor_boundary: MercuryTrustNetworkSponsorBoundary,
    pub trust_anchor: MercuryTrustNetworkTrustAnchor,
    pub interop_surface: MercuryTrustNetworkInteropSurface,
    pub reviewer_population: MercuryAssuranceReviewerPopulation,
    pub sponsor_owner: String,
    pub support_owner: String,
    pub fail_closed: bool,
    pub profile_file: String,
    pub embedded_oem_package_file: String,
    pub embedded_partner_manifest_file: String,
    pub artifacts: Vec<MercuryTrustNetworkArtifact>,
}

impl MercuryTrustNetworkPackage {
    pub fn validate(&self) -> Result<(), MercuryContractError> {
        if self.schema != MERCURY_TRUST_NETWORK_PACKAGE_SCHEMA {
            return Err(MercuryContractError::InvalidSchema {
                expected: MERCURY_TRUST_NETWORK_PACKAGE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("trust_network_package.package_id", &self.package_id)?;
        ensure_non_empty("trust_network_package.workflow_id", &self.workflow_id)?;
        ensure_non_empty(
            "trust_network_package.same_workflow_boundary",
            &self.same_workflow_boundary,
        )?;
        ensure_non_empty("trust_network_package.sponsor_owner", &self.sponsor_owner)?;
        ensure_non_empty("trust_network_package.support_owner", &self.support_owner)?;
        ensure_non_empty("trust_network_package.profile_file", &self.profile_file)?;
        ensure_non_empty(
            "trust_network_package.embedded_oem_package_file",
            &self.embedded_oem_package_file,
        )?;
        ensure_non_empty(
            "trust_network_package.embedded_partner_manifest_file",
            &self.embedded_partner_manifest_file,
        )?;
        if !self.fail_closed {
            return Err(MercuryContractError::Validation(
                "trust_network_package.fail_closed must remain true".to_string(),
            ));
        }
        if self.artifacts.is_empty() {
            return Err(MercuryContractError::MissingField(
                "trust_network_package.artifacts",
            ));
        }

        let mut artifact_kinds = HashSet::new();
        for artifact in &self.artifacts {
            artifact.validate()?;
            if !artifact_kinds.insert(artifact.artifact_kind) {
                return Err(MercuryContractError::Validation(format!(
                    "trust_network_package.artifacts contains duplicate artifact kind {:?}",
                    artifact.artifact_kind
                )));
            }
        }
        Ok(())
    }
}

fn ensure_non_empty(field: &'static str, value: &str) -> Result<(), MercuryContractError> {
    if value.trim().is_empty() {
        Err(MercuryContractError::EmptyField(field))
    } else {
        Ok(())
    }
}

fn ensure_unique_steps(
    witness_steps: &[MercuryTrustNetworkWitnessStep],
) -> Result<(), MercuryContractError> {
    if witness_steps.is_empty() {
        return Err(MercuryContractError::MissingField(
            "trust_network_profile.witness_steps",
        ));
    }

    let mut seen = HashSet::new();
    for step in witness_steps {
        if !seen.insert(*step) {
            return Err(MercuryContractError::Validation(format!(
                "trust_network_profile.witness_steps contains duplicate value {:?}",
                step
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn trust_network_profile_validates() {
        let profile = MercuryTrustNetworkProfile {
            schema: MERCURY_TRUST_NETWORK_PROFILE_SCHEMA.to_string(),
            profile_id: "trust-network-counterparty-review-2026-04-03".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            sponsor_boundary: MercuryTrustNetworkSponsorBoundary::CounterpartyReviewExchange,
            trust_anchor: MercuryTrustNetworkTrustAnchor::ChioCheckpointWitnessChain,
            interop_surface: MercuryTrustNetworkInteropSurface::ProofInquiryBundleExchange,
            reviewer_population: MercuryAssuranceReviewerPopulation::CounterpartyReview,
            witness_steps: vec![
                MercuryTrustNetworkWitnessStep::CheckpointPublication,
                MercuryTrustNetworkWitnessStep::IndependentWitnessRecord,
                MercuryTrustNetworkWitnessStep::CounterpartyResolution,
            ],
            retained_artifact_policy:
                "retain-shared-proof-and-counterparty-review-exchange-artifacts".to_string(),
            intended_use: "Share one bounded proof and inquiry bundle for counterparty review."
                .to_string(),
            fail_closed: true,
        };
        profile.validate().expect("trust network profile");
    }

    #[test]
    fn trust_network_package_rejects_duplicate_artifact_kinds() {
        let package = MercuryTrustNetworkPackage {
            schema: MERCURY_TRUST_NETWORK_PACKAGE_SCHEMA.to_string(),
            package_id: "trust-network-counterparty-review-2026-04-03".to_string(),
            workflow_id: "workflow-release-control".to_string(),
            same_workflow_boundary: "Controlled release workflow.".to_string(),
            sponsor_boundary: MercuryTrustNetworkSponsorBoundary::CounterpartyReviewExchange,
            trust_anchor: MercuryTrustNetworkTrustAnchor::ChioCheckpointWitnessChain,
            interop_surface: MercuryTrustNetworkInteropSurface::ProofInquiryBundleExchange,
            reviewer_population: MercuryAssuranceReviewerPopulation::CounterpartyReview,
            sponsor_owner: "counterparty-review-network-sponsor".to_string(),
            support_owner: "mercury-trust-network-ops".to_string(),
            fail_closed: true,
            profile_file: "trust-network-profile.json".to_string(),
            embedded_oem_package_file: "embedded-oem/embedded-oem-package.json".to_string(),
            embedded_partner_manifest_file: "embedded-oem/partner-sdk-manifest.json".to_string(),
            artifacts: vec![
                MercuryTrustNetworkArtifact {
                    artifact_kind: MercuryTrustNetworkArtifactKind::SharedInquiryPackage,
                    relative_path: "trust-network-share/inquiry-package.json".to_string(),
                },
                MercuryTrustNetworkArtifact {
                    artifact_kind: MercuryTrustNetworkArtifactKind::SharedInquiryPackage,
                    relative_path: "trust-network-share/inquiry-package-copy.json".to_string(),
                },
            ],
        };
        let error = package.validate().expect_err("duplicate artifact kind");
        assert!(
            error.to_string().contains("duplicate artifact kind"),
            "{error}"
        );
    }
}
