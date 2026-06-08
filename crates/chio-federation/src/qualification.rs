use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::error::FederationContractError;
use crate::receipt::lineage::SignedExportEnvelope;
use crate::validation::{ensure_non_empty, ensure_unique_strings};

pub const CHIO_FEDERATION_QUALIFICATION_MATRIX_SCHEMA: &str =
    "chio.federation-qualification-matrix.v1";

const FEDERATION_REQUIRED_REQUIREMENTS: [&str; 5] = [
    "TRUSTMAX-01",
    "TRUSTMAX-02",
    "TRUSTMAX-03",
    "TRUSTMAX-04",
    "TRUSTMAX-05",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationScenarioKind {
    HostilePublisher,
    ConflictingActivation,
    InsufficientQuorum,
    EclipseAttempt,
    ReputationSybil,
    GovernanceInterop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationQualificationOutcome {
    Pass,
    FailClosed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationQualificationCase {
    pub id: String,
    pub name: String,
    pub requirement_ids: Vec<String>,
    pub scenario: FederationScenarioKind,
    pub expected_outcome: FederationQualificationOutcome,
    pub observed_outcome: FederationQualificationOutcome,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationQualificationMatrix {
    pub schema: String,
    pub profile_id: String,
    pub exchange_ref: String,
    pub quorum_report_ref: String,
    pub reputation_clearing_ref: String,
    pub cases: Vec<FederationQualificationCase>,
}

pub type SignedFederationQualificationMatrix = SignedExportEnvelope<FederationQualificationMatrix>;

pub fn validate_federation_qualification_matrix(
    matrix: &FederationQualificationMatrix,
) -> Result<(), FederationContractError> {
    if matrix.schema != CHIO_FEDERATION_QUALIFICATION_MATRIX_SCHEMA {
        return Err(FederationContractError::UnsupportedSchema(
            matrix.schema.clone(),
        ));
    }
    ensure_non_empty(&matrix.profile_id, "federation_qualification.profile_id")?;
    ensure_non_empty(
        &matrix.exchange_ref,
        "federation_qualification.exchange_ref",
    )?;
    ensure_non_empty(
        &matrix.quorum_report_ref,
        "federation_qualification.quorum_report_ref",
    )?;
    ensure_non_empty(
        &matrix.reputation_clearing_ref,
        "federation_qualification.reputation_clearing_ref",
    )?;
    if matrix.cases.is_empty() {
        return Err(FederationContractError::MissingField(
            "federation_qualification.cases",
        ));
    }

    let mut case_ids = HashSet::new();
    let mut covered_requirements = HashSet::new();
    for case in &matrix.cases {
        ensure_non_empty(&case.id, "federation_qualification.cases.id")?;
        ensure_non_empty(&case.name, "federation_qualification.cases.name")?;
        ensure_non_empty(&case.notes, "federation_qualification.cases.notes")?;
        if case.requirement_ids.is_empty() {
            return Err(FederationContractError::InvalidQualificationCase(format!(
                "qualification case `{}` requires at least one requirement id",
                case.id
            )));
        }
        ensure_unique_strings(
            &case.requirement_ids,
            "federation_qualification.cases.requirement_ids",
        )?;
        if !case_ids.insert(case.id.as_str()) {
            return Err(FederationContractError::DuplicateValue(case.id.clone()));
        }
        for requirement in &case.requirement_ids {
            covered_requirements.insert(requirement.as_str());
        }
    }

    for requirement in FEDERATION_REQUIRED_REQUIREMENTS {
        if !covered_requirements.contains(requirement) {
            return Err(FederationContractError::InvalidQualificationCase(format!(
                "qualification matrix is missing coverage for {requirement}"
            )));
        }
    }

    Ok(())
}
