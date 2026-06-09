use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::error::Web3ContractError;
use crate::settlement::Web3SettlementLifecycleState;
use crate::validation::{ensure_non_empty, ensure_unique_strings};

pub const CHIO_WEB3_QUALIFICATION_MATRIX_SCHEMA: &str = "chio.web3-qualification-matrix.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Web3QualificationOutcome {
    Pass,
    FailClosed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3QualificationCase {
    pub id: String,
    pub name: String,
    pub requirement_ids: Vec<String>,
    pub lifecycle_state: Web3SettlementLifecycleState,
    pub expected_outcome: Web3QualificationOutcome,
    pub observed_outcome: Web3QualificationOutcome,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3QualificationMatrix {
    pub schema: String,
    pub trust_profile_id: String,
    pub contract_package_id: String,
    pub cases: Vec<Web3QualificationCase>,
}
pub fn validate_web3_qualification_matrix(
    matrix: &Web3QualificationMatrix,
) -> Result<(), Web3ContractError> {
    if matrix.schema != CHIO_WEB3_QUALIFICATION_MATRIX_SCHEMA {
        return Err(Web3ContractError::UnsupportedSchema(matrix.schema.clone()));
    }
    ensure_non_empty(
        &matrix.trust_profile_id,
        "web3_qualification_matrix.trust_profile_id",
    )?;
    ensure_non_empty(
        &matrix.contract_package_id,
        "web3_qualification_matrix.contract_package_id",
    )?;
    if matrix.cases.is_empty() {
        return Err(Web3ContractError::MissingField(
            "web3_qualification_matrix.cases",
        ));
    }
    let mut case_ids = HashSet::new();
    for case in &matrix.cases {
        ensure_non_empty(&case.id, "web3_qualification_matrix.case.id")?;
        ensure_non_empty(&case.name, "web3_qualification_matrix.case.name")?;
        ensure_non_empty(&case.notes, "web3_qualification_matrix.case.notes")?;
        if !case_ids.insert(case.id.as_str()) {
            return Err(Web3ContractError::DuplicateValue(case.id.clone()));
        }
        if case.requirement_ids.is_empty() {
            return Err(Web3ContractError::InvalidQualificationCase(format!(
                "case {} must cite at least one requirement id",
                case.id
            )));
        }
        ensure_unique_strings(
            &case.requirement_ids,
            "web3_qualification_matrix.case.requirement_ids",
        )?;
    }
    Ok(())
}
