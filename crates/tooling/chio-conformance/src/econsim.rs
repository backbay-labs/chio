use std::collections::BTreeSet;

use chio_core::receipt::lineage::SignedExportEnvelope;
use chio_core::Keypair;
use serde::{Deserialize, Serialize};

pub const ECONSIM_SCENARIO_RESULT_SCHEMA: &str = "chio.econsim.scenario-result.v1";
pub const ECONSIM_QUALIFICATION_MATRIX_SCHEMA: &str = "chio.econsim.qualification-matrix.v1";

pub const ECONSIM_SCENARIO_CLASSES: [&str; 6] = [
    "collusion-bid-ring",
    "credit-exhaustion",
    "fee-structuring",
    "oracle-divergence",
    "settlement-dos",
    "sybil-pricing-ring",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EconsimDisposition {
    FailClosed,
    Breach,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EconsimFindingSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EconsimTargetStatus {
    Bound,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EconsimOutcome {
    Held,
    Finding,
    TargetMissing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EconsimScenarioResult {
    pub schema: String,
    pub scenario_id: String,
    pub scenario_class: String,
    pub seed: u64,
    pub corpus_manifest_digest: String,
    pub requirement_ids: Vec<String>,
    pub expected_disposition: EconsimDisposition,
    pub observed_disposition: Option<EconsimDisposition>,
    pub target_status: EconsimTargetStatus,
    pub outcome: EconsimOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_severity: Option<EconsimFindingSeverity>,
    pub assertion_scope: String,
    pub explicit_limits: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EconsimHarnessProvenance {
    pub git_commit: String,
    pub source_tree_state: String,
    pub source_tree_digest: String,
    pub executable_digest: String,
    pub cargo_lock_digest: String,
    pub enabled_features: Vec<String>,
    pub target_triple: String,
    pub rustc_version: String,
    pub cargo_version: String,
    pub command: Vec<String>,
    pub scenario_manifest_digest: String,
    pub corpus_manifest_digest: String,
    pub runner_key_id: String,
    pub qualification_scope: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EconsimQualificationMatrix {
    pub schema: String,
    pub profile_id: String,
    pub harness_provenance: EconsimHarnessProvenance,
    pub cases: Vec<EconsimScenarioResult>,
}

pub type SignedEconsimQualificationMatrix = SignedExportEnvelope<EconsimQualificationMatrix>;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EconsimValidationError {
    #[error("unsupported econsim schema: {0}")]
    UnsupportedSchema(String),
    #[error("econsim field must not be empty: {0}")]
    EmptyField(&'static str),
    #[error("econsim scenario seed must be non-zero")]
    ZeroSeed,
    #[error("unknown econsim scenario class: {0}")]
    UnknownClass(String),
    #[error("duplicate econsim scenario id: {0}")]
    DuplicateScenario(String),
    #[error("invalid econsim result: {0}")]
    InvalidResult(&'static str),
    #[error("econsim matrix is missing scenario class: {0}")]
    MissingClass(String),
    #[error("econsim matrix cannot be signed: {0}")]
    SigningBoundary(&'static str),
    #[error("econsim matrix signing failed: {0}")]
    Signing(String),
}

pub fn validate_econsim_scenario_result(
    result: &EconsimScenarioResult,
) -> Result<(), EconsimValidationError> {
    if result.schema != ECONSIM_SCENARIO_RESULT_SCHEMA {
        return Err(EconsimValidationError::UnsupportedSchema(
            result.schema.clone(),
        ));
    }
    for (value, field) in [
        (&result.scenario_id, "scenarioId"),
        (&result.scenario_class, "scenarioClass"),
        (&result.corpus_manifest_digest, "corpusManifestDigest"),
        (&result.assertion_scope, "assertionScope"),
    ] {
        if value.trim().is_empty() {
            return Err(EconsimValidationError::EmptyField(field));
        }
    }
    if !ECONSIM_SCENARIO_CLASSES.contains(&result.scenario_class.as_str()) {
        return Err(EconsimValidationError::UnknownClass(
            result.scenario_class.clone(),
        ));
    }
    if result.seed == 0 {
        return Err(EconsimValidationError::ZeroSeed);
    }
    if result.requirement_ids.is_empty() {
        return Err(EconsimValidationError::EmptyField("requirementIds"));
    }
    if result.explicit_limits.is_empty() {
        return Err(EconsimValidationError::EmptyField("explicitLimits"));
    }
    if result.expected_disposition != EconsimDisposition::FailClosed {
        return Err(EconsimValidationError::InvalidResult(
            "expected disposition must be fail-closed",
        ));
    }
    match result.outcome {
        EconsimOutcome::Held
            if result.target_status == EconsimTargetStatus::Bound
                && result.observed_disposition == Some(EconsimDisposition::FailClosed)
                && result.finding_severity.is_none() => {}
        EconsimOutcome::Finding
            if result.target_status == EconsimTargetStatus::Bound
                && result.observed_disposition == Some(EconsimDisposition::Breach)
                && result.finding_severity.is_some() => {}
        EconsimOutcome::TargetMissing
            if result.target_status == EconsimTargetStatus::Missing
                && result.observed_disposition.is_none()
                && result.finding_severity == Some(EconsimFindingSeverity::High) => {}
        _ => {
            return Err(EconsimValidationError::InvalidResult(
                "outcome, target, disposition, and severity disagree",
            ));
        }
    }
    Ok(())
}

pub fn validate_econsim_qualification_matrix(
    matrix: &EconsimQualificationMatrix,
) -> Result<(), EconsimValidationError> {
    if matrix.schema != ECONSIM_QUALIFICATION_MATRIX_SCHEMA {
        return Err(EconsimValidationError::UnsupportedSchema(
            matrix.schema.clone(),
        ));
    }
    if matrix.profile_id.trim().is_empty() {
        return Err(EconsimValidationError::EmptyField("profileId"));
    }
    if matrix.cases.is_empty() {
        return Err(EconsimValidationError::EmptyField("cases"));
    }
    validate_provenance(&matrix.harness_provenance)?;
    let mut ids = BTreeSet::new();
    let mut classes = BTreeSet::new();
    for case in &matrix.cases {
        validate_econsim_scenario_result(case)?;
        if !ids.insert(case.scenario_id.as_str()) {
            return Err(EconsimValidationError::DuplicateScenario(
                case.scenario_id.clone(),
            ));
        }
        classes.insert(case.scenario_class.as_str());
    }
    for class in ECONSIM_SCENARIO_CLASSES {
        if !classes.contains(class) {
            return Err(EconsimValidationError::MissingClass(class.to_owned()));
        }
    }
    Ok(())
}

pub fn sign_econsim_qualification_matrix(
    matrix: EconsimQualificationMatrix,
    signer: &Keypair,
) -> Result<SignedEconsimQualificationMatrix, EconsimValidationError> {
    validate_econsim_qualification_matrix(&matrix)?;
    if matrix.cases.iter().any(|case| {
        case.outcome == EconsimOutcome::TargetMissing
            || case.finding_severity >= Some(EconsimFindingSeverity::High)
    }) {
        return Err(EconsimValidationError::SigningBoundary(
            "missing targets and unresolved high or critical findings are not signable",
        ));
    }
    SignedExportEnvelope::sign(matrix, signer)
        .map_err(|error| EconsimValidationError::Signing(error.to_string()))
}

fn validate_provenance(
    provenance: &EconsimHarnessProvenance,
) -> Result<(), EconsimValidationError> {
    for (value, field) in [
        (&provenance.git_commit, "harnessProvenance.gitCommit"),
        (
            &provenance.source_tree_state,
            "harnessProvenance.sourceTreeState",
        ),
        (
            &provenance.source_tree_digest,
            "harnessProvenance.sourceTreeDigest",
        ),
        (
            &provenance.executable_digest,
            "harnessProvenance.executableDigest",
        ),
        (
            &provenance.cargo_lock_digest,
            "harnessProvenance.cargoLockDigest",
        ),
        (&provenance.target_triple, "harnessProvenance.targetTriple"),
        (&provenance.rustc_version, "harnessProvenance.rustcVersion"),
        (&provenance.cargo_version, "harnessProvenance.cargoVersion"),
        (
            &provenance.scenario_manifest_digest,
            "harnessProvenance.scenarioManifestDigest",
        ),
        (
            &provenance.corpus_manifest_digest,
            "harnessProvenance.corpusManifestDigest",
        ),
        (&provenance.runner_key_id, "harnessProvenance.runnerKeyId"),
        (
            &provenance.qualification_scope,
            "harnessProvenance.qualificationScope",
        ),
    ] {
        if value.trim().is_empty() {
            return Err(EconsimValidationError::EmptyField(field));
        }
    }
    if provenance.command.is_empty() {
        return Err(EconsimValidationError::EmptyField(
            "harnessProvenance.command",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(class: &str) -> EconsimScenarioResult {
        EconsimScenarioResult {
            schema: ECONSIM_SCENARIO_RESULT_SCHEMA.to_owned(),
            scenario_id: format!("{class}-seed-7"),
            scenario_class: class.to_owned(),
            seed: 7,
            corpus_manifest_digest: "a".repeat(64),
            requirement_ids: vec!["AE-TEST".to_owned()],
            expected_disposition: EconsimDisposition::FailClosed,
            observed_disposition: Some(EconsimDisposition::FailClosed),
            target_status: EconsimTargetStatus::Bound,
            outcome: EconsimOutcome::Held,
            finding_severity: None,
            assertion_scope: "the named production validator rejected the corpus".to_owned(),
            explicit_limits: vec!["internal qualification only".to_owned()],
        }
    }

    fn provenance() -> EconsimHarnessProvenance {
        EconsimHarnessProvenance {
            git_commit: "abc".to_owned(),
            source_tree_state: "clean".to_owned(),
            source_tree_digest: "b".repeat(64),
            executable_digest: "c".repeat(64),
            cargo_lock_digest: "d".repeat(64),
            enabled_features: Vec::new(),
            target_triple: "test-target".to_owned(),
            rustc_version: "rustc test".to_owned(),
            cargo_version: "cargo test".to_owned(),
            command: vec!["chio-econsim-runner".to_owned()],
            scenario_manifest_digest: "e".repeat(64),
            corpus_manifest_digest: "a".repeat(64),
            runner_key_id: "runner-test".to_owned(),
            qualification_scope: "internal qualification only".to_owned(),
        }
    }

    fn matrix() -> EconsimQualificationMatrix {
        EconsimQualificationMatrix {
            schema: ECONSIM_QUALIFICATION_MATRIX_SCHEMA.to_owned(),
            profile_id: "econsim-v1".to_owned(),
            harness_provenance: provenance(),
            cases: ECONSIM_SCENARIO_CLASSES.into_iter().map(held).collect(),
        }
    }

    #[test]
    fn complete_held_matrix_signs_and_verifies() {
        let signed = sign_econsim_qualification_matrix(matrix(), &Keypair::from_seed(&[7; 32]))
            .expect("complete econsim matrix signs");
        assert!(signed.verify_signature().expect("signature verifies"));
    }

    #[test]
    fn high_finding_and_missing_target_do_not_cross_signing_boundary() {
        for (outcome, target, observed) in [
            (
                EconsimOutcome::Finding,
                EconsimTargetStatus::Bound,
                Some(EconsimDisposition::Breach),
            ),
            (
                EconsimOutcome::TargetMissing,
                EconsimTargetStatus::Missing,
                None,
            ),
        ] {
            let mut candidate = matrix();
            candidate.cases[0].outcome = outcome;
            candidate.cases[0].target_status = target;
            candidate.cases[0].observed_disposition = observed;
            candidate.cases[0].finding_severity = Some(EconsimFindingSeverity::High);
            assert!(matches!(
                sign_econsim_qualification_matrix(candidate, &Keypair::from_seed(&[7; 32])),
                Err(EconsimValidationError::SigningBoundary(_))
            ));
        }
    }

    #[test]
    fn short_unknown_and_cross_field_invalid_matrices_reject() {
        let mut short = matrix();
        short.cases.pop();
        assert!(matches!(
            validate_econsim_qualification_matrix(&short),
            Err(EconsimValidationError::MissingClass(_))
        ));

        let mut unknown = held("sybil-pricing-ring");
        unknown.scenario_class = "unknown".to_owned();
        assert!(matches!(
            validate_econsim_scenario_result(&unknown),
            Err(EconsimValidationError::UnknownClass(_))
        ));

        let mut invalid = held("sybil-pricing-ring");
        invalid.finding_severity = Some(EconsimFindingSeverity::Low);
        assert_eq!(
            validate_econsim_scenario_result(&invalid),
            Err(EconsimValidationError::InvalidResult(
                "outcome, target, disposition, and severity disagree"
            ))
        );
    }
}
