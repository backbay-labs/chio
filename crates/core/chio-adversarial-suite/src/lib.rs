//! Curated adversarial case metadata for Chio trust-boundary tests.
//!
//! This crate is the shared loader for malicious-but-well-formed cases.
//! Concrete vectors live under `cases/`; the crate fixes the envelope and
//! validation rules.

#![forbid(unsafe_code)]

use std::{fs, path::Path};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod manifest;
pub use manifest::{Manifest, ManifestEntry, MANIFEST_PRODUCER, MANIFEST_SCHEMA_VERSION};

/// Schema version accepted by this crate.
pub const CASE_SCHEMA_VERSION: u32 = 1;

/// Embedded JSON schema for on-disk adversarial case files.
pub const CASE_SCHEMA_JSON: &str = include_str!("../schema/case.schema.json");

/// Supported adversarial classes.
pub const ATTACK_CLASSES: &[AttackClass] = &[
    AttackClass::ClockRewound,
    AttackClass::FutureDated,
    AttackClass::ReplayedNonce,
    AttackClass::PartialSignature,
    AttackClass::ScopeSuperset,
    AttackClass::RevocationRollback,
    AttackClass::AnchorGrafted,
    AttackClass::SigstoreBundlePayloadMismatch,
    AttackClass::AuthorityBindingMutation,
];

/// One statically bundled adversarial case file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BundledCase {
    /// Repository-relative path to the case JSON.
    pub path: &'static str,
    /// Embedded JSON payload.
    pub contents: &'static str,
}

/// Case files embedded into the crate for downstream test harnesses.
pub const BUNDLED_CASES: &[BundledCase] = &[
    BundledCase {
        path: "cases/clock_rewound/clock-rewound-001.json",
        contents: include_str!("../cases/clock_rewound/clock-rewound-001.json"),
    },
    BundledCase {
        path: "cases/clock_rewound/clock-rewound-002.json",
        contents: include_str!("../cases/clock_rewound/clock-rewound-002.json"),
    },
    BundledCase {
        path: "cases/clock_rewound/clock-rewound-003.json",
        contents: include_str!("../cases/clock_rewound/clock-rewound-003.json"),
    },
    BundledCase {
        path: "cases/clock_rewound/clock-rewound-004.json",
        contents: include_str!("../cases/clock_rewound/clock-rewound-004.json"),
    },
    BundledCase {
        path: "cases/clock_rewound/clock-rewound-005.json",
        contents: include_str!("../cases/clock_rewound/clock-rewound-005.json"),
    },
    BundledCase {
        path: "cases/future_dated/future-dated-001.json",
        contents: include_str!("../cases/future_dated/future-dated-001.json"),
    },
    BundledCase {
        path: "cases/future_dated/future-dated-002.json",
        contents: include_str!("../cases/future_dated/future-dated-002.json"),
    },
    BundledCase {
        path: "cases/future_dated/future-dated-003.json",
        contents: include_str!("../cases/future_dated/future-dated-003.json"),
    },
    BundledCase {
        path: "cases/future_dated/future-dated-004.json",
        contents: include_str!("../cases/future_dated/future-dated-004.json"),
    },
    BundledCase {
        path: "cases/future_dated/future-dated-005.json",
        contents: include_str!("../cases/future_dated/future-dated-005.json"),
    },
    BundledCase {
        path: "cases/replayed_nonce/replayed-nonce-001.json",
        contents: include_str!("../cases/replayed_nonce/replayed-nonce-001.json"),
    },
    BundledCase {
        path: "cases/replayed_nonce/replayed-nonce-002.json",
        contents: include_str!("../cases/replayed_nonce/replayed-nonce-002.json"),
    },
    BundledCase {
        path: "cases/replayed_nonce/replayed-nonce-003.json",
        contents: include_str!("../cases/replayed_nonce/replayed-nonce-003.json"),
    },
    BundledCase {
        path: "cases/replayed_nonce/replayed-nonce-004.json",
        contents: include_str!("../cases/replayed_nonce/replayed-nonce-004.json"),
    },
    BundledCase {
        path: "cases/replayed_nonce/replayed-nonce-005.json",
        contents: include_str!("../cases/replayed_nonce/replayed-nonce-005.json"),
    },
    BundledCase {
        path: "cases/partial_signature/partial-signature-001.json",
        contents: include_str!("../cases/partial_signature/partial-signature-001.json"),
    },
    BundledCase {
        path: "cases/partial_signature/partial-signature-002.json",
        contents: include_str!("../cases/partial_signature/partial-signature-002.json"),
    },
    BundledCase {
        path: "cases/partial_signature/partial-signature-003.json",
        contents: include_str!("../cases/partial_signature/partial-signature-003.json"),
    },
    BundledCase {
        path: "cases/partial_signature/partial-signature-004.json",
        contents: include_str!("../cases/partial_signature/partial-signature-004.json"),
    },
    BundledCase {
        path: "cases/partial_signature/partial-signature-005.json",
        contents: include_str!("../cases/partial_signature/partial-signature-005.json"),
    },
    BundledCase {
        path: "cases/scope_superset/scope-superset-001.json",
        contents: include_str!("../cases/scope_superset/scope-superset-001.json"),
    },
    BundledCase {
        path: "cases/scope_superset/scope-superset-002.json",
        contents: include_str!("../cases/scope_superset/scope-superset-002.json"),
    },
    BundledCase {
        path: "cases/scope_superset/scope-superset-003.json",
        contents: include_str!("../cases/scope_superset/scope-superset-003.json"),
    },
    BundledCase {
        path: "cases/scope_superset/scope-superset-004.json",
        contents: include_str!("../cases/scope_superset/scope-superset-004.json"),
    },
    BundledCase {
        path: "cases/scope_superset/scope-superset-005.json",
        contents: include_str!("../cases/scope_superset/scope-superset-005.json"),
    },
    BundledCase {
        path: "cases/revocation_rollback/revocation-rollback-001.json",
        contents: include_str!("../cases/revocation_rollback/revocation-rollback-001.json"),
    },
    BundledCase {
        path: "cases/revocation_rollback/revocation-rollback-002.json",
        contents: include_str!("../cases/revocation_rollback/revocation-rollback-002.json"),
    },
    BundledCase {
        path: "cases/revocation_rollback/revocation-rollback-003.json",
        contents: include_str!("../cases/revocation_rollback/revocation-rollback-003.json"),
    },
    BundledCase {
        path: "cases/revocation_rollback/revocation-rollback-004.json",
        contents: include_str!("../cases/revocation_rollback/revocation-rollback-004.json"),
    },
    BundledCase {
        path: "cases/revocation_rollback/revocation-rollback-005.json",
        contents: include_str!("../cases/revocation_rollback/revocation-rollback-005.json"),
    },
    BundledCase {
        path: "cases/anchor_grafted/anchor-grafted-001.json",
        contents: include_str!("../cases/anchor_grafted/anchor-grafted-001.json"),
    },
    BundledCase {
        path: "cases/anchor_grafted/anchor-grafted-002.json",
        contents: include_str!("../cases/anchor_grafted/anchor-grafted-002.json"),
    },
    BundledCase {
        path: "cases/anchor_grafted/anchor-grafted-003.json",
        contents: include_str!("../cases/anchor_grafted/anchor-grafted-003.json"),
    },
    BundledCase {
        path: "cases/anchor_grafted/anchor-grafted-004.json",
        contents: include_str!("../cases/anchor_grafted/anchor-grafted-004.json"),
    },
    BundledCase {
        path: "cases/anchor_grafted/anchor-grafted-005.json",
        contents: include_str!("../cases/anchor_grafted/anchor-grafted-005.json"),
    },
    BundledCase {
        path: "cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-001.json",
        contents: include_str!(
            "../cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-001.json"
        ),
    },
    BundledCase {
        path: "cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-002.json",
        contents: include_str!(
            "../cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-002.json"
        ),
    },
    BundledCase {
        path: "cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-003.json",
        contents: include_str!(
            "../cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-003.json"
        ),
    },
    BundledCase {
        path: "cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-004.json",
        contents: include_str!(
            "../cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-004.json"
        ),
    },
    BundledCase {
        path: "cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-005.json",
        contents: include_str!(
            "../cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-005.json"
        ),
    },
    BundledCase {
        path: "cases/authority_binding_mutation/aggregate-root-binding-mutations-001.json",
        contents: include_str!(
            "../cases/authority_binding_mutation/aggregate-root-binding-mutations-001.json"
        ),
    },
    BundledCase {
        path: "cases/authority_binding_mutation/threshold-proposal-mutations-001.json",
        contents: include_str!(
            "../cases/authority_binding_mutation/threshold-proposal-mutations-001.json"
        ),
    },
];

/// One malicious-but-well-formed case consumed by test harnesses.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub struct AdversarialCase {
    /// Version of the case envelope, currently `1`.
    pub schema_version: u32,
    /// Stable case identifier, usually the file stem or content hash.
    pub id: String,
    /// Attack class this case exercises.
    pub class: AttackClass,
    /// Expected verdict. Adversarial cases are deny-asserted.
    pub expected_verdict: ExpectedVerdict,
    /// Stable deny reason asserted by downstream harnesses.
    pub expected_reason: String,
    /// Threat-model ID this case is intended to cover.
    pub threat_id: String,
    /// Auto-promoted cases start pending and do not count as coverage.
    pub pending: bool,
    /// Case-specific payload. Vector files define per-class shapes.
    pub artifact: serde_json::Value,
    /// Optional operator notes for triage and provenance.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl AdversarialCase {
    /// Load and validate a case from bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CaseError> {
        let case: Self = serde_json::from_slice(bytes)?;
        case.validate()?;
        Ok(case)
    }

    /// Load and validate a case from disk.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, CaseError> {
        Self::from_slice(&fs::read(path)?)
    }

    /// Validate semantic constraints that JSON Schema cannot enforce alone.
    pub fn validate(&self) -> Result<(), CaseError> {
        if self.schema_version != CASE_SCHEMA_VERSION {
            return Err(CaseError::UnsupportedSchemaVersion(self.schema_version));
        }
        if self.id.trim().is_empty() {
            return Err(CaseError::EmptyField("id"));
        }
        if !is_valid_case_id(&self.id) {
            return Err(CaseError::InvalidCaseId(self.id.clone()));
        }
        if self.expected_reason.trim().is_empty() {
            return Err(CaseError::EmptyField("expected_reason"));
        }
        if !is_valid_expected_reason(&self.expected_reason) {
            return Err(CaseError::InvalidExpectedReason(
                self.expected_reason.clone(),
            ));
        }
        if self.threat_id.trim().is_empty() {
            return Err(CaseError::EmptyField("threat_id"));
        }
        if !is_valid_threat_id(&self.threat_id) {
            return Err(CaseError::InvalidThreatId(self.threat_id.clone()));
        }
        if self.notes.iter().any(|note| note.trim().is_empty()) {
            return Err(CaseError::EmptyField("notes"));
        }
        match self.artifact.as_object() {
            Some(object) if !object.is_empty() => {}
            _ => return Err(CaseError::InvalidArtifact),
        }
        Ok(())
    }

    /// Convert a validated case into a coverage-eligible case.
    ///
    /// Pending cases are accepted by the raw loader for triage, but this
    /// method gives coverage gates a fail-closed API that rejects them.
    pub fn into_coverage_case(self) -> Result<CoverageCase, CaseError> {
        self.validate()?;
        if self.pending {
            return Err(CaseError::PendingCase(self.id));
        }
        Ok(CoverageCase(self))
    }
}

/// A validated non-pending adversarial case that may count as threat coverage.
#[derive(Clone, Debug, PartialEq)]
pub struct CoverageCase(AdversarialCase);

impl CoverageCase {
    /// Borrow the underlying case.
    pub const fn as_case(&self) -> &AdversarialCase {
        &self.0
    }

    /// Return the underlying case.
    pub fn into_inner(self) -> AdversarialCase {
        self.0
    }
}

/// Load all statically bundled cases.
pub fn bundled_cases() -> Result<Vec<AdversarialCase>, CaseError> {
    BUNDLED_CASES
        .iter()
        .map(|case| AdversarialCase::from_slice(case.contents.as_bytes()))
        .collect()
}

/// Load all statically bundled non-pending cases.
pub fn bundled_coverage_cases() -> Result<Vec<CoverageCase>, CaseError> {
    bundled_cases()?
        .into_iter()
        .map(AdversarialCase::into_coverage_case)
        .collect()
}

/// Load statically bundled cases for one attack class.
pub fn bundled_cases_by_class(class: AttackClass) -> Result<Vec<AdversarialCase>, CaseError> {
    Ok(bundled_cases()?
        .into_iter()
        .filter(|case| case.class == class)
        .collect())
}

/// Adversarial attack classes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackClass {
    ClockRewound,
    FutureDated,
    ReplayedNonce,
    PartialSignature,
    ScopeSuperset,
    RevocationRollback,
    AnchorGrafted,
    SigstoreBundlePayloadMismatch,
    AuthorityBindingMutation,
}

impl AttackClass {
    /// Stable snake_case class identifier used in paths and JSON.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClockRewound => "clock_rewound",
            Self::FutureDated => "future_dated",
            Self::ReplayedNonce => "replayed_nonce",
            Self::PartialSignature => "partial_signature",
            Self::ScopeSuperset => "scope_superset",
            Self::RevocationRollback => "revocation_rollback",
            Self::AnchorGrafted => "anchor_grafted",
            Self::SigstoreBundlePayloadMismatch => "sigstore_bundle_payload_mismatch",
            Self::AuthorityBindingMutation => "authority_binding_mutation",
        }
    }
}

/// Verdict expected from a trust-boundary harness.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ExpectedVerdict {
    #[serde(rename = "DENY")]
    Deny,
}

/// Case load or validation failure.
#[derive(Debug, Error)]
pub enum CaseError {
    #[error("failed to read adversarial case")]
    Io(#[from] std::io::Error),
    #[error("failed to parse adversarial case JSON")]
    Json(#[from] serde_json::Error),
    #[error("unsupported adversarial case schema version {0}")]
    UnsupportedSchemaVersion(u32),
    #[error("adversarial case field {0} must not be empty")]
    EmptyField(&'static str),
    #[error("adversarial case id {0} is not schema-compliant")]
    InvalidCaseId(String),
    #[error("adversarial case expected_reason {0} is not schema-compliant")]
    InvalidExpectedReason(String),
    #[error("adversarial case threat_id {0} is not schema-compliant")]
    InvalidThreatId(String),
    #[error("adversarial case artifact must be a non-empty object")]
    InvalidArtifact,
    #[error("pending adversarial case {0} is not coverage-eligible")]
    PendingCase(String),
    #[error("manifest drift: case id '{case_id}' does not match bundled path '{path}'")]
    ManifestDrift { case_id: String, path: String },
}

fn is_valid_case_id(id: &str) -> bool {
    let mut chars = id.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_lowercase() || first.is_ascii_digit())
        && chars.all(|ch| {
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '_' | '-')
        })
}

fn is_valid_expected_reason(reason: &str) -> bool {
    let mut chars = reason.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
}

fn is_valid_threat_id(threat_id: &str) -> bool {
    let mut chars = threat_id.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn attack_class_names_are_stable() {
        let names = ATTACK_CLASSES
            .iter()
            .map(|class| class.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "clock_rewound",
                "future_dated",
                "replayed_nonce",
                "partial_signature",
                "scope_superset",
                "revocation_rollback",
                "anchor_grafted",
                "sigstore_bundle_payload_mismatch",
                "authority_binding_mutation"
            ]
        );
    }

    #[test]
    fn parses_and_validates_case_envelope() -> Result<(), CaseError> {
        let case = AdversarialCase::from_slice(
            br#"{
              "schema_version": 1,
              "id": "clock-rewound-smoke",
              "class": "clock_rewound",
              "expected_verdict": "DENY",
              "expected_reason": "capability_not_yet_valid",
              "threat_id": "capability_token_theft",
              "pending": false,
              "artifact": { "receipt": { "issued_at": "1970-01-01T00:00:00Z" } }
            }"#,
        )?;

        assert_eq!(case.class, AttackClass::ClockRewound);
        assert_eq!(case.expected_verdict, ExpectedVerdict::Deny);
        assert!(!case.pending);
        assert!(case.into_coverage_case().is_ok());
        Ok(())
    }

    #[test]
    fn rejects_empty_object_artifact() {
        let err = AdversarialCase::from_slice(
            br#"{
              "schema_version": 1,
              "id": "empty-artifact",
              "class": "future_dated",
              "expected_verdict": "DENY",
              "expected_reason": "capability_not_yet_valid",
              "threat_id": "capability_token_theft",
              "pending": false,
              "artifact": {}
            }"#,
        )
        .err();

        assert!(matches!(err, Some(CaseError::InvalidArtifact)));
    }

    #[test]
    fn rejects_non_object_artifact() {
        let err = AdversarialCase::from_slice(
            br#"{
              "schema_version": 1,
              "id": "scalar-artifact",
              "class": "future_dated",
              "expected_verdict": "DENY",
              "expected_reason": "capability_not_yet_valid",
              "threat_id": "capability_token_theft",
              "pending": false,
              "artifact": "not-an-object"
            }"#,
        )
        .err();

        assert!(matches!(err, Some(CaseError::InvalidArtifact)));
    }

    #[test]
    fn rejects_unknown_fields() {
        let err = AdversarialCase::from_slice(
            br#"{
              "schema_version": 1,
              "id": "extra-field",
              "class": "replayed_nonce",
              "expected_verdict": "DENY",
              "expected_reason": "nonce_replayed",
              "threat_id": "native_channel_replay",
              "pending": false,
              "artifact": { "nonce": "n-1" },
              "unexpected": true
            }"#,
        )
        .err();

        assert!(matches!(err, Some(CaseError::Json(_))));
    }

    #[test]
    fn rejects_unsupported_schema_versions() {
        let err = AdversarialCase::from_slice(
            br#"{
              "schema_version": 2,
              "id": "future-version",
              "class": "replayed_nonce",
              "expected_verdict": "DENY",
              "expected_reason": "nonce_replayed",
              "threat_id": "native_channel_replay",
              "pending": false,
              "artifact": { "nonce": "n-1" }
            }"#,
        )
        .err();

        assert!(matches!(err, Some(CaseError::UnsupportedSchemaVersion(2))));
    }

    #[test]
    fn rejects_non_deny_verdicts() {
        let err = AdversarialCase::from_slice(
            br#"{
              "schema_version": 1,
              "id": "allow-verdict",
              "class": "replayed_nonce",
              "expected_verdict": "ALLOW",
              "expected_reason": "nonce_replayed",
              "threat_id": "native_channel_replay",
              "pending": false,
              "artifact": { "nonce": "n-1" }
            }"#,
        )
        .err();

        assert!(matches!(err, Some(CaseError::Json(_))));
    }

    #[test]
    fn rejects_malformed_ids() {
        let err = AdversarialCase::from_slice(
            br#"{
              "schema_version": 1,
              "id": "Bad ID",
              "class": "scope_superset",
              "expected_verdict": "DENY",
              "expected_reason": "scope_superset",
              "threat_id": "delegation_chain_abuse",
              "pending": false,
              "artifact": { "scope": "*" }
            }"#,
        )
        .err();

        assert!(matches!(err, Some(CaseError::InvalidCaseId(_))));
    }

    #[test]
    fn rejects_malformed_threat_ids() {
        let err = AdversarialCase::from_slice(
            br#"{
              "schema_version": 1,
              "id": "bad-threat-id",
              "class": "scope_superset",
              "expected_verdict": "DENY",
              "expected_reason": "scope_superset",
              "threat_id": "Bad Threat",
              "pending": false,
              "artifact": { "scope": "*" }
            }"#,
        )
        .err();

        assert!(matches!(err, Some(CaseError::InvalidThreatId(_))));
    }

    #[test]
    fn rejects_padded_expected_reason() {
        let err = AdversarialCase::from_slice(
            br#"{
              "schema_version": 1,
              "id": "bad-reason",
              "class": "scope_superset",
              "expected_verdict": "DENY",
              "expected_reason": " scope_superset ",
              "threat_id": "delegation_chain_abuse",
              "pending": false,
              "artifact": { "scope": "*" }
            }"#,
        )
        .err();

        assert!(matches!(err, Some(CaseError::InvalidExpectedReason(_))));
    }

    #[test]
    fn rejects_control_character_expected_reason() {
        let err = AdversarialCase::from_slice(
            br#"{
              "schema_version": 1,
              "id": "bad-reason-control",
              "class": "scope_superset",
              "expected_verdict": "DENY",
              "expected_reason": "scope_superset\nadmin",
              "threat_id": "delegation_chain_abuse",
              "pending": false,
              "artifact": { "scope": "*" }
            }"#,
        )
        .err();

        assert!(matches!(err, Some(CaseError::InvalidExpectedReason(_))));
    }

    #[test]
    fn rejects_empty_notes() {
        let err = AdversarialCase::from_slice(
            br#"{
              "schema_version": 1,
              "id": "empty-note",
              "class": "scope_superset",
              "expected_verdict": "DENY",
              "expected_reason": "scope_superset",
              "threat_id": "delegation_chain_abuse",
              "pending": false,
              "artifact": { "scope": "*" },
              "notes": [""]
            }"#,
        )
        .err();

        assert!(matches!(err, Some(CaseError::EmptyField("notes"))));
    }

    #[test]
    fn pending_cases_are_not_coverage_eligible() -> Result<(), CaseError> {
        let case = AdversarialCase::from_slice(
            br#"{
              "schema_version": 1,
              "id": "pending-crash",
              "class": "anchor_grafted",
              "expected_verdict": "DENY",
              "expected_reason": "anchor_grafted",
              "threat_id": "delegation_chain_abuse",
              "pending": true,
              "artifact": { "anchor": "pending" }
            }"#,
        )?;

        assert!(matches!(
            case.into_coverage_case(),
            Err(CaseError::PendingCase(id)) if id == "pending-crash"
        ));
        Ok(())
    }

    #[test]
    fn bundled_cases_are_valid_and_coverage_eligible() -> Result<(), CaseError> {
        let cases = bundled_cases()?;
        assert_eq!(cases.len(), BUNDLED_CASES.len());
        for case in cases {
            assert_eq!(case.expected_verdict, ExpectedVerdict::Deny);
            assert!(!case.pending);
            assert!(!case.expected_reason.trim().is_empty());
            assert!(!case.threat_id.trim().is_empty());
            assert!(case
                .artifact
                .as_object()
                .is_some_and(|object| !object.is_empty()));
            case.into_coverage_case()?;
        }
        Ok(())
    }

    /// Every non-pending bundled case must cite a
    /// `threat_id` that exists in
    /// `spec/security/chio-threat-model.v1.json`. Vectors with
    /// `pending: true` are auto-promoted from libFuzzer crashes
    /// and are excepted from the citation gate until a human
    /// triages them and strips the flag.
    #[test]
    fn every_non_pending_case_cites_a_known_threat_id() -> Result<(), CaseError> {
        const THREAT_MODEL_JSON: &str =
            include_str!("../../../../spec/security/chio-threat-model.v1.json");
        let doc: serde_json::Value =
            serde_json::from_str(THREAT_MODEL_JSON).expect("threat-model JSON parses");
        let known: std::collections::BTreeSet<String> = doc
            .get("threats")
            .and_then(serde_json::Value::as_array)
            .map(|threats| {
                threats
                    .iter()
                    .filter_map(|t| t.get("id").and_then(serde_json::Value::as_str))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            !known.is_empty(),
            "threat-model JSON must enumerate at least one threat ID"
        );

        for case in bundled_cases()? {
            if case.pending {
                continue;
            }
            assert!(
                known.contains(&case.threat_id),
                "case {:?} cites threat_id {:?} which is not in chio-threat-model.v1.json",
                case.id,
                case.threat_id
            );
        }
        Ok(())
    }
}
