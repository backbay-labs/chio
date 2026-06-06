use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::runtime_attestation::{AttestationVerifierFamily, RuntimeAttestationTrustMaterial};

use super::runtime_attestation::{RuntimeAssuranceTier, RuntimeAttestationEvidence};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationTrustPolicy {
    #[serde(default)]
    pub rules: Vec<AttestationTrustRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationTrustRule {
    pub name: String,
    pub schema: String,
    pub verifier: String,
    pub effective_tier: RuntimeAssuranceTier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_family: Option<AttestationVerifierFamily>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_evidence_age_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_attestation_types: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub required_assertions: BTreeMap<String, String>,
}

impl AttestationTrustRule {
    pub(crate) fn matches(
        &self,
        attestation: &RuntimeAttestationEvidence,
        trust_material: &RuntimeAttestationTrustMaterial,
    ) -> bool {
        self.schema == attestation.schema
            && canonicalize_attestation_verifier(&self.verifier)
                == canonicalize_attestation_verifier(&attestation.verifier)
            && self
                .verifier_family
                .is_none_or(|family| family == trust_material.verifier_family)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedRuntimeAssurance {
    pub raw_tier: RuntimeAssuranceTier,
    pub effective_tier: RuntimeAssuranceTier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
}

#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationTrustError {
    #[cfg_attr(
        feature = "std",
        error("runtime attestation workload identity is invalid: {0}")
    )]
    InvalidWorkloadIdentity(String),

    #[cfg_attr(
        feature = "std",
        error(
            "runtime attestation evidence is stale at {now} (issued_at={issued_at}, expires_at={expires_at})"
        )
    )]
    StaleEvidence {
        now: u64,
        issued_at: u64,
        expires_at: u64,
    },

    #[cfg_attr(
        feature = "std",
        error(
            "attestation trust rule `{rule}` rejected evidence older than {max_age_seconds}s (actual age {actual_age_seconds}s)"
        )
    )]
    EvidenceTooOld {
        rule: String,
        max_age_seconds: u64,
        actual_age_seconds: u64,
    },

    #[cfg_attr(
        feature = "std",
        error("attestation trust rule `{rule}` requires an attestationType claim")
    )]
    MissingAttestationType { rule: String },

    #[cfg_attr(
        feature = "std",
        error("attestation trust rule `{rule}` rejected attestation type `{actual}`")
    )]
    DisallowedAttestationType { rule: String, actual: String },

    #[cfg_attr(
        feature = "std",
        error(
            "runtime attestation schema `{schema}` is not supported by the appraisal-aware trust boundary"
        )
    )]
    UnsupportedEvidence { schema: String },

    #[cfg_attr(
        feature = "std",
        error("attestation trust rule `{rule}` requires normalized assertion `{assertion}`")
    )]
    MissingAssertion { rule: String, assertion: String },

    #[cfg_attr(
        feature = "std",
        error(
            "attestation trust rule `{rule}` rejected normalized assertion `{assertion}`: expected `{expected}`, got `{actual}`"
        )
    )]
    AssertionMismatch {
        rule: String,
        assertion: String,
        expected: String,
        actual: String,
    },

    #[cfg_attr(
        feature = "std",
        error(
            "runtime attestation evidence from verifier `{verifier}` with schema `{schema}` did not match any trusted verifier rule"
        )
    )]
    UntrustedEvidence { verifier: String, schema: String },
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for AttestationTrustError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidWorkloadIdentity(v) => {
                write!(f, "runtime attestation workload identity is invalid: {v}")
            }
            Self::StaleEvidence {
                now,
                issued_at,
                expires_at,
            } => write!(
                f,
                "runtime attestation evidence is stale at {now} (issued_at={issued_at}, expires_at={expires_at})"
            ),
            Self::EvidenceTooOld {
                rule,
                max_age_seconds,
                actual_age_seconds,
            } => write!(
                f,
                "attestation trust rule `{rule}` rejected evidence older than {max_age_seconds}s (actual age {actual_age_seconds}s)"
            ),
            Self::MissingAttestationType { rule } => write!(
                f,
                "attestation trust rule `{rule}` requires an attestationType claim"
            ),
            Self::DisallowedAttestationType { rule, actual } => write!(
                f,
                "attestation trust rule `{rule}` rejected attestation type `{actual}`"
            ),
            Self::UnsupportedEvidence { schema } => write!(
                f,
                "runtime attestation schema `{schema}` is not supported by the appraisal-aware trust boundary"
            ),
            Self::MissingAssertion { rule, assertion } => write!(
                f,
                "attestation trust rule `{rule}` requires normalized assertion `{assertion}`"
            ),
            Self::AssertionMismatch {
                rule,
                assertion,
                expected,
                actual,
            } => write!(
                f,
                "attestation trust rule `{rule}` rejected normalized assertion `{assertion}`: expected `{expected}`, got `{actual}`"
            ),
            Self::UntrustedEvidence { verifier, schema } => write!(
                f,
                "runtime attestation evidence from verifier `{verifier}` with schema `{schema}` did not match any trusted verifier rule"
            ),
        }
    }
}

#[cfg(not(feature = "std"))]
impl core::error::Error for AttestationTrustError {}

pub(crate) fn normalized_assertion_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Bool(value) => Some(if *value {
            "true".to_string()
        } else {
            "false".to_string()
        }),
        serde_json::Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

pub fn canonicalize_attestation_verifier(value: &str) -> String {
    let trimmed = value.trim();
    match Url::parse(trimmed) {
        Ok(url) => url.to_string().trim_end_matches('/').to_string(),
        Err(_) => trimmed.trim_end_matches('/').to_string(),
    }
}
