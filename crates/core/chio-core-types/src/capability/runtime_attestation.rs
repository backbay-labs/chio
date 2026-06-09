use alloc::format;
use alloc::string::{String, ToString};

use serde::{Deserialize, Serialize};

use crate::runtime_attestation::derive_runtime_attestation_trust_material;

use super::trust_policy::{
    normalized_assertion_string, AttestationTrustError, AttestationTrustPolicy,
    ResolvedRuntimeAssurance,
};
use super::workload_identity::{WorkloadIdentity, WorkloadIdentityError};

/// Explicit operator-visible runtime assurance tier derived from attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAssuranceTier {
    #[default]
    None,
    Basic,
    Attested,
    Verified,
}

/// Normalized runtime attestation evidence carried with governed requests.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeAttestationEvidence {
    /// Schema or format identifier of the upstream attestation statement.
    pub schema: String,
    /// Attestation verifier or relying party that accepted the evidence.
    pub verifier: String,
    /// Normalized assurance tier resolved from the evidence.
    pub tier: RuntimeAssuranceTier,
    /// Unix timestamp (seconds) when this attestation was issued.
    pub issued_at: u64,
    /// Unix timestamp (seconds) when this attestation expires.
    pub expires_at: u64,
    /// Stable SHA-256 digest of the attestation evidence payload.
    pub evidence_sha256: String,
    /// Optional runtime identity or workload identifier associated with the evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_identity: Option<String>,
    /// Optional normalized workload identity when the upstream verifier exposed one explicitly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_identity: Option<WorkloadIdentity>,
    /// Optional structured claims preserved for adapters or operator inspection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Value>,
}

impl RuntimeAttestationEvidence {
    #[must_use]
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.issued_at && now < self.expires_at
    }

    pub fn normalized_workload_identity(
        &self,
    ) -> core::result::Result<Option<WorkloadIdentity>, WorkloadIdentityError> {
        let explicit = self
            .workload_identity
            .as_ref()
            .map(|identity| {
                identity.validate()?;
                Ok(identity.clone())
            })
            .transpose()?;
        let parsed_runtime_identity = match self.runtime_identity.as_deref() {
            Some(value) if value.trim().is_empty() => {
                return Err(WorkloadIdentityError::EmptyRuntimeIdentity);
            }
            Some(value) if value.trim_start().starts_with("spiffe://") => {
                Some(WorkloadIdentity::parse_spiffe_uri(value)?)
            }
            Some(_) => None,
            None => None,
        };

        match (explicit, parsed_runtime_identity) {
            (Some(explicit), Some(parsed)) => {
                if explicit.scheme != parsed.scheme {
                    return Err(WorkloadIdentityError::Conflict {
                        field: "scheme",
                        expected: format!("{:?}", parsed.scheme).to_lowercase(),
                        actual: format!("{:?}", explicit.scheme).to_lowercase(),
                    });
                }
                if explicit.trust_domain != parsed.trust_domain {
                    return Err(WorkloadIdentityError::Conflict {
                        field: "trust_domain",
                        expected: parsed.trust_domain,
                        actual: explicit.trust_domain,
                    });
                }
                if explicit.path != parsed.path {
                    return Err(WorkloadIdentityError::Conflict {
                        field: "path",
                        expected: parsed.path,
                        actual: explicit.path,
                    });
                }
                Ok(Some(explicit))
            }
            (Some(explicit), None) => {
                if let Some(runtime_identity) = self.runtime_identity.as_ref() {
                    return Err(WorkloadIdentityError::OpaqueRuntimeIdentityConflict(
                        runtime_identity.clone(),
                    ));
                }
                Ok(Some(explicit))
            }
            (None, Some(parsed)) => Ok(Some(parsed)),
            (None, None) => Ok(None),
        }
    }

    pub fn validate_workload_identity_binding(
        &self,
    ) -> core::result::Result<(), WorkloadIdentityError> {
        self.normalized_workload_identity().map(|_| ())
    }

    pub fn resolve_effective_runtime_assurance(
        &self,
        policy: Option<&AttestationTrustPolicy>,
        now: u64,
    ) -> core::result::Result<ResolvedRuntimeAssurance, AttestationTrustError> {
        self.validate_workload_identity_binding()
            .map_err(|error| AttestationTrustError::InvalidWorkloadIdentity(error.to_string()))?;
        if !self.is_valid_at(now) {
            return Err(AttestationTrustError::StaleEvidence {
                now,
                issued_at: self.issued_at,
                expires_at: self.expires_at,
            });
        }

        let raw_tier = self.tier;
        let Some(policy) = policy else {
            return Ok(ResolvedRuntimeAssurance {
                raw_tier,
                effective_tier: raw_tier,
                matched_rule: None,
            });
        };
        if policy.rules.is_empty() {
            return Ok(ResolvedRuntimeAssurance {
                raw_tier,
                effective_tier: raw_tier,
                matched_rule: None,
            });
        }
        let trust_material = derive_runtime_attestation_trust_material(self).map_err(|_| {
            AttestationTrustError::UnsupportedEvidence {
                schema: self.schema.clone(),
            }
        })?;

        for rule in &policy.rules {
            if !rule.matches(self, &trust_material) {
                continue;
            }
            if let Some(max_age_seconds) = rule.max_evidence_age_seconds {
                let age = now.saturating_sub(self.issued_at);
                if age > max_age_seconds {
                    return Err(AttestationTrustError::EvidenceTooOld {
                        rule: rule.name.clone(),
                        max_age_seconds,
                        actual_age_seconds: age,
                    });
                }
            }
            if !rule.allowed_attestation_types.is_empty() {
                let actual = trust_material
                    .normalized_assertions
                    .get("attestationType")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| AttestationTrustError::MissingAttestationType {
                        rule: rule.name.clone(),
                    })?;
                if !rule
                    .allowed_attestation_types
                    .iter()
                    .any(|allowed| allowed == actual)
                {
                    return Err(AttestationTrustError::DisallowedAttestationType {
                        rule: rule.name.clone(),
                        actual: actual.to_string(),
                    });
                }
            }
            for (assertion, expected) in &rule.required_assertions {
                let actual = trust_material
                    .normalized_assertions
                    .get(assertion)
                    .ok_or_else(|| AttestationTrustError::MissingAssertion {
                        rule: rule.name.clone(),
                        assertion: assertion.clone(),
                    })?;
                let actual = normalized_assertion_string(actual).ok_or_else(|| {
                    AttestationTrustError::AssertionMismatch {
                        rule: rule.name.clone(),
                        assertion: assertion.clone(),
                        expected: expected.clone(),
                        actual: actual.to_string(),
                    }
                })?;
                if actual != *expected {
                    return Err(AttestationTrustError::AssertionMismatch {
                        rule: rule.name.clone(),
                        assertion: assertion.clone(),
                        expected: expected.clone(),
                        actual,
                    });
                }
            }

            return Ok(ResolvedRuntimeAssurance {
                raw_tier,
                effective_tier: rule.effective_tier,
                matched_rule: Some(rule.name.clone()),
            });
        }

        Err(AttestationTrustError::UntrustedEvidence {
            verifier: self.verifier.clone(),
            schema: self.schema.clone(),
        })
    }
}
