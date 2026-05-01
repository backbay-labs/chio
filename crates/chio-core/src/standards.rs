use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

pub const CHIO_PORTABLE_CLAIM_CATALOG_SCHEMA: &str = "chio.portable-claim-catalog.v1";
pub const CHIO_PORTABLE_IDENTITY_BINDING_SCHEMA: &str = "chio.portable-identity-binding.v1";
pub const CHIO_GOVERNED_AUTH_BINDING_SCHEMA: &str = "chio.governed-auth-binding.v1";
pub const CHIO_PORTABLE_SUBJECT_BINDING_DID_CHIO_SUBJECT_KEY_THUMBPRINT: &str =
    "did:chio-subject-key-thumbprint";
pub const CHIO_PORTABLE_ISSUER_IDENTITY_HTTPS_JWKS: &str = "https-url+jwks";
pub const CHIO_PROVENANCE_ANCHOR_DID_CHIO: &str = "did:chio";
pub const CHIO_GOVERNED_AUTH_AUTHORITATIVE_SOURCE: &str = "metadata.governed_transaction";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioPortableClaimCatalog {
    pub schema: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub always_disclosed_claims: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selectively_disclosable_claims: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub optional_claims: Vec<String>,
    pub status_reference_kind: String,
    pub unsupported_claims_fail_closed: bool,
}

impl Default for ChioPortableClaimCatalog {
    fn default() -> Self {
        Self {
            schema: CHIO_PORTABLE_CLAIM_CATALOG_SCHEMA.to_string(),
            always_disclosed_claims: vec![
                "iss".to_string(),
                "sub".to_string(),
                "vct".to_string(),
                "cnf".to_string(),
                "chio_passport_id".to_string(),
                "chio_subject_did".to_string(),
                "chio_credential_count".to_string(),
            ],
            selectively_disclosable_claims: vec![
                "chio_issuer_dids".to_string(),
                "chio_merkle_roots".to_string(),
                "chio_enterprise_identity_provenance".to_string(),
            ],
            optional_claims: vec!["chio_passport_status".to_string()],
            status_reference_kind: "chio-passport-status-distribution".to_string(),
            unsupported_claims_fail_closed: true,
        }
    }
}

impl ChioPortableClaimCatalog {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != CHIO_PORTABLE_CLAIM_CATALOG_SCHEMA {
            return Err(format!(
                "portable claim catalog schema must be `{CHIO_PORTABLE_CLAIM_CATALOG_SCHEMA}`"
            ));
        }
        ensure_string_list(
            "portable claim catalog always_disclosed_claims",
            &self.always_disclosed_claims,
        )?;
        ensure_string_list(
            "portable claim catalog selectively_disclosable_claims",
            &self.selectively_disclosable_claims,
        )?;
        ensure_string_list(
            "portable claim catalog optional_claims",
            &self.optional_claims,
        )?;
        if self.status_reference_kind.trim().is_empty() {
            return Err(
                "portable claim catalog status_reference_kind must not be empty".to_string(),
            );
        }
        Ok(())
    }

    #[must_use]
    pub fn supports_selective_disclosure(&self, claim: &str) -> bool {
        self.selectively_disclosable_claims
            .iter()
            .any(|value| value == claim)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioPortableIdentityBinding {
    pub schema: String,
    pub subject_binding: String,
    pub portable_subject_claim: String,
    pub subject_confirmation_claim: String,
    pub chio_subject_provenance_claim: String,
    pub issuer_identity: String,
    pub portable_issuer_claim: String,
    pub chio_issuer_provenance_claim: String,
    pub enterprise_provenance_claim: String,
    pub chio_provenance_anchor: String,
    pub unsupported_mappings_fail_closed: bool,
}

impl Default for ChioPortableIdentityBinding {
    fn default() -> Self {
        Self {
            schema: CHIO_PORTABLE_IDENTITY_BINDING_SCHEMA.to_string(),
            subject_binding: CHIO_PORTABLE_SUBJECT_BINDING_DID_CHIO_SUBJECT_KEY_THUMBPRINT
                .to_string(),
            portable_subject_claim: "sub".to_string(),
            subject_confirmation_claim: "cnf.jwk".to_string(),
            chio_subject_provenance_claim: "chio_subject_did".to_string(),
            issuer_identity: CHIO_PORTABLE_ISSUER_IDENTITY_HTTPS_JWKS.to_string(),
            portable_issuer_claim: "iss".to_string(),
            chio_issuer_provenance_claim: "chio_issuer_dids".to_string(),
            enterprise_provenance_claim: "chio_enterprise_identity_provenance".to_string(),
            chio_provenance_anchor: CHIO_PROVENANCE_ANCHOR_DID_CHIO.to_string(),
            unsupported_mappings_fail_closed: true,
        }
    }
}

impl ChioPortableIdentityBinding {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != CHIO_PORTABLE_IDENTITY_BINDING_SCHEMA {
            return Err(format!(
                "portable identity binding schema must be `{CHIO_PORTABLE_IDENTITY_BINDING_SCHEMA}`"
            ));
        }
        ensure_non_empty(
            "portable identity binding subject_binding",
            &self.subject_binding,
        )?;
        ensure_non_empty(
            "portable identity binding portable_subject_claim",
            &self.portable_subject_claim,
        )?;
        ensure_non_empty(
            "portable identity binding subject_confirmation_claim",
            &self.subject_confirmation_claim,
        )?;
        ensure_non_empty(
            "portable identity binding chio_subject_provenance_claim",
            &self.chio_subject_provenance_claim,
        )?;
        ensure_non_empty(
            "portable identity binding issuer_identity",
            &self.issuer_identity,
        )?;
        ensure_non_empty(
            "portable identity binding portable_issuer_claim",
            &self.portable_issuer_claim,
        )?;
        ensure_non_empty(
            "portable identity binding chio_issuer_provenance_claim",
            &self.chio_issuer_provenance_claim,
        )?;
        ensure_non_empty(
            "portable identity binding enterprise_provenance_claim",
            &self.enterprise_provenance_claim,
        )?;
        ensure_non_empty(
            "portable identity binding chio_provenance_anchor",
            &self.chio_provenance_anchor,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioGovernedAuthorizationBinding {
    pub schema: String,
    pub authoritative_source: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub intent_binding_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approval_binding_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subject_binding_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuer_binding_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_assurance_binding_fields: Vec<String>,
    pub delegated_call_chain_field: String,
    pub unsupported_mappings_fail_closed: bool,
}

impl Default for ChioGovernedAuthorizationBinding {
    fn default() -> Self {
        Self {
            schema: CHIO_GOVERNED_AUTH_BINDING_SCHEMA.to_string(),
            authoritative_source: CHIO_GOVERNED_AUTH_AUTHORITATIVE_SOURCE.to_string(),
            intent_binding_fields: vec!["intentId".to_string(), "intentHash".to_string()],
            approval_binding_fields: vec![
                "approvalTokenId".to_string(),
                "approvalApproved".to_string(),
                "approverKey".to_string(),
            ],
            subject_binding_fields: vec!["subjectKey".to_string(), "subjectKeySource".to_string()],
            issuer_binding_fields: vec!["issuerKey".to_string(), "issuerKeySource".to_string()],
            runtime_assurance_binding_fields: vec![
                "runtimeAssuranceTier".to_string(),
                "runtimeAssuranceVerifier".to_string(),
                "runtimeAssuranceEvidenceSha256".to_string(),
            ],
            delegated_call_chain_field: "callChain".to_string(),
            unsupported_mappings_fail_closed: true,
        }
    }
}

impl ChioGovernedAuthorizationBinding {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != CHIO_GOVERNED_AUTH_BINDING_SCHEMA {
            return Err(format!(
                "governed authorization binding schema must be `{CHIO_GOVERNED_AUTH_BINDING_SCHEMA}`"
            ));
        }
        ensure_non_empty(
            "governed authorization binding authoritative_source",
            &self.authoritative_source,
        )?;
        ensure_string_list(
            "governed authorization binding intent_binding_fields",
            &self.intent_binding_fields,
        )?;
        ensure_string_list(
            "governed authorization binding approval_binding_fields",
            &self.approval_binding_fields,
        )?;
        ensure_string_list(
            "governed authorization binding subject_binding_fields",
            &self.subject_binding_fields,
        )?;
        ensure_string_list(
            "governed authorization binding issuer_binding_fields",
            &self.issuer_binding_fields,
        )?;
        ensure_string_list(
            "governed authorization binding runtime_assurance_binding_fields",
            &self.runtime_assurance_binding_fields,
        )?;
        ensure_non_empty(
            "governed authorization binding delegated_call_chain_field",
            &self.delegated_call_chain_field,
        )?;
        Ok(())
    }
}

fn ensure_non_empty(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}

fn ensure_string_list(label: &str, values: &[String]) -> Result<(), String> {
    if values.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(label, value)?;
        if !seen.insert(value) {
            return Err(format!("{label} must not repeat `{value}`"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portable_claim_catalog_defaults_and_validation_guards_hold() {
        let catalog = ChioPortableClaimCatalog::default();
        catalog
            .validate()
            .unwrap_or_else(|error| panic!("default portable claim catalog: {error}"));
        assert!(catalog.supports_selective_disclosure("chio_issuer_dids"));
        assert!(!catalog.supports_selective_disclosure("unknown_claim"));

        let mut invalid = catalog.clone();
        invalid.schema = "chio.portable-claim-catalog.v9".to_string();
        assert!(invalid.validate().is_err());

        let mut invalid = catalog.clone();
        invalid.status_reference_kind = " ".to_string();
        assert!(invalid.validate().is_err());

        let mut invalid = catalog;
        invalid.always_disclosed_claims = vec!["iss".to_string(), "iss".to_string()];
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn portable_identity_binding_validation_rejects_schema_and_empty_fields() {
        let binding = ChioPortableIdentityBinding::default();
        binding
            .validate()
            .unwrap_or_else(|error| panic!("default portable identity binding: {error}"));

        let mut invalid = binding.clone();
        invalid.schema = "chio.portable-identity-binding.v9".to_string();
        assert!(invalid.validate().is_err());

        let mut invalid = binding.clone();
        invalid.subject_binding.clear();
        assert!(invalid.validate().is_err());

        let mut invalid = binding;
        invalid.chio_provenance_anchor = " ".to_string();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn governed_authorization_binding_validation_rejects_schema_and_list_errors() {
        let binding = ChioGovernedAuthorizationBinding::default();
        binding
            .validate()
            .unwrap_or_else(|error| panic!("default governed authorization binding: {error}"));

        let mut invalid = binding.clone();
        invalid.schema = "chio.governed-auth-binding.v9".to_string();
        assert!(invalid.validate().is_err());

        let mut invalid = binding.clone();
        invalid.intent_binding_fields.clear();
        assert!(invalid.validate().is_err());

        let mut invalid = binding.clone();
        invalid.approval_binding_fields =
            vec!["approvalTokenId".to_string(), "approvalTokenId".to_string()];
        assert!(invalid.validate().is_err());

        let mut invalid = binding;
        invalid.delegated_call_chain_field = " ".to_string();
        assert!(invalid.validate().is_err());
    }
}
