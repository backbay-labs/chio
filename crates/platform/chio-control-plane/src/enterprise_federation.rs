use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::CliError;
use crate::JwtProviderProfile;

pub const ENTERPRISE_PROVIDER_REGISTRY_VERSION: &str = "chio.enterprise-providers.v1";
pub const CERTIFICATION_DISCOVERY_NETWORK_VERSION: &str = "chio.certify.discovery-network.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnterpriseProviderKind {
    #[serde(rename = "oidc_jwks")]
    OidcJwks,
    #[serde(rename = "oauth_introspection")]
    OauthIntrospection,
    #[serde(rename = "scim")]
    Scim,
    #[serde(rename = "saml")]
    Saml,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnterpriseProviderProvenance {
    #[serde(default)]
    pub configured_from: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_material_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_mapping_source: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnterpriseTrustBoundary {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_issuers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_audiences: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_tenants: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_organizations: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnterpriseSubjectMapping {
    pub principal_source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_id_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles_field: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnterpriseProviderRecord {
    pub provider_id: String,
    pub kind: EnterpriseProviderKind,
    pub enabled: bool,
    #[serde(default)]
    pub provenance: EnterpriseProviderProvenance,
    #[serde(default)]
    pub trust_boundary: EnterpriseTrustBoundary,
    #[serde(default, with = "jwt_provider_profile_serde")]
    pub provider_profile: Option<JwtProviderProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introspection_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scim_base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saml_entity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saml_metadata_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    pub subject_mapping: EnterpriseSubjectMapping,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub validation_errors: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnterpriseProviderRegistry {
    pub version: String,
    pub providers: BTreeMap<String, EnterpriseProviderRecord>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationDiscoveryOperator {
    pub operator_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_name: Option<String>,
    pub registry_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_token: Option<String>,
    #[serde(default)]
    pub allow_publish: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trust_labels: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub validation_errors: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationDiscoveryNetwork {
    pub version: String,
    #[serde(default)]
    pub operators: BTreeMap<String, CertificationDiscoveryOperator>,
}

impl Default for EnterpriseProviderRegistry {
    fn default() -> Self {
        Self {
            version: ENTERPRISE_PROVIDER_REGISTRY_VERSION.to_string(),
            providers: BTreeMap::new(),
        }
    }
}

impl Default for CertificationDiscoveryNetwork {
    fn default() -> Self {
        Self {
            version: CERTIFICATION_DISCOVERY_NETWORK_VERSION.to_string(),
            operators: BTreeMap::new(),
        }
    }
}

impl EnterpriseProviderRecord {
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        require_non_empty(&self.provider_id, "provider_id", &mut errors);
        require_non_empty(
            &self.provenance.configured_from,
            "provenance.configured_from",
            &mut errors,
        );
        require_non_empty(
            self.provenance
                .trust_material_ref
                .as_deref()
                .unwrap_or_default(),
            "provenance.trust_material_ref",
            &mut errors,
        );
        require_non_empty(
            &self.subject_mapping.principal_source,
            "subject_mapping.principal_source",
            &mut errors,
        );

        match self.kind {
            EnterpriseProviderKind::OidcJwks => {
                require_non_empty(
                    self.issuer.as_deref().unwrap_or_default(),
                    "issuer",
                    &mut errors,
                );
                if is_blank(self.discovery_url.as_deref()) && is_blank(self.jwks_url.as_deref()) {
                    errors
                        .push("oidc_jwks provider requires discovery_url or jwks_url".to_string());
                }
            }
            EnterpriseProviderKind::OauthIntrospection => {
                require_non_empty(
                    self.issuer.as_deref().unwrap_or_default(),
                    "issuer",
                    &mut errors,
                );
                require_non_empty(
                    self.introspection_url.as_deref().unwrap_or_default(),
                    "introspection_url",
                    &mut errors,
                );
            }
            EnterpriseProviderKind::Scim => {
                require_non_empty(
                    self.scim_base_url.as_deref().unwrap_or_default(),
                    "scim_base_url",
                    &mut errors,
                );
            }
            EnterpriseProviderKind::Saml => {
                require_non_empty(
                    self.saml_entity_id.as_deref().unwrap_or_default(),
                    "saml_entity_id",
                    &mut errors,
                );
                require_non_empty(
                    self.saml_metadata_url.as_deref().unwrap_or_default(),
                    "saml_metadata_url",
                    &mut errors,
                );
            }
        }

        if let Some(issuer) = self.issuer.as_deref() {
            if !allowlist_matches(&self.trust_boundary.allowed_issuers, issuer) {
                errors.push(format!(
                    "issuer `{issuer}` falls outside trust_boundary.allowed_issuers"
                ));
            }
        }
        if let Some(tenant_id) = self.tenant_id.as_deref() {
            if !allowlist_matches(&self.trust_boundary.allowed_tenants, tenant_id) {
                errors.push(format!(
                    "tenant_id `{tenant_id}` falls outside trust_boundary.allowed_tenants"
                ));
            }
        }
        if let Some(organization_id) = self.organization_id.as_deref() {
            if !allowlist_matches(&self.trust_boundary.allowed_organizations, organization_id) {
                errors.push(format!(
                    "organization_id `{organization_id}` falls outside trust_boundary.allowed_organizations"
                ));
            }
        }

        errors
    }

    pub fn is_validated_enabled(&self) -> bool {
        self.enabled && self.validation_errors.is_empty()
    }
}

impl CertificationDiscoveryOperator {
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        require_non_empty(&self.operator_id, "operator_id", &mut errors);
        require_non_empty(&self.registry_url, "registry_url", &mut errors);

        if !(is_blank(Some(&self.registry_url))
            || self.registry_url.starts_with("http://")
            || self.registry_url.starts_with("https://"))
        {
            errors.push("registry_url must start with http:// or https://".to_string());
        }

        errors
    }

    pub fn normalized_registry_url(&self) -> String {
        self.registry_url.trim().trim_end_matches('/').to_string()
    }

    pub fn is_valid(&self) -> bool {
        self.validation_errors.is_empty()
    }
}

impl EnterpriseProviderRegistry {
    pub fn load(path: &Path) -> Result<Self, CliError> {
        let bytes = fs::read(path).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read enterprise provider registry {}: {error}",
                path.display()
            ))
        })?;
        let registry = serde_json::from_slice::<Self>(&bytes).map_err(|error| {
            CliError::cli_json_error(format!(
                "failed to parse enterprise provider registry {}: {error}",
                path.display()
            ))
        })?;
        registry.with_revalidated_records()
    }

    pub fn save(&self, path: &Path) -> Result<(), CliError> {
        let registry = self.clone().with_revalidated_records()?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| {
                    CliError::cli_io_error(format!(
                        "failed to create enterprise provider registry directory {}: {error}",
                        parent.display()
                    ))
                })?;
            }
        }
        let serialized = serde_json::to_vec_pretty(&registry).map_err(|error| {
            CliError::cli_json_error(format!(
                "failed to serialize enterprise provider registry {}: {error}",
                path.display()
            ))
        })?;
        fs::write(path, serialized).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to write enterprise provider registry {}: {error}",
                path.display()
            ))
        })
    }

    pub fn validated_provider(&self, provider_id: &str) -> Option<&EnterpriseProviderRecord> {
        self.providers
            .get(provider_id)
            .filter(|record| record.is_validated_enabled())
    }

    pub fn upsert(&mut self, mut record: EnterpriseProviderRecord) {
        record.validation_errors = record.validate();
        self.version = ENTERPRISE_PROVIDER_REGISTRY_VERSION.to_string();
        self.providers.insert(record.provider_id.clone(), record);
    }

    pub fn remove(&mut self, provider_id: &str) -> bool {
        self.providers.remove(provider_id).is_some()
    }

    fn with_revalidated_records(mut self) -> Result<Self, CliError> {
        if self.version != ENTERPRISE_PROVIDER_REGISTRY_VERSION {
            return Err(CliError::cli_other_error(format!(
                "unsupported enterprise provider registry version `{}`",
                self.version
            )));
        }
        self.version = ENTERPRISE_PROVIDER_REGISTRY_VERSION.to_string();

        let mut normalized = BTreeMap::new();
        for (provider_id, mut record) in self.providers {
            if provider_id != record.provider_id {
                return Err(CliError::cli_other_error(
                    "enterprise provider map key must match provider_id".to_string(),
                ));
            }
            record.validation_errors = record.validate();
            normalized.insert(record.provider_id.clone(), record);
        }
        self.providers = normalized;
        Ok(self)
    }
}

impl CertificationDiscoveryNetwork {
    pub fn load(path: &Path) -> Result<Self, CliError> {
        let bytes = fs::read(path).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read certification discovery network {}: {error}",
                path.display()
            ))
        })?;
        let network = serde_json::from_slice::<Self>(&bytes).map_err(|error| {
            CliError::cli_json_error(format!(
                "failed to parse certification discovery network {}: {error}",
                path.display()
            ))
        })?;
        network.with_revalidated_records()
    }

    pub fn save(&self, path: &Path) -> Result<(), CliError> {
        let network = self.clone().with_revalidated_records()?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| {
                    CliError::cli_io_error(format!(
                        "failed to create certification discovery network directory {}: {error}",
                        parent.display()
                    ))
                })?;
            }
        }
        let serialized = serde_json::to_vec_pretty(&network).map_err(|error| {
            CliError::cli_json_error(format!(
                "failed to serialize certification discovery network {}: {error}",
                path.display()
            ))
        })?;
        fs::write(path, serialized).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to write certification discovery network {}: {error}",
                path.display()
            ))
        })
    }

    pub fn validated_operator(&self, operator_id: &str) -> Option<&CertificationDiscoveryOperator> {
        self.operators
            .get(operator_id)
            .filter(|operator| operator.is_valid())
    }

    pub fn validated_operators(&self) -> impl Iterator<Item = &CertificationDiscoveryOperator> {
        self.operators
            .values()
            .filter(|operator| operator.is_valid())
    }

    pub fn upsert(&mut self, mut operator: CertificationDiscoveryOperator) {
        operator.registry_url = operator.normalized_registry_url();
        operator.validation_errors = operator.validate();
        self.version = CERTIFICATION_DISCOVERY_NETWORK_VERSION.to_string();
        self.operators
            .insert(operator.operator_id.clone(), operator);
    }

    fn with_revalidated_records(mut self) -> Result<Self, CliError> {
        if self.version != CERTIFICATION_DISCOVERY_NETWORK_VERSION {
            return Err(CliError::cli_other_error(format!(
                "unsupported certification discovery network version `{}`",
                self.version
            )));
        }
        self.version = CERTIFICATION_DISCOVERY_NETWORK_VERSION.to_string();

        let mut normalized = BTreeMap::new();
        for (_, mut operator) in self.operators {
            operator.registry_url = operator.normalized_registry_url();
            operator.validation_errors = operator.validate();
            normalized.insert(operator.operator_id.clone(), operator);
        }
        self.operators = normalized;
        Ok(self)
    }
}

fn require_non_empty(value: &str, field: &str, errors: &mut Vec<String>) {
    if is_blank(Some(value)) {
        errors.push(format!("{field} is required"));
    }
}

fn allowlist_matches(allowlist: &[String], value: &str) -> bool {
    if allowlist.is_empty() {
        return true;
    }
    let value = value.trim();
    allowlist
        .iter()
        .map(|candidate| candidate.trim())
        .any(|candidate| !candidate.is_empty() && candidate == value)
}

fn is_blank(value: Option<&str>) -> bool {
    value.is_none_or(|value| value.trim().is_empty())
}

mod jwt_provider_profile_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::JwtProviderProfile;

    pub fn serialize<S>(
        value: &Option<JwtProviderProfile>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_option(value).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<JwtProviderProfile>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<String>::deserialize(deserializer)?;
        value
            .map(parse_profile)
            .transpose()
            .map_err(serde::de::Error::custom)
    }

    fn serialize_option(value: &Option<JwtProviderProfile>) -> Option<&'static str> {
        value.map(|profile| match profile {
            JwtProviderProfile::Generic => "generic",
            JwtProviderProfile::Auth0 => "auth0",
            JwtProviderProfile::Okta => "okta",
            JwtProviderProfile::AzureAd => "azure-ad",
        })
    }

    fn parse_profile(value: String) -> Result<JwtProviderProfile, String> {
        match value.as_str() {
            "generic" => Ok(JwtProviderProfile::Generic),
            "auth0" => Ok(JwtProviderProfile::Auth0),
            "okta" => Ok(JwtProviderProfile::Okta),
            "azure-ad" => Ok(JwtProviderProfile::AzureAd),
            other => Err(format!("unsupported jwt provider profile `{other}`")),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::{CliError, JwtProviderProfile};

    use super::{
        CertificationDiscoveryNetwork, CertificationDiscoveryOperator, EnterpriseProviderKind,
        EnterpriseProviderProvenance, EnterpriseProviderRecord, EnterpriseProviderRegistry,
        EnterpriseSubjectMapping, EnterpriseTrustBoundary, CERTIFICATION_DISCOVERY_NETWORK_VERSION,
        ENTERPRISE_PROVIDER_REGISTRY_VERSION,
    };

    fn subject_mapping() -> EnterpriseSubjectMapping {
        EnterpriseSubjectMapping {
            principal_source: "sub".to_string(),
            client_id_field: None,
            object_id_field: None,
            tenant_id_field: None,
            organization_id_field: None,
            groups_field: None,
            roles_field: None,
        }
    }

    fn provenance() -> EnterpriseProviderProvenance {
        EnterpriseProviderProvenance {
            configured_from: "manual".to_string(),
            source_ref: Some("operator".to_string()),
            trust_material_ref: Some("jwks:primary".to_string()),
            subject_mapping_source: Some("manual".to_string()),
        }
    }

    fn trust_boundary() -> EnterpriseTrustBoundary {
        EnterpriseTrustBoundary {
            allowed_issuers: vec!["https://issuer.example".to_string()],
            allowed_audiences: vec!["chio-mcp".to_string()],
            allowed_tenants: vec!["tenant-123".to_string()],
            allowed_organizations: vec!["org-456".to_string()],
        }
    }

    fn provider_record(
        provider_id: &str,
        kind: EnterpriseProviderKind,
    ) -> EnterpriseProviderRecord {
        EnterpriseProviderRecord {
            provider_id: provider_id.to_string(),
            kind,
            enabled: true,
            provenance: provenance(),
            trust_boundary: trust_boundary(),
            provider_profile: Some(JwtProviderProfile::Generic),
            issuer: Some("https://issuer.example".to_string()),
            discovery_url: Some(
                "https://issuer.example/.well-known/openid-configuration".to_string(),
            ),
            jwks_url: Some("https://issuer.example/jwks".to_string()),
            introspection_url: Some("https://issuer.example/introspect".to_string()),
            scim_base_url: Some("https://issuer.example/scim".to_string()),
            saml_entity_id: Some("urn:example:saml".to_string()),
            saml_metadata_url: Some("https://issuer.example/metadata".to_string()),
            tenant_id: Some("tenant-123".to_string()),
            organization_id: Some("org-456".to_string()),
            subject_mapping: subject_mapping(),
            validation_errors: Vec::new(),
        }
    }

    fn temp_registry_path() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .test_unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("chio-enterprise-provider-registry-{nonce}.json"))
    }

    fn temp_discovery_path() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .test_unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("chio-certify-discovery-network-{nonce}.json"))
    }

    fn assert_registry_error(err: &CliError, expected_code: &str, expected_domain: &str) {
        match err {
            CliError::Chio(chio) => {
                assert_eq!(chio.code().as_str(), expected_code);
                assert_eq!(chio.domain().as_str(), expected_domain);
            }
            other => panic!("expected registry-backed CliError::Chio, got: {other:?}"),
        }
    }

    use chio_test_support::prelude::*;

    fn must_err<T: std::fmt::Debug>(result: Result<T, CliError>, context: &str) -> CliError {
        match result {
            Ok(value) => panic!("{context}: expected error, got {value:?}"),
            Err(error) => error,
        }
    }

    fn write_test_file(path: &std::path::Path, bytes: impl AsRef<[u8]>) {
        if let Err(error) = fs::write(path, bytes) {
            panic!("failed to write {}: {error}", path.display());
        }
    }

    fn discovery_operator(operator_id: &str) -> CertificationDiscoveryOperator {
        CertificationDiscoveryOperator {
            operator_id: operator_id.to_string(),
            operator_name: Some(format!("Operator {operator_id}")),
            registry_url: format!("https://{operator_id}.example.com/"),
            control_token: Some(format!("token-{operator_id}")),
            allow_publish: true,
            trust_labels: vec!["public".to_string()],
            validation_errors: Vec::new(),
        }
    }

    #[test]
    fn enterprise_provider_oidc_missing_issuer_is_invalid() {
        let mut record = provider_record("oidc", EnterpriseProviderKind::OidcJwks);
        record.issuer = None;

        let errors = record.validate();

        assert!(
            errors.iter().any(|error| error.contains("issuer")),
            "expected issuer validation error, got {errors:?}"
        );
    }

    #[test]
    fn enterprise_provider_introspection_missing_url_is_invalid() {
        let mut record =
            provider_record("introspection", EnterpriseProviderKind::OauthIntrospection);
        record.introspection_url = None;

        let errors = record.validate();

        assert!(
            errors
                .iter()
                .any(|error| error.contains("introspection_url")),
            "expected introspection_url validation error, got {errors:?}"
        );
    }

    #[test]
    fn enterprise_provider_scim_missing_base_url_is_invalid() {
        let mut record = provider_record("scim", EnterpriseProviderKind::Scim);
        record.scim_base_url = None;

        let errors = record.validate();

        assert!(
            errors.iter().any(|error| error.contains("scim_base_url")),
            "expected scim_base_url validation error, got {errors:?}"
        );
    }

    #[test]
    fn enterprise_provider_saml_missing_metadata_url_is_invalid() {
        let mut record = provider_record("saml", EnterpriseProviderKind::Saml);
        record.saml_metadata_url = None;

        let errors = record.validate();

        assert!(
            errors
                .iter()
                .any(|error| error.contains("saml_metadata_url")),
            "expected saml_metadata_url validation error, got {errors:?}"
        );
    }

    #[test]
    fn enterprise_provider_missing_trust_material_reference_is_invalid() {
        let mut record = provider_record("oidc", EnterpriseProviderKind::OidcJwks);
        record.provenance.trust_material_ref = None;

        let errors = record.validate();

        assert!(
            errors
                .iter()
                .any(|error| error.contains("provenance.trust_material_ref")),
            "expected trust_material_ref validation error, got {errors:?}"
        );
    }

    #[test]
    fn enterprise_provider_out_of_boundary_issuer_is_invalid() {
        let mut record = provider_record("oidc", EnterpriseProviderKind::OidcJwks);
        record.issuer = Some("https://rogue.example".to_string());

        let errors = record.validate();

        assert!(
            errors.iter().any(|error| error.contains("allowed_issuers")),
            "expected allowed_issuers validation error, got {errors:?}"
        );
    }

    #[test]
    fn enterprise_provider_registry_round_trips_validation_state() {
        let path = temp_registry_path();
        let mut registry = EnterpriseProviderRegistry {
            version: ENTERPRISE_PROVIDER_REGISTRY_VERSION.to_string(),
            providers: BTreeMap::new(),
        };
        let mut invalid_record = provider_record("oidc", EnterpriseProviderKind::OidcJwks);
        invalid_record.issuer = None;
        registry.upsert(invalid_record.clone());

        registry.save(&path).test_unwrap();
        let loaded = EnterpriseProviderRegistry::load(&path).test_unwrap();

        assert_eq!(loaded.version, ENTERPRISE_PROVIDER_REGISTRY_VERSION);
        assert_eq!(
            loaded.providers.get("oidc").test_unwrap().validation_errors,
            invalid_record.validate()
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn enterprise_provider_registry_rejects_mismatched_map_key() {
        let path = temp_registry_path();
        let mut registry = EnterpriseProviderRegistry {
            version: ENTERPRISE_PROVIDER_REGISTRY_VERSION.to_string(),
            providers: BTreeMap::new(),
        };
        registry.providers.insert(
            "oidc-alias".to_string(),
            provider_record("oidc", EnterpriseProviderKind::OidcJwks),
        );
        fs::write(&path, serde_json::to_vec_pretty(&registry).test_unwrap()).test_unwrap();

        let error = must_err(
            EnterpriseProviderRegistry::load(&path),
            "provider map key mismatch should fail closed",
        );
        let _ = fs::remove_file(path);

        assert!(
            error
                .to_string()
                .contains("enterprise provider map key must match provider_id"),
            "expected provider key mismatch error, got {error}"
        );
    }

    #[test]
    fn enterprise_provider_registry_local_failures_use_cli_domains() {
        let missing_path = temp_registry_path();
        let missing_error = must_err(
            EnterpriseProviderRegistry::load(&missing_path),
            "missing registry should fail closed",
        );
        assert_registry_error(&missing_error, "urn:chio:error:cli:io", "cli");

        let invalid_json_path = temp_registry_path();
        write_test_file(&invalid_json_path, b"{not-json");
        let json_error = must_err(
            EnterpriseProviderRegistry::load(&invalid_json_path),
            "invalid registry JSON should fail closed",
        );
        assert_registry_error(&json_error, "urn:chio:error:cli:json", "cli");
        let _ = fs::remove_file(invalid_json_path);

        let unsupported_version_path = temp_registry_path();
        write_test_file(
            &unsupported_version_path,
            r#"{"version":"unsupported","providers":{}}"#,
        );
        let version_error = must_err(
            EnterpriseProviderRegistry::load(&unsupported_version_path),
            "unsupported registry version should fail closed",
        );
        assert_registry_error(&version_error, "urn:chio:error:cli:other", "cli");
        let _ = fs::remove_file(unsupported_version_path);
    }

    #[test]
    fn enterprise_provider_invalid_enabled_record_is_excluded_by_validated_provider() {
        let mut registry = EnterpriseProviderRegistry {
            version: ENTERPRISE_PROVIDER_REGISTRY_VERSION.to_string(),
            providers: BTreeMap::new(),
        };
        let mut invalid_record = provider_record("oidc", EnterpriseProviderKind::OidcJwks);
        invalid_record.issuer = None;
        registry.upsert(invalid_record);

        assert!(registry.validated_provider("oidc").is_none());
    }

    #[test]
    fn enterprise_provider_registry_remove_deletes_record() {
        let mut registry = EnterpriseProviderRegistry {
            version: ENTERPRISE_PROVIDER_REGISTRY_VERSION.to_string(),
            providers: BTreeMap::new(),
        };
        registry.upsert(provider_record("oidc", EnterpriseProviderKind::OidcJwks));

        assert!(registry.remove("oidc"));
        assert!(!registry.providers.contains_key("oidc"));
    }

    #[test]
    fn certification_discovery_network_round_trips_validation_state() {
        let path = temp_discovery_path();
        let mut network = CertificationDiscoveryNetwork {
            version: CERTIFICATION_DISCOVERY_NETWORK_VERSION.to_string(),
            operators: BTreeMap::new(),
        };
        let mut invalid = discovery_operator("west");
        invalid.registry_url = "west.example.com".to_string();
        network.upsert(invalid.clone());

        network.save(&path).test_unwrap();
        let loaded = CertificationDiscoveryNetwork::load(&path).test_unwrap();

        assert_eq!(loaded.version, CERTIFICATION_DISCOVERY_NETWORK_VERSION);
        assert_eq!(
            loaded.operators.get("west").test_unwrap().validation_errors,
            invalid.validate()
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn certification_discovery_network_local_failures_use_cli_domains() {
        let invalid_json_path = temp_discovery_path();
        write_test_file(&invalid_json_path, b"{not-json");
        let json_error = must_err(
            CertificationDiscoveryNetwork::load(&invalid_json_path),
            "invalid discovery JSON should fail closed",
        );
        assert_registry_error(&json_error, "urn:chio:error:cli:json", "cli");
        let _ = fs::remove_file(invalid_json_path);

        let unsupported_version_path = temp_discovery_path();
        write_test_file(
            &unsupported_version_path,
            r#"{"version":"unsupported","operators":{}}"#,
        );
        let version_error = must_err(
            CertificationDiscoveryNetwork::load(&unsupported_version_path),
            "unsupported discovery version should fail closed",
        );
        assert_registry_error(&version_error, "urn:chio:error:cli:other", "cli");
        let _ = fs::remove_file(unsupported_version_path);
    }

    #[test]
    fn certification_discovery_network_normalizes_registry_urls() {
        let mut network = CertificationDiscoveryNetwork::default();
        network.upsert(discovery_operator("east"));

        assert_eq!(
            network
                .validated_operator("east")
                .test_unwrap()
                .registry_url,
            "https://east.example.com"
        );
    }
}
