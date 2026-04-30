use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use chio_core::session::{EnterpriseFederationMethod, EnterpriseIdentityContext};
use chio_core::sha256_hex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::enterprise_federation::{EnterpriseProviderKind, EnterpriseProviderRecord};
use crate::CliError;

pub const SCIM_LIFECYCLE_REGISTRY_VERSION: &str = "chio.scim-lifecycle-registry.v1";
pub const SCIM_LIFECYCLE_RECORD_SCHEMA: &str = "chio.scim-lifecycle-record.v1";
pub const SCIM_CORE_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const SCIM_ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
pub const CHIO_SCIM_USER_EXTENSION_SCHEMA: &str =
    "urn:chio:params:scim:schemas:extension:chio:2.0:User";
const IDENTITY_FEDERATION_DERIVATION_LABEL: &[u8] = b"chio.identity_federation.v1";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimName {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub honorific_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub honorific_suffix: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimMultiValue {
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChioScimUserExtension {
    pub provider_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_record_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimUserResource {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schemas: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub user_name: String,
    #[serde(default = "default_scim_active")]
    pub active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<ScimName>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub emails: Vec<ScimMultiValue>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<ScimMultiValue>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<ScimMultiValue>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entitlements: Vec<ScimMultiValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,
    #[serde(
        default,
        rename = "urn:chio:params:scim:schemas:extension:chio:2.0:User",
        skip_serializing_if = "Option::is_none"
    )]
    pub chio: Option<ChioScimUserExtension>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimErrorResponse {
    pub schemas: Vec<String>,
    pub status: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimLifecycleUserRecord {
    pub schema: String,
    pub user_id: String,
    pub provider_id: String,
    pub created_at: u64,
    pub updated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprovisioned_at: Option<u64>,
    pub scim_user: ScimUserResource,
    pub enterprise_identity: EnterpriseIdentityContext,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tracked_capability_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked_capability_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprovision_receipt_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimLifecycleRegistry {
    pub version: String,
    #[serde(default)]
    pub users: BTreeMap<String, ScimLifecycleUserRecord>,
}

impl Default for ScimLifecycleRegistry {
    fn default() -> Self {
        Self {
            version: SCIM_LIFECYCLE_REGISTRY_VERSION.to_string(),
            users: BTreeMap::new(),
        }
    }
}

impl ScimLifecycleRegistry {
    pub fn load(path: &Path) -> Result<Self, CliError> {
        match fs::read(path) {
            Ok(bytes) => {
                let mut registry: Self = serde_json::from_slice(&bytes)?;
                if registry.version != SCIM_LIFECYCLE_REGISTRY_VERSION {
                    return Err(CliError::cli_other_error(format!(
                        "unsupported scim lifecycle registry version: {}",
                        registry.version
                    )));
                }
                registry.version = SCIM_LIFECYCLE_REGISTRY_VERSION.to_string();
                Ok(registry)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(CliError::Io(error)),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), CliError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    pub fn get(&self, user_id: &str) -> Option<&ScimLifecycleUserRecord> {
        self.users.get(user_id)
    }

    pub fn find_by_identity(
        &self,
        provider_id: &str,
        subject_key: &str,
    ) -> Option<&ScimLifecycleUserRecord> {
        self.users.values().find(|record| {
            record.provider_id == provider_id
                && record.enterprise_identity.subject_key == subject_key
        })
    }

    pub fn insert(&mut self, record: ScimLifecycleUserRecord) -> Result<(), CliError> {
        if self.users.contains_key(&record.user_id) {
            return Err(CliError::cli_other_error(format!(
                "scim user `{}` already exists",
                record.user_id
            )));
        }
        if self
            .find_by_identity(&record.provider_id, &record.enterprise_identity.subject_key)
            .is_some()
        {
            return Err(CliError::cli_other_error(format!(
                "scim lifecycle already contains provider `{}` subject `{}`",
                record.provider_id, record.enterprise_identity.subject_key
            )));
        }
        self.users.insert(record.user_id.clone(), record);
        Ok(())
    }

    pub fn bind_capability(
        &mut self,
        provider_id: &str,
        subject_key: &str,
        capability_id: &str,
        now: u64,
    ) -> Result<bool, CliError> {
        let Some(record) = self.users.values_mut().find(|record| {
            record.provider_id == provider_id
                && record.enterprise_identity.subject_key == subject_key
        }) else {
            return Ok(false);
        };
        if !record.scim_user.active {
            return Err(CliError::cli_other_error(format!(
                "scim lifecycle identity `{}` is inactive",
                record.user_id
            )));
        }
        if !record
            .tracked_capability_ids
            .iter()
            .any(|existing| existing == capability_id)
        {
            record
                .tracked_capability_ids
                .push(capability_id.to_string());
            record.updated_at = now;
        }
        Ok(true)
    }

    pub fn deactivate(
        &mut self,
        user_id: &str,
        now: u64,
        revoked_capability_ids: &[String],
        receipt_id: Option<&str>,
    ) -> Result<Option<ScimLifecycleUserRecord>, CliError> {
        let Some(record) = self.users.get_mut(user_id) else {
            return Ok(None);
        };
        record.scim_user.active = false;
        record.updated_at = now;
        record.deprovisioned_at = Some(now);
        if let Some(extension) = record.scim_user.chio.as_mut() {
            extension.subject_key = Some(record.enterprise_identity.subject_key.clone());
            extension.principal = Some(record.enterprise_identity.principal.clone());
        }
        for capability_id in revoked_capability_ids {
            if !record
                .revoked_capability_ids
                .iter()
                .any(|existing| existing == capability_id)
            {
                record.revoked_capability_ids.push(capability_id.clone());
            }
        }
        if let Some(receipt_id) = receipt_id {
            record.deprovision_receipt_id = Some(receipt_id.to_string());
        }
        Ok(Some(record.clone()))
    }
}

impl ScimLifecycleUserRecord {
    pub fn active(&self) -> bool {
        self.scim_user.active
    }
}

pub fn build_scim_user_record(
    provider: &EnterpriseProviderRecord,
    mut user: ScimUserResource,
    now: u64,
    location: Option<String>,
) -> Result<ScimLifecycleUserRecord, CliError> {
    ensure_scim_provider(provider)?;
    validate_scim_user_request(&user)?;

    let user_id = user
        .id
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| derive_scim_user_id(provider, &user));
    let enterprise_identity =
        build_enterprise_identity_context_from_scim(provider, &user, &user_id)?;

    user.id = Some(user_id.clone());
    user.schemas = vec![
        SCIM_CORE_USER_SCHEMA.to_string(),
        CHIO_SCIM_USER_EXTENSION_SCHEMA.to_string(),
    ];
    user.meta = Some(ScimMeta {
        resource_type: Some("User".to_string()),
        location,
    });
    user.chio = Some(ChioScimUserExtension {
        provider_id: provider.provider_id.clone(),
        provider_record_id: Some(provider.provider_id.clone()),
        principal: Some(enterprise_identity.principal.clone()),
        subject_key: Some(enterprise_identity.subject_key.clone()),
        client_id: enterprise_identity.client_id.clone(),
        object_id: enterprise_identity.object_id.clone(),
        tenant_id: enterprise_identity.tenant_id.clone(),
        organization_id: enterprise_identity.organization_id.clone(),
    });

    Ok(ScimLifecycleUserRecord {
        schema: SCIM_LIFECYCLE_RECORD_SCHEMA.to_string(),
        user_id,
        provider_id: provider.provider_id.clone(),
        created_at: now,
        updated_at: now,
        deprovisioned_at: None,
        scim_user: user,
        enterprise_identity,
        tracked_capability_ids: Vec::new(),
        revoked_capability_ids: Vec::new(),
        deprovision_receipt_id: None,
    })
}

pub fn build_scim_error(status: u16, detail: impl Into<String>) -> ScimErrorResponse {
    ScimErrorResponse {
        schemas: vec![SCIM_ERROR_SCHEMA.to_string()],
        status: status.to_string(),
        detail: detail.into(),
    }
}

pub fn build_enterprise_identity_context_from_scim(
    provider: &EnterpriseProviderRecord,
    user: &ScimUserResource,
    user_id: &str,
) -> Result<EnterpriseIdentityContext, CliError> {
    ensure_scim_provider(provider)?;
    let principal = derive_scim_principal(provider, user, user_id)?;
    let extension = required_chio_extension(user)?;

    let mut attribute_sources = BTreeMap::new();
    attribute_sources.insert(
        "principal".to_string(),
        provider.subject_mapping.principal_source.clone(),
    );
    if extension.client_id.is_some() {
        attribute_sources.insert(
            "clientId".to_string(),
            provider
                .subject_mapping
                .client_id_field
                .clone()
                .unwrap_or_else(|| "clientId".to_string()),
        );
    }
    if extension.object_id.is_some() {
        attribute_sources.insert(
            "objectId".to_string(),
            provider
                .subject_mapping
                .object_id_field
                .clone()
                .unwrap_or_else(|| "objectId".to_string()),
        );
    }
    if extension.tenant_id.is_some() {
        attribute_sources.insert(
            "tenantId".to_string(),
            provider
                .subject_mapping
                .tenant_id_field
                .clone()
                .unwrap_or_else(|| "tenantId".to_string()),
        );
    }
    if extension.organization_id.is_some() {
        attribute_sources.insert(
            "organizationId".to_string(),
            provider
                .subject_mapping
                .organization_id_field
                .clone()
                .unwrap_or_else(|| "organizationId".to_string()),
        );
    }
    if !user.groups.is_empty() {
        attribute_sources.insert(
            "groups".to_string(),
            provider
                .subject_mapping
                .groups_field
                .clone()
                .unwrap_or_else(|| "groups".to_string()),
        );
    }
    if !user.roles.is_empty() {
        attribute_sources.insert(
            "roles".to_string(),
            provider
                .subject_mapping
                .roles_field
                .clone()
                .unwrap_or_else(|| "roles".to_string()),
        );
    }

    Ok(EnterpriseIdentityContext {
        provider_id: provider.provider_id.clone(),
        provider_record_id: Some(provider.provider_id.clone()),
        provider_kind: "scim".to_string(),
        federation_method: EnterpriseFederationMethod::Scim,
        principal: principal.clone(),
        subject_key: derive_enterprise_subject_key(&provider.provider_id, &principal),
        client_id: extension.client_id.clone(),
        object_id: extension.object_id.clone(),
        tenant_id: extension.tenant_id.clone(),
        organization_id: extension.organization_id.clone(),
        groups: user
            .groups
            .iter()
            .map(|value| value.value.clone())
            .collect(),
        roles: user.roles.iter().map(|value| value.value.clone()).collect(),
        source_subject: user
            .external_id
            .clone()
            .or_else(|| Some(user_id.to_string())),
        attribute_sources,
        trust_material_ref: provider.provenance.trust_material_ref.clone(),
    })
}

pub fn derive_enterprise_subject_key(provider_scope: &str, canonical_principal: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(IDENTITY_FEDERATION_DERIVATION_LABEL);
    hasher.update([1u8]);
    hasher.update(provider_scope.as_bytes());
    hasher.update([0u8]);
    hasher.update(canonical_principal.as_bytes());
    let digest = hasher.finalize();
    sha256_hex(digest.as_slice())
}

pub fn required_chio_extension(
    user: &ScimUserResource,
) -> Result<&ChioScimUserExtension, CliError> {
    let Some(extension) = user.chio.as_ref() else {
        return Err(CliError::cli_other_error(format!(
            "scim user requires the `{CHIO_SCIM_USER_EXTENSION_SCHEMA}` extension"
        )));
    };
    if extension.provider_id.trim().is_empty() {
        return Err(CliError::cli_other_error(
            "scim user chio extension requires provider_id".to_string(),
        ));
    }
    Ok(extension)
}

pub fn validate_scim_user_request(user: &ScimUserResource) -> Result<(), CliError> {
    if !user.schemas.is_empty() {
        if !user
            .schemas
            .iter()
            .any(|value| value == SCIM_CORE_USER_SCHEMA)
        {
            return Err(CliError::cli_other_error(format!(
                "scim user schemas must include `{SCIM_CORE_USER_SCHEMA}`"
            )));
        }
        if !user
            .schemas
            .iter()
            .any(|value| value == CHIO_SCIM_USER_EXTENSION_SCHEMA)
        {
            return Err(CliError::cli_other_error(format!(
                "scim user schemas must include `{CHIO_SCIM_USER_EXTENSION_SCHEMA}`"
            )));
        }
    }
    if user.user_name.trim().is_empty() {
        return Err(CliError::cli_other_error(
            "scim user requires a non-empty userName".to_string(),
        ));
    }
    let _ = required_chio_extension(user)?;
    Ok(())
}

pub fn ensure_scim_provider(provider: &EnterpriseProviderRecord) -> Result<(), CliError> {
    if !provider.is_validated_enabled() {
        return Err(CliError::cli_other_error(format!(
            "enterprise provider `{}` is not enabled and validated for scim lifecycle",
            provider.provider_id
        )));
    }
    if !matches!(provider.kind, EnterpriseProviderKind::Scim) {
        return Err(CliError::cli_other_error(format!(
            "enterprise provider `{}` is not a scim provider",
            provider.provider_id
        )));
    }
    Ok(())
}

fn derive_scim_user_id(provider: &EnterpriseProviderRecord, user: &ScimUserResource) -> String {
    let source = user
        .external_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(user.user_name.as_str());
    let digest = sha256_hex(format!("{}:{source}", provider.provider_id).as_bytes());
    format!("scim-{}", &digest[..32])
}

fn derive_scim_principal(
    provider: &EnterpriseProviderRecord,
    user: &ScimUserResource,
    user_id: &str,
) -> Result<String, CliError> {
    let source = provider.subject_mapping.principal_source.trim();
    match source {
        "userName" | "username" | "sub" => Ok(user.user_name.trim().to_string()),
        "externalId" => user
            .external_id
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "scim provider principal_source `externalId` requires externalId".to_string(),
                )
            }),
        "id" => Ok(user_id.to_string()),
        "email" | "emails" | "primaryEmail" => primary_email(user).ok_or_else(|| {
            CliError::cli_other_error(
                "scim provider principal_source `email` requires at least one email value"
                    .to_string(),
            )
        }),
        "clientId" => required_chio_extension(user)?
            .client_id
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "scim provider principal_source `clientId` requires clientId".to_string(),
                )
            }),
        "objectId" => required_chio_extension(user)?
            .object_id
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "scim provider principal_source `objectId` requires objectId".to_string(),
                )
            }),
        other => Err(CliError::cli_other_error(format!(
            "unsupported scim principal_source `{other}`; use userName, externalId, id, email, clientId, or objectId"
        ))),
    }
}

fn primary_email(user: &ScimUserResource) -> Option<String> {
    user.emails
        .iter()
        .find(|email| email.primary.unwrap_or(false))
        .or_else(|| user.emails.first())
        .map(|email| email.value.clone())
        .filter(|value| !value.trim().is_empty())
}

fn default_scim_active() -> bool {
    true
}
