use chio_finding_market_port::HostedTenantId;
use serde::Serialize;
use url::Url;

use crate::{HostedAuthenticatedPrincipal, HostedEdgeError};

/// Header carrying the tenant identity on every hosted request.
pub const HOSTED_TENANT_HEADER: &str = "Chio-Tenant-ID";
/// Schema identifier for the tenant binding contract.
pub const HOSTED_TENANT_BINDING_SCHEMA: &str = "chio.finding.hosted-tenant-binding.v1";
/// Schema identifier for the canonical request context.
pub const HOSTED_REQUEST_CONTRACT_SCHEMA: &str = "chio.finding.hosted-request-context.v1";
/// Schema identifier pinned by every mutation response.
pub const HOSTED_MUTATION_RESPONSE_SCHEMA: &str = "chio.finding.hosted-mutation-response.v1";
/// Schema identifier for the wire domain-event envelope.
pub const HOSTED_DOMAIN_EVENT_SCHEMA: &str = "chio.finding.hosted-domain-event.v1";

const MAX_REQUEST_ID_BYTES: usize = 128;
const MAX_PRINCIPAL_ID_BYTES: usize = 256;
const MAX_ACTION_BYTES: usize = 128;
const MAX_TARGET_BYTES: usize = 4_096;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
const MAX_OPERATION_ID_BYTES: usize = 256;
const MAX_RESOURCE_ID_BYTES: usize = 256;
const MAX_EVENT_KIND_BYTES: usize = 96;
const MAX_AGGREGATE_KIND_BYTES: usize = 96;
const MAX_AGGREGATE_ID_BYTES: usize = 256;
const MAX_EVENT_ID_BYTES: usize = 256;
const MAX_ARTIFACT_SCHEMA_BYTES: usize = 256;
const MAX_I_JSON_INTEGER: u64 = (1_u64 << 53) - 1;

/// A validated tenant identity taken from the tenant header before
/// any credential is inspected.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedTenantBinding {
    schema: &'static str,
    header_name: &'static str,
    tenant_id: HostedTenantId,
}

impl HostedTenantBinding {
    /// Parse the mandatory tenant selector before credential authentication.
    pub fn from_header(value: Option<&str>) -> Result<Self, HostedEdgeError> {
        let value = value.ok_or(HostedEdgeError::AuthenticationFailed)?;
        if value.trim() != value {
            return Err(HostedEdgeError::AuthenticationFailed);
        }
        let tenant_id =
            HostedTenantId::new(value).map_err(|_| HostedEdgeError::AuthenticationFailed)?;
        Ok(Self {
            schema: HOSTED_TENANT_BINDING_SCHEMA,
            header_name: HOSTED_TENANT_HEADER,
            tenant_id,
        })
    }

    /// The bound tenant.
    #[must_use]
    pub const fn tenant_id(&self) -> &HostedTenantId {
        &self.tenant_id
    }

    /// Bind the untrusted selector to the authenticated principal.
    pub fn bind_principal(
        &self,
        principal: &HostedAuthenticatedPrincipal,
    ) -> Result<(), HostedEdgeError> {
        if self.tenant_id != principal.tenant_id {
            return Err(HostedEdgeError::AuthorizationFailed);
        }
        Ok(())
    }
}

/// The HTTP methods the hosted contract signs over.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum HostedHttpMethod {
    Get,
    Post,
    Put,
    Delete,
}

impl HostedHttpMethod {
    /// Stable wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }

    const fn requires_idempotency(self) -> bool {
        !matches!(self, Self::Get)
    }
}

/// Authenticated metadata passed to a hosted market handler.
///
/// The request body is not embedded here. Only its canonical SHA-256 crosses
/// the authentication boundary, so handlers cannot accidentally authorize one
/// payload and execute another.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedRequestContract {
    schema: &'static str,
    request_id: String,
    tenant_id: HostedTenantId,
    principal_id: String,
    action: String,
    method: HostedHttpMethod,
    canonical_target: String,
    body_sha256: String,
    idempotency_key: Option<String>,
    received_at: u64,
}

impl HostedRequestContract {
    /// Fail closed on any malformed, oversized, or unbindable field.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        binding: &HostedTenantBinding,
        principal: &HostedAuthenticatedPrincipal,
        request_id: impl Into<String>,
        action: impl Into<String>,
        method: HostedHttpMethod,
        canonical_target: impl Into<String>,
        body_sha256: impl Into<String>,
        idempotency_key: Option<String>,
        received_at: u64,
    ) -> Result<Self, HostedEdgeError> {
        binding.bind_principal(principal)?;
        let contract = Self {
            schema: HOSTED_REQUEST_CONTRACT_SCHEMA,
            request_id: request_id.into(),
            tenant_id: binding.tenant_id.clone(),
            principal_id: principal.principal_id.clone(),
            action: action.into(),
            method,
            canonical_target: canonical_target.into(),
            body_sha256: body_sha256.into(),
            idempotency_key,
            received_at,
        };
        contract.validate()?;
        Ok(contract)
    }

    fn validate(&self) -> Result<(), HostedEdgeError> {
        if !valid_text(&self.request_id, MAX_REQUEST_ID_BYTES)
            || !valid_identifier(&self.principal_id, MAX_PRINCIPAL_ID_BYTES)
            || !valid_identifier(&self.action, MAX_ACTION_BYTES)
            || !valid_sha256(&self.body_sha256)
            || self.received_at == 0
            || self.received_at > MAX_I_JSON_INTEGER
            || self
                .idempotency_key
                .as_deref()
                .is_some_and(|value| !valid_identifier(value, MAX_IDEMPOTENCY_KEY_BYTES))
            || (self.method.requires_idempotency() && self.idempotency_key.is_none())
            || !valid_target(&self.canonical_target)
        {
            return Err(HostedEdgeError::InvalidRequest);
        }
        Ok(())
    }

    /// The bound tenant.
    #[must_use]
    pub const fn tenant_id(&self) -> &HostedTenantId {
        &self.tenant_id
    }

    /// The caller-supplied request id, already validated.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// The authenticated principal id.
    #[must_use]
    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    /// The governed action name.
    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }

    /// The bound HTTP method.
    #[must_use]
    pub const fn method(&self) -> HostedHttpMethod {
        self.method
    }

    /// The exact target path the credential proof signed over.
    #[must_use]
    pub fn canonical_target(&self) -> &str {
        &self.canonical_target
    }

    /// Digest of the exact request body bytes.
    #[must_use]
    pub fn body_sha256(&self) -> &str {
        &self.body_sha256
    }

    /// The idempotency key, when the operation carries one.
    #[must_use]
    pub fn idempotency_key(&self) -> Option<&str> {
        self.idempotency_key.as_deref()
    }

    /// Unix seconds the edge accepted the request.
    #[must_use]
    pub const fn received_at(&self) -> u64 {
        self.received_at
    }
}

/// Whether a mutation applied or was an exact replay.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostedMutationOutcome {
    Applied,
    ExactReplay,
    Accepted,
}

/// The wire response for one accepted mutation.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedMutationResponse {
    schema: &'static str,
    request_id: String,
    tenant_id: HostedTenantId,
    operation_id: String,
    outcome: HostedMutationOutcome,
    resource_id: String,
    resource_sha256: String,
}

impl HostedMutationResponse {
    /// Fail closed on any malformed, oversized, or unbindable field.
    pub fn new(
        request_id: impl Into<String>,
        tenant_id: HostedTenantId,
        operation_id: impl Into<String>,
        outcome: HostedMutationOutcome,
        resource_id: impl Into<String>,
        resource_sha256: impl Into<String>,
    ) -> Result<Self, HostedEdgeError> {
        let response = Self {
            schema: HOSTED_MUTATION_RESPONSE_SCHEMA,
            request_id: request_id.into(),
            tenant_id,
            operation_id: operation_id.into(),
            outcome,
            resource_id: resource_id.into(),
            resource_sha256: resource_sha256.into(),
        };
        if !valid_text(&response.request_id, MAX_REQUEST_ID_BYTES)
            || !valid_identifier(&response.operation_id, MAX_OPERATION_ID_BYTES)
            || !valid_identifier(&response.resource_id, MAX_RESOURCE_ID_BYTES)
            || !valid_sha256(&response.resource_sha256)
        {
            return Err(HostedEdgeError::InvalidRequest);
        }
        Ok(response)
    }
}

/// The wire envelope of one committed domain event projection.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedDomainEventEnvelope {
    schema: &'static str,
    tenant_id: HostedTenantId,
    event_kind: String,
    aggregate_kind: String,
    aggregate_id: String,
    event_id: String,
    revision: u64,
    previous_event_sha256: Option<String>,
    artifact_schema: String,
    artifact_sha256: String,
    occurred_at: u64,
}

impl HostedDomainEventEnvelope {
    /// Fail closed on any malformed, oversized, or unbindable field.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: HostedTenantId,
        event_kind: impl Into<String>,
        aggregate_kind: impl Into<String>,
        aggregate_id: impl Into<String>,
        event_id: impl Into<String>,
        revision: u64,
        previous_event_sha256: Option<String>,
        artifact_schema: impl Into<String>,
        artifact_sha256: impl Into<String>,
        occurred_at: u64,
    ) -> Result<Self, HostedEdgeError> {
        let event = Self {
            schema: HOSTED_DOMAIN_EVENT_SCHEMA,
            tenant_id,
            event_kind: event_kind.into(),
            aggregate_kind: aggregate_kind.into(),
            aggregate_id: aggregate_id.into(),
            event_id: event_id.into(),
            revision,
            previous_event_sha256,
            artifact_schema: artifact_schema.into(),
            artifact_sha256: artifact_sha256.into(),
            occurred_at,
        };
        let valid_head = match event.revision {
            1 => event.previous_event_sha256.is_none(),
            2.. => event
                .previous_event_sha256
                .as_deref()
                .is_some_and(valid_sha256),
            0 => false,
        };
        if !valid_identifier(&event.event_kind, MAX_EVENT_KIND_BYTES)
            || !valid_identifier(&event.aggregate_kind, MAX_AGGREGATE_KIND_BYTES)
            || !valid_identifier(&event.aggregate_id, MAX_AGGREGATE_ID_BYTES)
            || !valid_identifier(&event.event_id, MAX_EVENT_ID_BYTES)
            || !valid_identifier(&event.artifact_schema, MAX_ARTIFACT_SCHEMA_BYTES)
            || !valid_sha256(&event.artifact_sha256)
            || event.occurred_at == 0
            || event.occurred_at > MAX_I_JSON_INTEGER
            || event.revision > MAX_I_JSON_INTEGER
            || !valid_head
        {
            return Err(HostedEdgeError::InvalidRequest);
        }
        Ok(event)
    }
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_target(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_TARGET_BYTES || value.chars().any(char::is_control) {
        return false;
    }
    Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use chio_finding_market_port::HostedPrincipalRole;
    use chio_test_support::prelude::*;
    use serde_json::json;

    use super::*;
    use crate::{HostedAuthMethod, HOSTED_ERROR_SCHEMA};

    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn principal(tenant_id: HostedTenantId) -> HostedAuthenticatedPrincipal {
        HostedAuthenticatedPrincipal {
            tenant_id,
            principal_id: "buyer-1".to_owned(),
            role: HostedPrincipalRole::Buyer,
            method: HostedAuthMethod::ApiKey,
            credential_id: "key-1".to_owned(),
            artifact_signer_key: None,
        }
    }

    fn validate_schema(schema_name: &str, document: serde_json::Value) {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .join("spec/schemas/chio-http/v1");
        let schema_path = root.join(schema_name);
        let schema = chio_spec_validate::load_json(&schema_path).test_unwrap();
        chio_spec_validate::validate_value(
            &schema_path,
            &schema,
            Path::new("<hosted-contract>"),
            &document,
        )
        .test_unwrap();
    }

    #[test]
    fn tenant_header_is_mandatory_and_bound_to_the_principal() {
        assert_eq!(
            HostedTenantBinding::from_header(None),
            Err(HostedEdgeError::AuthenticationFailed)
        );
        assert_eq!(
            HostedTenantBinding::from_header(Some(" tenant-a")),
            Err(HostedEdgeError::AuthenticationFailed)
        );
        let binding = HostedTenantBinding::from_header(Some("tenant-a")).test_unwrap();
        binding
            .bind_principal(&principal(HostedTenantId::new("tenant-a").test_unwrap()))
            .test_unwrap();
        assert_eq!(
            binding.bind_principal(&principal(HostedTenantId::new("tenant-b").test_unwrap())),
            Err(HostedEdgeError::AuthorizationFailed)
        );
        validate_schema(
            "finding-hosted-tenant-binding.schema.json",
            serde_json::to_value(binding).test_unwrap(),
        );
    }

    #[test]
    fn mutating_request_requires_idempotency_and_serializes_to_contract() {
        let tenant = HostedTenantId::new("tenant-a").test_unwrap();
        let binding = HostedTenantBinding::from_header(Some(tenant.as_str())).test_unwrap();
        let principal = principal(tenant);
        let rejected = HostedRequestContract::new(
            &binding,
            &principal,
            "request-1",
            "finding.publish",
            HostedHttpMethod::Post,
            "https://market.example/v1/findings/publish",
            SHA,
            None,
            1_700_000_000,
        );
        assert_eq!(rejected, Err(HostedEdgeError::InvalidRequest));
        let request = HostedRequestContract::new(
            &binding,
            &principal,
            "request-1",
            "finding.publish",
            HostedHttpMethod::Post,
            "https://market.example/v1/findings/publish",
            SHA,
            Some("publish-1".to_owned()),
            1_700_000_000,
        )
        .test_unwrap();
        validate_schema(
            "finding-hosted-request-context.schema.json",
            serde_json::to_value(request).test_unwrap(),
        );
    }

    #[test]
    fn response_and_domain_event_match_their_closed_schemas() {
        let tenant = HostedTenantId::new("tenant-a").test_unwrap();
        let response = HostedMutationResponse::new(
            "request-1",
            tenant.clone(),
            "operation-1",
            HostedMutationOutcome::Applied,
            "finding-1",
            SHA,
        )
        .test_unwrap();
        validate_schema(
            "finding-hosted-mutation-response.schema.json",
            serde_json::to_value(response).test_unwrap(),
        );

        let event = HostedDomainEventEnvelope::new(
            tenant,
            "finding.published",
            "finding",
            "finding-1",
            "event-1",
            1,
            None,
            "chio.finding.v1",
            SHA,
            1_700_000_000,
        )
        .test_unwrap();
        validate_schema(
            "finding-hosted-domain-event.schema.json",
            serde_json::to_value(event).test_unwrap(),
        );
        assert!(HostedDomainEventEnvelope::new(
            HostedTenantId::new("tenant-a").test_unwrap(),
            "finding.published",
            "finding",
            "finding-1",
            "event-2",
            2,
            None,
            "chio.finding.v1",
            SHA,
            1_700_000_001,
        )
        .is_err());
    }

    #[test]
    fn hosted_error_contract_is_schema_valid_and_non_reflective() {
        let body = HostedEdgeError::DependencyUnavailable.body("request-1");
        validate_schema(
            "finding-hosted-error.schema.json",
            serde_json::to_value(body).test_unwrap(),
        );
        let invalid = json!({
            "schema": HOSTED_ERROR_SCHEMA,
            "code": "authentication_dependency_unavailable",
            "message": "SQL password leaked",
            "requestId": "request-1",
            "retryable": true,
            "detail": "secret"
        });
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .join("spec/schemas/chio-http/v1");
        let schema_path = root.join("finding-hosted-error.schema.json");
        let schema = chio_spec_validate::load_json(&schema_path).test_unwrap();
        assert!(chio_spec_validate::validate_value(
            &schema_path,
            &schema,
            Path::new("<invalid-hosted-error>"),
            &invalid,
        )
        .is_err());
    }
}
