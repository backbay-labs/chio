//! Session-scoped identifiers and normalized operations.
//!
//! These types sit above the raw transport frames. The edge layer can translate
//! JSON-RPC, stdio frames, or another protocol into `SessionOperation`, and the
//! kernel can evaluate those operations without knowing how they arrived.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use core::fmt;

use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::capability::{ModelMetadata, ProvenanceEvidenceClass};
use crate::crypto::{canonical_json_bytes, sha256_hex, Keypair, PublicKey, Signature};
use crate::error::Result;
use crate::schema_binding::ensure_schema_matches;
use crate::signer_binding::ensure_keypair_matches_embedded_key;
use crate::{AgentId, CapabilityToken, ServerId};

/// Opaque identifier for a logical runtime session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct SessionId(String);

impl SessionId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for SessionId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<String> for SessionId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for SessionId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

/// Opaque identifier for a request scoped to a session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct RequestId(String);

impl RequestId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for RequestId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<String> for RequestId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for RequestId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

/// Token used to correlate progress updates to a request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(untagged)]
pub enum ProgressToken {
    String(String),
    Integer(u64),
}

/// Transport family that owns a logical runtime session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionTransport {
    InProcess,
    Stdio,
    StreamableHttp,
}

/// Canonical owner for work and terminal state within a session.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkOwner {
    Request,
    Task,
}

/// Canonical owner for a stream surface within a session.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StreamOwner {
    RequestStream,
    SessionNotificationStream,
}

/// Ownership model for request-scoped work.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RequestOwnershipSnapshot {
    pub work_owner: WorkOwner,
    pub result_stream_owner: StreamOwner,
    pub terminal_state_owner: WorkOwner,
}

impl RequestOwnershipSnapshot {
    pub fn request_owned() -> Self {
        Self {
            work_owner: WorkOwner::Request,
            result_stream_owner: StreamOwner::RequestStream,
            terminal_state_owner: WorkOwner::Request,
        }
    }
}

/// Ownership model for task-scoped work.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TaskOwnershipSnapshot {
    pub work_owner: WorkOwner,
    pub result_stream_owner: StreamOwner,
    pub status_notification_owner: StreamOwner,
    pub terminal_state_owner: WorkOwner,
}

impl TaskOwnershipSnapshot {
    pub fn task_owned() -> Self {
        Self {
            work_owner: WorkOwner::Task,
            result_stream_owner: StreamOwner::RequestStream,
            status_notification_owner: StreamOwner::SessionNotificationStream,
            terminal_state_owner: WorkOwner::Task,
        }
    }
}

/// Authentication method used to admit a session at the transport layer.
///
/// This is intentionally separate from Chio capability authorization. A session
/// may be transport-authenticated and still be denied by capability or guard
/// checks later during operation evaluation.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionAuthMethod {
    Anonymous,
    StaticBearer {
        principal: String,
        token_fingerprint: String,
    },
    OAuthBearer {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        principal: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        issuer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        subject: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        audience: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        scopes: Vec<String>,
        #[serde(
            default,
            skip_serializing_if = "OAuthBearerFederatedClaims::is_empty",
            rename = "federatedClaims"
        )]
        federated_claims: OAuthBearerFederatedClaims,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            rename = "enterpriseIdentity"
        )]
        enterprise_identity: Option<EnterpriseIdentityContext>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token_fingerprint: Option<String>,
    },
}

impl SessionAuthMethod {
    #[must_use]
    pub fn token_fingerprint(&self) -> Option<&str> {
        match self {
            Self::Anonymous => None,
            Self::StaticBearer {
                token_fingerprint, ..
            } => Some(token_fingerprint.as_str()),
            Self::OAuthBearer {
                token_fingerprint, ..
            } => token_fingerprint.as_deref(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OAuthBearerFederatedClaims {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
}

impl OAuthBearerFederatedClaims {
    pub fn is_empty(&self) -> bool {
        self.client_id.is_none()
            && self.object_id.is_none()
            && self.tenant_id.is_none()
            && self.organization_id.is_none()
            && self.groups.is_empty()
            && self.roles.is_empty()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnterpriseFederationMethod {
    #[default]
    Jwt,
    Introspection,
    Scim,
    Saml,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EnterpriseIdentityContext {
    pub provider_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_record_id: Option<String>,
    pub provider_kind: String,
    pub federation_method: EnterpriseFederationMethod,
    pub principal: String,
    pub subject_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_subject: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attribute_sources: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_material_ref: Option<String>,
}

/// Optional continuity or login assertion carried across verifier-facing flows.
///
/// Chio treats this as bounded continuity metadata rather than ambient identity
/// truth. Callers must still bind it to the enclosing verifier and replay
/// boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioIdentityAssertion {
    pub verifier_id: String,
    pub subject: String,
    pub continuity_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_request_id: Option<String>,
}

impl ChioIdentityAssertion {
    pub fn validate(&self) -> core::result::Result<(), String> {
        if self.verifier_id.trim().is_empty() {
            return Err("identityAssertion.verifierId must not be empty".to_string());
        }
        if self.subject.trim().is_empty() {
            return Err("identityAssertion.subject must not be empty".to_string());
        }
        if self.continuity_id.trim().is_empty() {
            return Err("identityAssertion.continuityId must not be empty".to_string());
        }
        if self.issued_at > self.expires_at {
            return Err(
                "identityAssertion.issuedAt must be before or equal to identityAssertion.expiresAt"
                    .to_string(),
            );
        }
        if self
            .provider
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err("identityAssertion.provider must not be empty when present".to_string());
        }
        if self
            .session_hint
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err("identityAssertion.sessionHint must not be empty when present".to_string());
        }
        if self
            .bound_request_id
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(
                "identityAssertion.boundRequestId must not be empty when present".to_string(),
            );
        }
        Ok(())
    }

    pub fn validate_at(&self, now: u64) -> core::result::Result<(), String> {
        self.validate()?;
        if now > self.expires_at {
            return Err("identityAssertion is stale".to_string());
        }
        Ok(())
    }
}

/// Normalized transport-authentication context bound to a logical session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SessionAuthContext {
    pub transport: SessionTransport,
    pub method: SessionAuthMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OAuthBearerSessionAuthInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub federated_claims: OAuthBearerFederatedClaims,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enterprise_identity: Option<EnterpriseIdentityContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

impl SessionAuthContext {
    pub fn in_process_anonymous() -> Self {
        Self {
            transport: SessionTransport::InProcess,
            method: SessionAuthMethod::Anonymous,
            origin: None,
        }
    }

    pub fn stdio_anonymous() -> Self {
        Self {
            transport: SessionTransport::Stdio,
            method: SessionAuthMethod::Anonymous,
            origin: None,
        }
    }

    pub fn streamable_http_static_bearer(
        principal: impl Into<String>,
        token_fingerprint: impl Into<String>,
        origin: Option<String>,
    ) -> Self {
        Self {
            transport: SessionTransport::StreamableHttp,
            method: SessionAuthMethod::StaticBearer {
                principal: principal.into(),
                token_fingerprint: token_fingerprint.into(),
            },
            origin,
        }
    }

    pub fn streamable_http_oauth_bearer(
        principal: Option<String>,
        issuer: Option<String>,
        subject: Option<String>,
        audience: Option<String>,
        scopes: Vec<String>,
        token_fingerprint: Option<String>,
        origin: Option<String>,
    ) -> Self {
        Self::streamable_http_oauth_bearer_with_claims(OAuthBearerSessionAuthInput {
            principal,
            issuer,
            subject,
            audience,
            scopes,
            federated_claims: OAuthBearerFederatedClaims::default(),
            enterprise_identity: None,
            token_fingerprint,
            origin,
        })
    }

    pub fn streamable_http_oauth_bearer_with_claims(input: OAuthBearerSessionAuthInput) -> Self {
        Self {
            transport: SessionTransport::StreamableHttp,
            method: SessionAuthMethod::OAuthBearer {
                principal: input.principal,
                issuer: input.issuer,
                subject: input.subject,
                audience: input.audience,
                scopes: input.scopes,
                federated_claims: input.federated_claims,
                enterprise_identity: input.enterprise_identity,
                token_fingerprint: input.token_fingerprint,
            },
            origin: input.origin,
        }
    }

    pub fn is_authenticated(&self) -> bool {
        !matches!(self.method, SessionAuthMethod::Anonymous)
    }

    pub fn canonical_hash(&self) -> Result<String> {
        let canonical = canonical_json_bytes(self)?;
        Ok(sha256_hex(&canonical))
    }

    pub fn auth_method_hash(&self) -> Result<String> {
        let canonical = canonical_json_bytes(&self.method)?;
        Ok(sha256_hex(&canonical))
    }

    pub fn principal(&self) -> Option<&str> {
        match &self.method {
            SessionAuthMethod::Anonymous => None,
            SessionAuthMethod::StaticBearer { principal, .. } => Some(principal.as_str()),
            SessionAuthMethod::OAuthBearer { principal, .. } => principal.as_deref(),
        }
    }
}

/// Versioned schema identifier for signed session anchors.
pub const CHIO_SESSION_ANCHOR_SCHEMA: &str = "chio.session_anchor.v1";
/// Versioned schema identifier for persisted request-lineage records.
pub const CHIO_REQUEST_LINEAGE_RECORD_SCHEMA: &str = "chio.request_lineage_record.v1";

/// Optional proof-binding material that tightens session continuity semantics.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SessionProofBinding {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpop_public_key_thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtls_thumbprint_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_attestation_sha256: Option<String>,
}

impl SessionProofBinding {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.token_fingerprint.is_none()
            && self.dpop_public_key_thumbprint.is_none()
            && self.mtls_thumbprint_sha256.is_none()
            && self.runtime_attestation_sha256.is_none()
    }

    #[must_use]
    pub fn from_auth_context(auth_context: &SessionAuthContext) -> Option<Self> {
        let binding = Self {
            token_fingerprint: auth_context.method.token_fingerprint().map(str::to_string),
            dpop_public_key_thumbprint: None,
            mtls_thumbprint_sha256: None,
            runtime_attestation_sha256: None,
        };
        (!binding.is_empty()).then_some(binding)
    }
}

/// Stable handle to a signed session anchor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SessionAnchorReference {
    pub session_anchor_id: String,
    pub session_anchor_hash: String,
}

impl SessionAnchorReference {
    #[must_use]
    pub fn new(
        session_anchor_id: impl Into<String>,
        session_anchor_hash: impl Into<String>,
    ) -> Self {
        Self {
            session_anchor_id: session_anchor_id.into(),
            session_anchor_hash: session_anchor_hash.into(),
        }
    }
}

/// Signable session-continuity anchor bound to a normalized auth context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SessionAnchorBody {
    pub schema: String,
    pub id: String,
    pub session_id: SessionId,
    pub agent_id: AgentId,
    pub auth_context: SessionAuthContext,
    pub auth_context_hash: String,
    pub auth_method_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_binding: Option<SessionProofBinding>,
    pub auth_epoch: u64,
    pub issued_at: u64,
    pub kernel_key: PublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SessionAnchorContext {
    pub session_id: SessionId,
    pub agent_id: AgentId,
    pub auth_context: SessionAuthContext,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_binding: Option<SessionProofBinding>,
}

impl SessionAnchorContext {
    #[must_use]
    pub fn new(
        session_id: SessionId,
        agent_id: AgentId,
        auth_context: SessionAuthContext,
        proof_binding: Option<SessionProofBinding>,
    ) -> Self {
        Self {
            session_id,
            agent_id,
            auth_context,
            proof_binding,
        }
    }
}

impl SessionAnchorBody {
    pub fn new(
        id: impl Into<String>,
        context: SessionAnchorContext,
        auth_epoch: u64,
        issued_at: u64,
        kernel_key: PublicKey,
    ) -> Result<Self> {
        Ok(Self {
            schema: CHIO_SESSION_ANCHOR_SCHEMA.to_string(),
            id: id.into(),
            session_id: context.session_id,
            agent_id: context.agent_id,
            auth_context_hash: context.auth_context.canonical_hash()?,
            auth_method_hash: context.auth_context.auth_method_hash()?,
            auth_context: context.auth_context,
            proof_binding: context.proof_binding.filter(|binding| !binding.is_empty()),
            auth_epoch,
            issued_at,
            kernel_key,
        })
    }
}

/// Signed session anchor that captures authenticated session continuity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SessionAnchor {
    pub schema: String,
    pub id: String,
    pub session_id: SessionId,
    pub agent_id: AgentId,
    pub auth_context: SessionAuthContext,
    pub auth_context_hash: String,
    pub auth_method_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_binding: Option<SessionProofBinding>,
    pub auth_epoch: u64,
    pub issued_at: u64,
    pub kernel_key: PublicKey,
    pub signature: Signature,
}

impl SessionAnchor {
    pub fn sign(body: SessionAnchorBody, keypair: &Keypair) -> Result<Self> {
        ensure_schema_matches(&body.schema, CHIO_SESSION_ANCHOR_SCHEMA, "session anchor")?;
        ensure_keypair_matches_embedded_key(
            &body.kernel_key,
            keypair,
            "session anchor",
            "kernel_key",
        )?;
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            schema: body.schema,
            id: body.id,
            session_id: body.session_id,
            agent_id: body.agent_id,
            auth_context: body.auth_context,
            auth_context_hash: body.auth_context_hash,
            auth_method_hash: body.auth_method_hash,
            proof_binding: body.proof_binding,
            auth_epoch: body.auth_epoch,
            issued_at: body.issued_at,
            kernel_key: body.kernel_key,
            signature,
        })
    }

    #[must_use]
    pub fn body(&self) -> SessionAnchorBody {
        SessionAnchorBody {
            schema: self.schema.clone(),
            id: self.id.clone(),
            session_id: self.session_id.clone(),
            agent_id: self.agent_id.clone(),
            auth_context: self.auth_context.clone(),
            auth_context_hash: self.auth_context_hash.clone(),
            auth_method_hash: self.auth_method_hash.clone(),
            proof_binding: self.proof_binding.clone(),
            auth_epoch: self.auth_epoch,
            issued_at: self.issued_at,
            kernel_key: self.kernel_key.clone(),
        }
    }

    pub fn verify_signature(&self) -> Result<bool> {
        ensure_schema_matches(&self.schema, CHIO_SESSION_ANCHOR_SCHEMA, "session anchor")?;
        let body = self.body();
        self.kernel_key.verify_canonical(&body, &self.signature)
    }

    pub fn anchor_hash(&self) -> Result<String> {
        let canonical = canonical_json_bytes(&self.body())?;
        Ok(sha256_hex(&canonical))
    }

    pub fn reference(&self) -> Result<SessionAnchorReference> {
        Ok(SessionAnchorReference::new(
            self.id.clone(),
            self.anchor_hash()?,
        ))
    }

    pub fn matches_context(
        &self,
        auth_context: &SessionAuthContext,
        proof_binding: Option<&SessionProofBinding>,
    ) -> Result<bool> {
        let expected_context_hash = auth_context.canonical_hash()?;
        let expected_method_hash = auth_context.auth_method_hash()?;
        let normalized_binding = proof_binding.filter(|binding| !binding.is_empty());

        Ok(self.auth_context == *auth_context
            && self.auth_context_hash == expected_context_hash
            && self.auth_method_hash == expected_method_hash
            && self.proof_binding.as_ref() == normalized_binding)
    }
}

/// Runtime lineage mode for a request node inside Chio's provenance graph.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestLineageMode {
    Root,
    LocalChild,
    Continued,
}

/// Persisted kernel record for one request node in the provenance DAG.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RequestLineageRecord {
    pub schema: String,
    pub request_id: RequestId,
    pub session_anchor: SessionAnchorReference,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_request_id: Option<RequestId>,
    pub operation_kind: OperationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent_hash: Option<String>,
    pub lineage_mode: RequestLineageMode,
    pub evidence_class: ProvenanceEvidenceClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation_token_id: Option<String>,
    pub started_at: u64,
}

impl RequestLineageRecord {
    #[must_use]
    pub fn new(
        request_id: RequestId,
        session_anchor: SessionAnchorReference,
        operation_kind: OperationKind,
        lineage_mode: RequestLineageMode,
        started_at: u64,
    ) -> Self {
        let evidence_class = match lineage_mode {
            RequestLineageMode::Root | RequestLineageMode::LocalChild => {
                ProvenanceEvidenceClass::Observed
            }
            RequestLineageMode::Continued => ProvenanceEvidenceClass::Verified,
        };

        Self {
            schema: CHIO_REQUEST_LINEAGE_RECORD_SCHEMA.to_string(),
            request_id,
            session_anchor,
            parent_request_id: None,
            operation_kind,
            capability_id: None,
            subject_key: None,
            issuer_key: None,
            intent_hash: None,
            lineage_mode,
            evidence_class,
            continuation_token_id: None,
            started_at,
        }
    }

    pub fn validate_schema(&self) -> Result<()> {
        ensure_schema_matches(
            &self.schema,
            CHIO_REQUEST_LINEAGE_RECORD_SCHEMA,
            "request lineage record",
        )
    }

    #[must_use]
    pub fn with_parent_request_id(mut self, parent_request_id: RequestId) -> Self {
        self.parent_request_id = Some(parent_request_id);
        self
    }

    #[must_use]
    pub fn with_capability_attribution(
        mut self,
        capability_id: impl Into<String>,
        subject_key: impl Into<String>,
        issuer_key: impl Into<String>,
    ) -> Self {
        self.capability_id = Some(capability_id.into());
        self.subject_key = Some(subject_key.into());
        self.issuer_key = Some(issuer_key.into());
        self
    }

    #[must_use]
    pub fn with_intent_hash(mut self, intent_hash: impl Into<String>) -> Self {
        self.intent_hash = Some(intent_hash.into());
        self
    }

    #[must_use]
    pub fn with_evidence_class(mut self, evidence_class: ProvenanceEvidenceClass) -> Self {
        self.evidence_class = evidence_class;
        self
    }

    #[must_use]
    pub fn with_continuation_token_id(mut self, continuation_token_id: impl Into<String>) -> Self {
        self.continuation_token_id = Some(continuation_token_id.into());
        self
    }

    #[must_use]
    pub fn is_root(&self) -> bool {
        matches!(self.lineage_mode, RequestLineageMode::Root)
    }

    #[must_use]
    pub fn is_local_child(&self) -> bool {
        matches!(self.lineage_mode, RequestLineageMode::LocalChild)
    }

    #[must_use]
    pub fn is_continued(&self) -> bool {
        matches!(self.lineage_mode, RequestLineageMode::Continued)
    }
}

/// Terminal runtime state for a session-scoped request.
///
/// This tracks lifecycle completion independently from authorization verdicts.
/// A denied request still reaches a terminal `Completed` state, while cancelled
/// or interrupted work records a different terminal outcome.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum OperationTerminalState {
    Completed,
    Cancelled { reason: String },
    Incomplete { reason: String },
}

impl OperationTerminalState {
    pub fn is_completed(&self) -> bool {
        matches!(self, Self::Completed)
    }

    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled { .. })
    }

    pub fn is_incomplete(&self) -> bool {
        matches!(self, Self::Incomplete { .. })
    }
}

/// Normalized operation kind, independent of edge framing.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    ToolCall,
    CreateMessage,
    CreateElicitation,
    ListRoots,
    ListResources,
    ReadResource,
    ListResourceTemplates,
    ListPrompts,
    GetPrompt,
    Complete,
    ListCapabilities,
    Heartbeat,
}

impl OperationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ToolCall => "tool_call",
            Self::CreateMessage => "create_message",
            Self::CreateElicitation => "create_elicitation",
            Self::ListRoots => "list_roots",
            Self::ListResources => "list_resources",
            Self::ReadResource => "read_resource",
            Self::ListResourceTemplates => "list_resource_templates",
            Self::ListPrompts => "list_prompts",
            Self::GetPrompt => "get_prompt",
            Self::Complete => "complete",
            Self::ListCapabilities => "list_capabilities",
            Self::Heartbeat => "heartbeat",
        }
    }
}

/// Session-scoped metadata attached to every normalized operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperationContext {
    pub session_id: SessionId,
    pub request_id: RequestId,
    pub agent_id: AgentId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_request_id: Option<RequestId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress_token: Option<ProgressToken>,
}

impl OperationContext {
    pub fn new(session_id: SessionId, request_id: RequestId, agent_id: AgentId) -> Self {
        Self {
            session_id,
            request_id,
            agent_id,
            parent_request_id: None,
            progress_token: None,
        }
    }
}

/// Root metadata exposed by the client to bound filesystem access.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RootDefinition {
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Normalized root view consumed by the shared runtime.
///
/// `RootDefinition` remains the transport shape received from the client. The
/// runtime uses `NormalizedRoot` to freeze whether a root is enforceable for
/// filesystem-shaped access or should be treated as metadata only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NormalizedRoot {
    EnforceableFileSystem {
        uri: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        normalized_path: String,
    },
    UnenforceableFileSystem {
        uri: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        reason: String,
    },
    NonFileSystem {
        uri: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        scheme: String,
    },
}

/// Explicit runtime classification for resource URIs.
///
/// Resource reads can point at provider-owned identifiers that are not
/// filesystem-backed. The runtime uses this boundary to decide when negotiated
/// filesystem roots apply and when a resource should remain provider-defined.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResourceUriClassification {
    EnforceableFileSystem {
        uri: String,
        normalized_path: String,
    },
    UnenforceableFileSystem {
        uri: String,
        reason: String,
    },
    NonFileSystem {
        uri: String,
        scheme: String,
    },
}

impl RootDefinition {
    /// Normalize the transport-provided root into the runtime's shared model.
    pub fn normalize_for_runtime(&self) -> NormalizedRoot {
        NormalizedRoot::from_root_definition(self)
    }
}

impl NormalizedRoot {
    pub fn from_root_definition(root: &RootDefinition) -> Self {
        match Url::parse(&root.uri) {
            Ok(parsed) if parsed.scheme() == "file" => match normalize_local_file_uri_path(&parsed)
            {
                Ok(normalized_path) => Self::EnforceableFileSystem {
                    uri: root.uri.clone(),
                    name: root.name.clone(),
                    normalized_path,
                },
                Err(reason) => Self::UnenforceableFileSystem {
                    uri: root.uri.clone(),
                    name: root.name.clone(),
                    reason: reason.to_string(),
                },
            },
            Ok(parsed) => Self::NonFileSystem {
                uri: root.uri.clone(),
                name: root.name.clone(),
                scheme: parsed.scheme().to_string(),
            },
            Err(_) if root.uri.starts_with("file:") => Self::UnenforceableFileSystem {
                uri: root.uri.clone(),
                name: root.name.clone(),
                reason: "invalid_file_uri".to_string(),
            },
            Err(_) => Self::NonFileSystem {
                uri: root.uri.clone(),
                name: root.name.clone(),
                scheme: extract_uri_scheme(&root.uri).unwrap_or_else(|| "unknown".to_string()),
            },
        }
    }

    pub fn is_enforceable_filesystem(&self) -> bool {
        matches!(self, Self::EnforceableFileSystem { .. })
    }

    pub fn normalized_filesystem_path(&self) -> Option<&str> {
        match self {
            Self::EnforceableFileSystem {
                normalized_path, ..
            } => Some(normalized_path.as_str()),
            Self::UnenforceableFileSystem { .. } | Self::NonFileSystem { .. } => None,
        }
    }

    pub fn uri(&self) -> &str {
        match self {
            Self::EnforceableFileSystem { uri, .. }
            | Self::UnenforceableFileSystem { uri, .. }
            | Self::NonFileSystem { uri, .. } => uri.as_str(),
        }
    }
}

impl ResourceUriClassification {
    pub fn from_uri(uri: &str) -> Self {
        match Url::parse(uri) {
            Ok(parsed) if parsed.scheme() == "file" => match normalize_local_file_uri_path(&parsed)
            {
                Ok(normalized_path) => Self::EnforceableFileSystem {
                    uri: uri.to_string(),
                    normalized_path,
                },
                Err(reason) => Self::UnenforceableFileSystem {
                    uri: uri.to_string(),
                    reason: reason.to_string(),
                },
            },
            Ok(parsed) => Self::NonFileSystem {
                uri: uri.to_string(),
                scheme: parsed.scheme().to_string(),
            },
            Err(_) if uri.starts_with("file:") => Self::UnenforceableFileSystem {
                uri: uri.to_string(),
                reason: "invalid_file_uri".to_string(),
            },
            Err(_) => Self::NonFileSystem {
                uri: uri.to_string(),
                scheme: extract_uri_scheme(uri).unwrap_or_else(|| "unknown".to_string()),
            },
        }
    }

    pub fn is_enforceable_filesystem(&self) -> bool {
        matches!(self, Self::EnforceableFileSystem { .. })
    }

    pub fn normalized_filesystem_path(&self) -> Option<&str> {
        match self {
            Self::EnforceableFileSystem {
                normalized_path, ..
            } => Some(normalized_path.as_str()),
            Self::UnenforceableFileSystem { .. } | Self::NonFileSystem { .. } => None,
        }
    }
}

fn normalize_local_file_uri_path(parsed: &Url) -> core::result::Result<String, &'static str> {
    match parsed.host_str() {
        None => {}
        Some(host) if host.eq_ignore_ascii_case("localhost") => {}
        Some(_) => return Err("non_local_file_authority"),
    }

    let decoded_path = percent_decode_str(parsed.path())
        .decode_utf8()
        .map_err(|_| "invalid_utf8_path")?;

    normalize_absolute_filesystem_path(decoded_path.as_ref()).ok_or("file_path_not_absolute")
}

fn normalize_absolute_filesystem_path(path: &str) -> Option<String> {
    let path = path.replace('\\', "/");

    let (prefix, remainder) = if let Some(after_root) = path.strip_prefix('/') {
        if let Some((drive, remainder)) = split_windows_drive(after_root) {
            (format!("{drive}:"), remainder)
        } else {
            ("/".to_string(), after_root)
        }
    } else if let Some((drive, remainder)) = split_windows_drive(&path) {
        (format!("{drive}:"), remainder)
    } else {
        return None;
    };

    let mut segments: Vec<&str> = Vec::new();
    for segment in remainder.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }

        if segment == ".." {
            if !segments.is_empty() {
                segments.pop();
            }
            continue;
        }

        segments.push(segment);
    }

    if prefix == "/" {
        if segments.is_empty() {
            Some("/".to_string())
        } else {
            Some(format!("/{}", segments.join("/")))
        }
    } else if segments.is_empty() {
        Some(format!("{prefix}/"))
    } else {
        Some(format!("{prefix}/{}", segments.join("/")))
    }
}

fn split_windows_drive(path: &str) -> Option<(char, &str)> {
    let bytes = path.as_bytes();
    if bytes.len() < 2 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' {
        return None;
    }

    let drive = char::from(bytes[0]).to_ascii_uppercase();
    match bytes.get(2).copied() {
        None => Some((drive, "")),
        Some(b'/') => Some((drive, &path[3..])),
        _ => None,
    }
}

fn extract_uri_scheme(uri: &str) -> Option<String> {
    let (scheme, _) = uri.split_once(':')?;
    let mut chars = scheme.chars();
    let first = chars.next()?;
    if !first.is_ascii_alphabetic() {
        return None;
    }
    if chars.all(|character| {
        character.is_ascii_alphanumeric()
            || character == '+'
            || character == '-'
            || character == '.'
    }) {
        Some(scheme.to_string())
    } else {
        None
    }
}

/// Normalized tool call payload. This is transport-agnostic and suitable for
/// direct kernel evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallOperation {
    pub capability: CapabilityToken,
    pub server_id: ServerId,
    pub tool_name: String,
    pub arguments: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_metadata: Option<ModelMetadata>,
}

/// Resource metadata exposed through the session layer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceDefinition {
    pub uri: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icons: Option<serde_json::Value>,
}

/// Parameterized resource template metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceTemplateDefinition {
    pub uri_template: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icons: Option<serde_json::Value>,
}

/// Resource content payload returned by a read request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceContent {
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<serde_json::Value>,
}

/// Prompt argument metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PromptArgument {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

/// Prompt metadata exposed through the session layer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PromptDefinition {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<PromptArgument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icons: Option<serde_json::Value>,
}

/// Message inside a prompt response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PromptMessage {
    pub role: String,
    pub content: serde_json::Value,
}

/// Prompt retrieval result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PromptResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub messages: Vec<PromptMessage>,
}

/// Reference target for an MCP-style completion request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CompletionReference {
    Prompt { name: String },
    Resource { uri: String },
}

/// In-progress argument being completed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompletionArgument {
    pub name: String,
    pub value: String,
}

/// Completion result payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompletionResult {
    pub values: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u32>,
    pub has_more: bool,
}

/// Message content submitted for client-side sampling.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SamplingMessage {
    pub role: String,
    pub content: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "_meta")]
    pub meta: Option<serde_json::Value>,
}

/// Tool schema advertised to a client during a sampling request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SamplingTool {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}

/// Controls whether tool use is allowed during client-side sampling.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SamplingToolChoice {
    pub mode: String,
}

/// Normalized payload for an MCP `sampling/createMessage` child request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreateMessageOperation {
    pub messages: Vec<SamplingMessage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_preferences: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_prompt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    pub max_tokens: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stop_sequences: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<SamplingTool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<SamplingToolChoice>,
}

/// Result payload returned by a client-side sampling request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreateMessageResult {
    pub role: String,
    pub content: serde_json::Value,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<String>,
}

/// Action selected by the client during an elicitation flow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ElicitationAction {
    Accept,
    Decline,
    Cancel,
}

/// Normalized payload for an MCP `elicitation/create` child request.
///
/// Chio ships both form-mode and URL-mode elicitation. URL-mode completion is
/// brokered by the edge via pending elicitation ownership and later
/// `notifications/elicitation/complete` forwarding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "mode", rename_all = "camelCase")]
pub enum CreateElicitationOperation {
    Form {
        #[serde(default, skip_serializing_if = "Option::is_none", rename = "_meta")]
        meta: Option<serde_json::Value>,
        message: String,
        #[serde(rename = "requestedSchema")]
        requested_schema: serde_json::Value,
    },
    Url {
        #[serde(default, skip_serializing_if = "Option::is_none", rename = "_meta")]
        meta: Option<serde_json::Value>,
        message: String,
        url: String,
        #[serde(rename = "elicitationId")]
        elicitation_id: String,
    },
}

/// Result payload returned by a client-side elicitation request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreateElicitationResult {
    pub action: ElicitationAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<serde_json::Value>,
}

/// Resource read payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadResourceOperation {
    pub capability: CapabilityToken,
    pub uri: String,
}

impl ReadResourceOperation {
    pub fn classify_uri_for_runtime(&self) -> ResourceUriClassification {
        ResourceUriClassification::from_uri(&self.uri)
    }
}

/// Prompt retrieval payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPromptOperation {
    pub capability: CapabilityToken,
    pub prompt_name: String,
    pub arguments: serde_json::Value,
}

/// Completion payload for prompt arguments or resource templates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteOperation {
    pub capability: CapabilityToken,
    pub reference: CompletionReference,
    pub argument: CompletionArgument,
    #[serde(default)]
    pub context_arguments: serde_json::Value,
}

/// Higher-level operations the runtime can evaluate within a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum SessionOperation {
    ToolCall(ToolCallOperation),
    CreateMessage(CreateMessageOperation),
    CreateElicitation(CreateElicitationOperation),
    ListRoots,
    ListResources,
    ReadResource(ReadResourceOperation),
    ListResourceTemplates,
    ListPrompts,
    GetPrompt(GetPromptOperation),
    Complete(CompleteOperation),
    ListCapabilities,
    Heartbeat,
}

impl SessionOperation {
    pub fn kind(&self) -> OperationKind {
        match self {
            Self::ToolCall(_) => OperationKind::ToolCall,
            Self::CreateMessage(_) => OperationKind::CreateMessage,
            Self::CreateElicitation(_) => OperationKind::CreateElicitation,
            Self::ListRoots => OperationKind::ListRoots,
            Self::ListResources => OperationKind::ListResources,
            Self::ReadResource(_) => OperationKind::ReadResource,
            Self::ListResourceTemplates => OperationKind::ListResourceTemplates,
            Self::ListPrompts => OperationKind::ListPrompts,
            Self::GetPrompt(_) => OperationKind::GetPrompt,
            Self::Complete(_) => OperationKind::Complete,
            Self::ListCapabilities => OperationKind::ListCapabilities,
            Self::Heartbeat => OperationKind::Heartbeat,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::capability::{CapabilityTokenBody, ChioScope, Operation, ToolGrant};
    use crate::crypto::Keypair;

    fn make_token(kp: &Keypair) -> CapabilityToken {
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-session-001".to_string(),
                issuer: kp.public_key(),
                subject: kp.public_key(),
                scope: ChioScope {
                    grants: vec![ToolGrant {
                        server_id: "srv-a".to_string(),
                        tool_name: "read_file".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    ..ChioScope::default()
                },
                issued_at: 100,
                expires_at: 200,
                delegation_chain: vec![],
            },
            kp,
        )
        .unwrap()
    }

    #[test]
    fn session_id_roundtrip() {
        let id = SessionId::new("sess-001");
        let encoded = serde_json::to_string(&id).unwrap();
        let decoded: SessionId = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, id);
        assert_eq!(decoded.to_string(), "sess-001");
    }

    #[test]
    fn operation_context_new_sets_default_lineage_fields() {
        let context = OperationContext::new(
            SessionId::new("sess-001"),
            RequestId::new("req-001"),
            "agent-123".to_string(),
        );
        assert_eq!(context.session_id.as_str(), "sess-001");
        assert_eq!(context.request_id.as_str(), "req-001");
        assert_eq!(context.agent_id, "agent-123");
        assert_eq!(context.parent_request_id, None);
        assert_eq!(context.progress_token, None);
    }

    #[test]
    fn operation_context_roundtrip_preserves_lineage() {
        let context = OperationContext {
            session_id: SessionId::new("sess-001"),
            request_id: RequestId::new("req-002"),
            agent_id: "agent-123".to_string(),
            parent_request_id: Some(RequestId::new("req-001")),
            progress_token: Some(ProgressToken::String("progress-7".to_string())),
        };

        let encoded = serde_json::to_string(&context).unwrap();
        let decoded: OperationContext = serde_json::from_str(&encoded).unwrap();

        assert_eq!(decoded, context);
    }

    #[test]
    fn progress_token_accepts_integer_or_string() {
        let numeric = serde_json::json!(7);
        let stringy = serde_json::json!("progress-7");

        let numeric_token: ProgressToken = serde_json::from_value(numeric).unwrap();
        let string_token: ProgressToken = serde_json::from_value(stringy).unwrap();

        assert_eq!(numeric_token, ProgressToken::Integer(7));
        assert_eq!(
            string_token,
            ProgressToken::String("progress-7".to_string())
        );
    }

    #[test]
    fn session_operation_roundtrip_preserves_tool_call_payload() {
        let kp = Keypair::generate();
        let op = SessionOperation::ToolCall(ToolCallOperation {
            capability: make_token(&kp),
            server_id: "srv-a".to_string(),
            tool_name: "read_file".to_string(),
            arguments: serde_json::json!({"path": "/app/src/lib.rs"}),
            model_metadata: Some(ModelMetadata {
                model_id: "gpt-5".to_string(),
                safety_tier: None,
                provider: Some("openai".to_string()),
                provenance_class: ProvenanceEvidenceClass::Observed,
            }),
        });

        let encoded = serde_json::to_string(&op).unwrap();
        let decoded: SessionOperation = serde_json::from_str(&encoded).unwrap();

        match decoded {
            SessionOperation::ToolCall(payload) => {
                assert_eq!(payload.server_id, "srv-a");
                assert_eq!(payload.tool_name, "read_file");
                assert_eq!(payload.arguments["path"], "/app/src/lib.rs");
                assert_eq!(
                    payload
                        .model_metadata
                        .as_ref()
                        .map(|metadata| metadata.model_id.as_str()),
                    Some("gpt-5")
                );
                assert_eq!(
                    payload
                        .model_metadata
                        .as_ref()
                        .map(|metadata| metadata.provenance_class),
                    Some(ProvenanceEvidenceClass::Observed)
                );
            }
            _ => panic!("expected tool call"),
        }
    }

    #[test]
    fn session_operation_reports_kind() {
        assert_eq!(SessionOperation::Heartbeat.kind(), OperationKind::Heartbeat);
        assert_eq!(
            SessionOperation::ListCapabilities.kind(),
            OperationKind::ListCapabilities
        );
        assert_eq!(
            SessionOperation::CreateMessage(CreateMessageOperation {
                messages: vec![],
                model_preferences: None,
                system_prompt: None,
                include_context: None,
                temperature: None,
                max_tokens: 1,
                stop_sequences: vec![],
                metadata: None,
                tools: vec![],
                tool_choice: None,
            })
            .kind(),
            OperationKind::CreateMessage
        );
        assert_eq!(
            SessionOperation::CreateElicitation(CreateElicitationOperation::Form {
                meta: None,
                message: "Confirm this action".to_string(),
                requested_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "approved": { "type": "boolean" }
                    },
                    "required": ["approved"]
                }),
            })
            .kind(),
            OperationKind::CreateElicitation
        );
        assert_eq!(
            SessionOperation::ListResources.kind(),
            OperationKind::ListResources
        );
        assert_eq!(SessionOperation::ListRoots.kind(), OperationKind::ListRoots);
    }

    #[test]
    fn root_definition_roundtrip() {
        let root = RootDefinition {
            uri: "file:///workspace/project".to_string(),
            name: Some("Project".to_string()),
        };

        let encoded = serde_json::to_string(&root).unwrap();
        let decoded: RootDefinition = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, root);
    }

    #[test]
    fn normalizes_enforceable_file_roots_for_runtime() {
        let root = RootDefinition {
            uri: "file:///workspace/project/../project/src".to_string(),
            name: Some("Project".to_string()),
        };

        let normalized = root.normalize_for_runtime();
        assert!(normalized.is_enforceable_filesystem());
        assert_eq!(
            normalized.normalized_filesystem_path(),
            Some("/workspace/project/src")
        );
    }

    #[test]
    fn normalizes_windows_style_file_roots_for_runtime() {
        let root = RootDefinition {
            uri: "file:///C:/Workspace/Chio/../project".to_string(),
            name: None,
        };

        let normalized = root.normalize_for_runtime();
        assert_eq!(
            normalized.normalized_filesystem_path(),
            Some("C:/Workspace/project")
        );
    }

    #[test]
    fn classifies_non_file_roots_as_metadata_only() {
        let root = RootDefinition {
            uri: "repo://docs/roadmap".to_string(),
            name: Some("Roadmap".to_string()),
        };

        let normalized = root.normalize_for_runtime();
        assert!(matches!(
            normalized,
            NormalizedRoot::NonFileSystem { ref scheme, .. } if scheme == "repo"
        ));
    }

    #[test]
    fn root_and_resource_normalization_cover_remaining_helper_edges() {
        let localhost_root = RootDefinition {
            uri: "file://localhost/workspace/project/docs".to_string(),
            name: None,
        };
        let normalized = localhost_root.normalize_for_runtime();
        assert!(normalized.is_enforceable_filesystem());
        assert_eq!(normalized.uri(), "file://localhost/workspace/project/docs");

        let invalid_file_root = RootDefinition {
            uri: "file:relative/path".to_string(),
            name: None,
        };
        let normalized = invalid_file_root.normalize_for_runtime();
        assert!(matches!(
            normalized,
            NormalizedRoot::EnforceableFileSystem { ref normalized_path, .. }
                if normalized_path == "/relative/path"
        ));

        let invalid_utf8_root = RootDefinition {
            uri: "file:///workspace/%FF".to_string(),
            name: None,
        };
        assert!(matches!(
            invalid_utf8_root.normalize_for_runtime(),
            NormalizedRoot::UnenforceableFileSystem { ref reason, .. }
                if reason == "invalid_utf8_path"
        ));

        let read = ReadResourceOperation {
            capability: make_token(&Keypair::generate()),
            uri: "file:///workspace/project/docs/../docs/spec.md".to_string(),
        };
        let classified = read.classify_uri_for_runtime();
        assert!(classified.is_enforceable_filesystem());
        assert_eq!(
            classified.normalized_filesystem_path(),
            Some("/workspace/project/docs/spec.md")
        );

        assert_eq!(
            normalize_absolute_filesystem_path("/workspace/project/../docs"),
            Some("/workspace/docs".to_string())
        );
        assert_eq!(
            normalize_absolute_filesystem_path("C:\\Workspace\\Chio\\..\\project"),
            Some("C:/Workspace/project".to_string())
        );
        assert_eq!(normalize_absolute_filesystem_path("relative/path"), None);
        assert_eq!(
            split_windows_drive("c:/Workspace/project"),
            Some(('C', "Workspace/project"))
        );
        assert_eq!(split_windows_drive("D:"), Some(('D', "")));
        assert_eq!(split_windows_drive("1:/not-a-drive"), None);
        assert_eq!(
            extract_uri_scheme("repo+docs://roadmap"),
            Some("repo+docs".to_string())
        );
        assert_eq!(extract_uri_scheme("1repo://roadmap"), None);
        assert_eq!(extract_uri_scheme("repo^docs://roadmap"), None);
    }

    #[test]
    fn marks_non_local_file_roots_as_unenforceable() {
        let root = RootDefinition {
            uri: "file://remote-host/workspace/project".to_string(),
            name: None,
        };

        let normalized = root.normalize_for_runtime();
        assert!(matches!(
            normalized,
            NormalizedRoot::UnenforceableFileSystem { ref reason, .. }
                if reason == "non_local_file_authority"
        ));
        assert_eq!(normalized.normalized_filesystem_path(), None);
    }

    #[test]
    fn classifies_filesystem_resource_uris_for_runtime() {
        let classified = ResourceUriClassification::from_uri(
            "file:///workspace/project/docs/../docs/roadmap.md",
        );

        assert!(classified.is_enforceable_filesystem());
        assert_eq!(
            classified.normalized_filesystem_path(),
            Some("/workspace/project/docs/roadmap.md")
        );
    }

    #[test]
    fn classifies_non_filesystem_resource_uris_without_forcing_root_checks() {
        let classified = ResourceUriClassification::from_uri("repo://docs/roadmap");

        assert!(matches!(
            classified,
            ResourceUriClassification::NonFileSystem { ref scheme, .. } if scheme == "repo"
        ));
        assert_eq!(classified.normalized_filesystem_path(), None);
    }

    #[test]
    fn marks_unenforceable_filesystem_resource_uris_as_fail_closed() {
        let classified = ResourceUriClassification::from_uri("file://remote-host/workspace/ops");

        assert!(matches!(
            classified,
            ResourceUriClassification::UnenforceableFileSystem { ref reason, .. }
                if reason == "non_local_file_authority"
        ));
        assert_eq!(classified.normalized_filesystem_path(), None);
    }

    #[test]
    fn create_message_operation_roundtrip() {
        let operation = CreateMessageOperation {
            messages: vec![SamplingMessage {
                role: "user".to_string(),
                content: serde_json::json!({
                    "type": "text",
                    "text": "Summarize this change"
                }),
                meta: Some(serde_json::json!({ "source": "tool-call" })),
            }],
            model_preferences: Some(serde_json::json!({
                "speedPriority": 0.8
            })),
            system_prompt: Some("You are careful.".to_string()),
            include_context: Some("none".to_string()),
            temperature: Some(0.2),
            max_tokens: 512,
            stop_sequences: vec!["END".to_string()],
            metadata: Some(serde_json::json!({ "trace": "abc123" })),
            tools: vec![SamplingTool {
                name: "search_docs".to_string(),
                description: Some("Search docs".to_string()),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string" }
                    },
                    "required": ["query"]
                }),
            }],
            tool_choice: Some(SamplingToolChoice {
                mode: "auto".to_string(),
            }),
        };

        let encoded = serde_json::to_string(&operation).unwrap();
        let decoded: CreateMessageOperation = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, operation);
    }

    #[test]
    fn create_elicitation_operation_roundtrip() {
        let operation = CreateElicitationOperation::Form {
            meta: Some(serde_json::json!({ "trace": "abc123" })),
            message: "Please confirm the deploy target".to_string(),
            requested_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "environment": {
                        "type": "string",
                        "enum": ["staging", "production"]
                    }
                },
                "required": ["environment"]
            }),
        };

        let encoded = serde_json::to_string(&operation).unwrap();
        let decoded: CreateElicitationOperation = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, operation);
    }

    #[test]
    fn create_elicitation_result_roundtrip() {
        let result = CreateElicitationResult {
            action: ElicitationAction::Accept,
            content: Some(serde_json::json!({
                "environment": "staging"
            })),
        };

        let encoded = serde_json::to_string(&result).unwrap();
        let decoded: CreateElicitationResult = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, result);
    }

    #[test]
    fn prompt_result_roundtrip() {
        let prompt = PromptResult {
            description: Some("Example prompt".to_string()),
            messages: vec![PromptMessage {
                role: "user".to_string(),
                content: serde_json::json!({
                    "type": "text",
                    "text": "hello"
                }),
            }],
        };

        let encoded = serde_json::to_string(&prompt).unwrap();
        let decoded: PromptResult = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, prompt);
    }

    #[test]
    fn completion_result_roundtrip() {
        let completion = CompletionResult {
            values: vec!["python".to_string(), "pytorch".to_string()],
            total: Some(10),
            has_more: true,
        };

        let encoded = serde_json::to_string(&completion).unwrap();
        let decoded: CompletionResult = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, completion);
    }

    #[test]
    fn session_auth_context_roundtrip_and_principal_helpers() {
        let auth = SessionAuthContext::streamable_http_static_bearer(
            "static-bearer:abcd1234",
            "cafebabe",
            Some("http://localhost:3000".to_string()),
        );

        assert!(auth.is_authenticated());
        assert_eq!(auth.principal(), Some("static-bearer:abcd1234"));

        let encoded = serde_json::to_string(&auth).unwrap();
        let decoded: SessionAuthContext = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, auth);
    }

    #[test]
    fn anonymous_session_auth_context_has_no_principal() {
        let auth = SessionAuthContext::stdio_anonymous();
        assert!(!auth.is_authenticated());
        assert_eq!(auth.principal(), None);
    }

    #[test]
    fn session_auth_context_helpers_cover_in_process_and_oauth_without_principal() {
        let in_process = SessionAuthContext::in_process_anonymous();
        assert_eq!(in_process.transport, SessionTransport::InProcess);
        assert!(!in_process.is_authenticated());
        assert_eq!(in_process.principal(), None);

        let oauth = SessionAuthContext::streamable_http_oauth_bearer(
            None,
            Some("https://issuer.example".to_string()),
            Some("user-123".to_string()),
            Some("chio-mcp".to_string()),
            vec!["mcp:invoke".to_string()],
            Some("cafebabe".to_string()),
            Some("https://app.example".to_string()),
        );
        assert!(oauth.is_authenticated());
        assert_eq!(oauth.principal(), None);
    }

    #[test]
    fn oauth_session_auth_context_roundtrips_with_federated_claims() {
        let auth = SessionAuthContext::streamable_http_oauth_bearer_with_claims(
            OAuthBearerSessionAuthInput {
                principal: Some("oidc:https://issuer.example#sub:user-123".to_string()),
                issuer: Some("https://issuer.example".to_string()),
                subject: Some("user-123".to_string()),
                audience: Some("chio-mcp".to_string()),
                scopes: vec!["mcp:invoke".to_string()],
                federated_claims: OAuthBearerFederatedClaims {
                    client_id: Some("client-abc".to_string()),
                    object_id: Some("object-123".to_string()),
                    tenant_id: Some("tenant-123".to_string()),
                    organization_id: Some("org-789".to_string()),
                    groups: vec!["eng".to_string(), "ops".to_string()],
                    roles: vec!["operator".to_string()],
                },
                enterprise_identity: Some(EnterpriseIdentityContext {
                    provider_id: "provider-1".to_string(),
                    provider_record_id: Some("provider-1".to_string()),
                    provider_kind: "oidc_jwks".to_string(),
                    federation_method: EnterpriseFederationMethod::Jwt,
                    principal: "oidc:https://issuer.example#sub:user-123".to_string(),
                    subject_key: "subject-key-123".to_string(),
                    client_id: Some("client-abc".to_string()),
                    object_id: Some("object-123".to_string()),
                    tenant_id: Some("tenant-123".to_string()),
                    organization_id: Some("org-789".to_string()),
                    groups: vec!["eng".to_string(), "ops".to_string()],
                    roles: vec!["operator".to_string()],
                    source_subject: Some("user-123".to_string()),
                    attribute_sources: BTreeMap::from([
                        ("principal".to_string(), "sub".to_string()),
                        ("groups".to_string(), "groups".to_string()),
                    ]),
                    trust_material_ref: Some("jwks:primary".to_string()),
                }),
                token_fingerprint: Some("cafebabe".to_string()),
                origin: Some("http://localhost:3000".to_string()),
            },
        );

        assert!(auth.is_authenticated());
        assert_eq!(
            auth.principal(),
            Some("oidc:https://issuer.example#sub:user-123")
        );

        let encoded = serde_json::to_string(&auth).unwrap();
        let decoded: SessionAuthContext = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, auth);
    }

    #[test]
    fn session_anchor_signing_binds_auth_context_and_reference() {
        let kp = Keypair::generate();
        let auth = SessionAuthContext::streamable_http_static_bearer(
            "static-bearer:abcd1234",
            "cafebabe",
            Some("https://app.example".to_string()),
        );
        let proof_binding = SessionProofBinding {
            token_fingerprint: Some("cafebabe".to_string()),
            dpop_public_key_thumbprint: Some("dpop-thumbprint".to_string()),
            mtls_thumbprint_sha256: None,
            runtime_attestation_sha256: None,
        };

        let body = SessionAnchorBody::new(
            "anchor-1",
            SessionAnchorContext::new(
                SessionId::new("sess-001"),
                "agent-123".to_string(),
                auth.clone(),
                Some(proof_binding.clone()),
            ),
            4,
            1_710_000_000,
            kp.public_key(),
        )
        .unwrap();
        let anchor = SessionAnchor::sign(body, &kp).unwrap();
        let reference = anchor.reference().unwrap();

        assert!(anchor.verify_signature().unwrap());
        assert!(anchor.matches_context(&auth, Some(&proof_binding)).unwrap());
        assert_eq!(reference.session_anchor_id, "anchor-1");
        assert!(!reference.session_anchor_hash.is_empty());
        assert_eq!(anchor.auth_context_hash, auth.canonical_hash().unwrap());
        assert_eq!(anchor.auth_method_hash, auth.auth_method_hash().unwrap());
    }

    #[test]
    fn session_anchor_detects_material_auth_context_drift() {
        let kp = Keypair::generate();
        let auth = SessionAuthContext::streamable_http_oauth_bearer(
            Some("oidc:https://issuer.example#sub:user-123".to_string()),
            Some("https://issuer.example".to_string()),
            Some("user-123".to_string()),
            Some("chio-mcp".to_string()),
            vec!["mcp:invoke".to_string()],
            Some("cafebabe".to_string()),
            Some("https://app.example".to_string()),
        );
        let body = SessionAnchorBody::new(
            "anchor-2",
            SessionAnchorContext::new(
                SessionId::new("sess-002"),
                "agent-456".to_string(),
                auth.clone(),
                SessionProofBinding::from_auth_context(&auth),
            ),
            1,
            1_710_000_010,
            kp.public_key(),
        )
        .unwrap();
        let anchor = SessionAnchor::sign(body, &kp).unwrap();
        let changed_auth = SessionAuthContext::streamable_http_oauth_bearer(
            Some("oidc:https://issuer.example#sub:user-123".to_string()),
            Some("https://issuer.example".to_string()),
            Some("user-123".to_string()),
            Some("chio-mcp".to_string()),
            vec!["mcp:invoke".to_string(), "mcp:admin".to_string()],
            Some("cafebabe".to_string()),
            Some("https://app.example".to_string()),
        );
        let changed_binding = SessionProofBinding::from_auth_context(&changed_auth);

        assert!(!anchor
            .matches_context(&changed_auth, changed_binding.as_ref())
            .unwrap());
    }

    #[test]
    fn request_lineage_record_tracks_continuation_and_capability_binding() {
        let record = RequestLineageRecord::new(
            RequestId::new("req-child-1"),
            SessionAnchorReference::new("anchor-1", "anchor-hash-1"),
            OperationKind::ToolCall,
            RequestLineageMode::Continued,
            1_710_000_020,
        )
        .with_parent_request_id(RequestId::new("req-parent-1"))
        .with_capability_attribution("cap-1", "subject-key-1", "issuer-key-1")
        .with_intent_hash("intent-hash-1")
        .with_continuation_token_id("continuation-1");

        let encoded = serde_json::to_string(&record).unwrap();
        let decoded: RequestLineageRecord = serde_json::from_str(&encoded).unwrap();

        assert!(decoded.is_continued());
        assert!(!decoded.is_root());
        assert_eq!(
            decoded.evidence_class,
            crate::capability::ProvenanceEvidenceClass::Verified
        );
        assert_eq!(
            decoded.parent_request_id,
            Some(RequestId::new("req-parent-1"))
        );
        assert_eq!(decoded.capability_id.as_deref(), Some("cap-1"));
        assert_eq!(
            decoded.continuation_token_id.as_deref(),
            Some("continuation-1")
        );
        assert!(decoded.validate_schema().is_ok());
    }

    #[test]
    fn request_lineage_record_rejects_unknown_schema() {
        let mut record = RequestLineageRecord::new(
            RequestId::new("req-schema"),
            SessionAnchorReference::new("anchor-1", "anchor-hash-1"),
            OperationKind::ToolCall,
            RequestLineageMode::LocalChild,
            1_710_000_030,
        );
        record.schema = "chio.request_lineage_record.v999".to_string();

        assert!(record.validate_schema().is_err());
    }

    #[test]
    fn ownership_snapshots_roundtrip_with_expected_defaults() {
        let request = RequestOwnershipSnapshot::request_owned();
        let task = TaskOwnershipSnapshot::task_owned();

        let request_encoded = serde_json::to_string(&request).unwrap();
        let task_encoded = serde_json::to_string(&task).unwrap();

        let request_decoded: RequestOwnershipSnapshot =
            serde_json::from_str(&request_encoded).unwrap();
        let task_decoded: TaskOwnershipSnapshot = serde_json::from_str(&task_encoded).unwrap();

        assert_eq!(request_decoded, request);
        assert_eq!(task_decoded, task);
        assert_eq!(request_decoded.work_owner, WorkOwner::Request);
        assert_eq!(
            request_decoded.result_stream_owner,
            StreamOwner::RequestStream
        );
        assert_eq!(request_decoded.terminal_state_owner, WorkOwner::Request);
        assert_eq!(task_decoded.work_owner, WorkOwner::Task);
        assert_eq!(task_decoded.result_stream_owner, StreamOwner::RequestStream);
        assert_eq!(
            task_decoded.status_notification_owner,
            StreamOwner::SessionNotificationStream
        );
        assert_eq!(task_decoded.terminal_state_owner, WorkOwner::Task);
    }

    #[test]
    fn operation_terminal_state_and_kind_helpers_cover_all_variants() {
        let completed = OperationTerminalState::Completed;
        let cancelled = OperationTerminalState::Cancelled {
            reason: "operator_cancelled".to_string(),
        };
        let incomplete = OperationTerminalState::Incomplete {
            reason: "stream_closed".to_string(),
        };
        assert!(completed.is_completed());
        assert!(!completed.is_cancelled());
        assert!(cancelled.is_cancelled());
        assert!(!cancelled.is_incomplete());
        assert!(incomplete.is_incomplete());

        assert_eq!(OperationKind::ToolCall.as_str(), "tool_call");
        assert_eq!(OperationKind::ReadResource.as_str(), "read_resource");
        assert_eq!(
            OperationKind::ListResourceTemplates.as_str(),
            "list_resource_templates"
        );
        assert_eq!(OperationKind::ListPrompts.as_str(), "list_prompts");
        assert_eq!(OperationKind::GetPrompt.as_str(), "get_prompt");
        assert_eq!(OperationKind::Complete.as_str(), "complete");
    }

    #[test]
    fn chio_identity_assertion_roundtrips_and_validates() {
        let assertion = ChioIdentityAssertion {
            verifier_id: "https://verifier.example.com".to_string(),
            subject: "alice@example.com".to_string(),
            continuity_id: "session-123".to_string(),
            issued_at: 100,
            expires_at: 200,
            provider: Some("oidc".to_string()),
            session_hint: Some("resume".to_string()),
            bound_request_id: Some("req-123".to_string()),
        };

        assertion.validate_at(150).unwrap();

        let encoded = serde_json::to_string(&assertion).unwrap();
        let decoded: ChioIdentityAssertion = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, assertion);
    }

    #[test]
    fn chio_identity_assertion_rejects_stale_or_empty_fields() {
        let stale = ChioIdentityAssertion {
            verifier_id: "https://verifier.example.com".to_string(),
            subject: "alice@example.com".to_string(),
            continuity_id: "session-123".to_string(),
            issued_at: 100,
            expires_at: 110,
            provider: None,
            session_hint: None,
            bound_request_id: None,
        };
        assert!(stale.validate_at(111).unwrap_err().contains("stale"));

        let empty = ChioIdentityAssertion {
            verifier_id: "https://verifier.example.com".to_string(),
            subject: "".to_string(),
            continuity_id: "session-123".to_string(),
            issued_at: 100,
            expires_at: 110,
            provider: None,
            session_hint: None,
            bound_request_id: None,
        };
        assert!(empty
            .validate()
            .unwrap_err()
            .contains("identityAssertion.subject"));
    }

    #[test]
    fn chio_identity_assertion_rejects_remaining_invalid_fields() {
        let mut assertion = ChioIdentityAssertion {
            verifier_id: "https://verifier.example.com".to_string(),
            subject: "alice@example.com".to_string(),
            continuity_id: "session-123".to_string(),
            issued_at: 200,
            expires_at: 100,
            provider: Some("oidc".to_string()),
            session_hint: Some("resume".to_string()),
            bound_request_id: Some("req-123".to_string()),
        };
        assert!(assertion.validate().unwrap_err().contains("issuedAt"));

        assertion = ChioIdentityAssertion {
            verifier_id: "".to_string(),
            subject: "alice@example.com".to_string(),
            continuity_id: "session-123".to_string(),
            issued_at: 100,
            expires_at: 200,
            provider: None,
            session_hint: None,
            bound_request_id: None,
        };
        assert!(assertion.validate().unwrap_err().contains("verifierId"));

        assertion = ChioIdentityAssertion {
            verifier_id: "https://verifier.example.com".to_string(),
            subject: "alice@example.com".to_string(),
            continuity_id: "".to_string(),
            issued_at: 100,
            expires_at: 200,
            provider: None,
            session_hint: None,
            bound_request_id: None,
        };
        assert!(assertion.validate().unwrap_err().contains("continuityId"));

        let mut assertion = ChioIdentityAssertion {
            verifier_id: "https://verifier.example.com".to_string(),
            subject: "alice@example.com".to_string(),
            continuity_id: "session-123".to_string(),
            issued_at: 100,
            expires_at: 200,
            provider: Some(" ".to_string()),
            session_hint: Some("resume".to_string()),
            bound_request_id: Some("req-123".to_string()),
        };
        assert!(assertion.validate().unwrap_err().contains("provider"));
        assertion.provider = Some("oidc".to_string());
        assertion.session_hint = Some(" ".to_string());
        assert!(assertion.validate().unwrap_err().contains("sessionHint"));
        assertion.session_hint = Some("resume".to_string());
        assertion.bound_request_id = Some(" ".to_string());
        assert!(assertion.validate().unwrap_err().contains("boundRequestId"));
    }
}
