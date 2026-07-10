use alloc::string::{String, ToString};

use serde::{Deserialize, Serialize};

use crate::crypto::{canonical_json_bytes, sha256_hex, Keypair, PublicKey, Signature};
use crate::error::Result;
use crate::schema_binding::ensure_schema_matches;
use crate::signer_binding::ensure_keypair_matches_embedded_key;
use crate::AgentId;

use super::auth::SessionAuthContext;
use super::identifiers::SessionId;

/// Versioned schema identifier for signed session anchors.
pub const CHIO_SESSION_ANCHOR_SCHEMA: &str = "chio.session_anchor.v1";
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
