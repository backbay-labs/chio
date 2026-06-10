use std::time::SystemTime;

use chio_core::canonical::canonical_json_bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ProviderId {
    OpenAi,
    Anthropic,
    Bedrock,
    Gemini,
    Mistral,
    Groq,
    Ollama,
    Cohere,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Principal {
    OpenAiOrg {
        org_id: String,
    },
    AnthropicWorkspace {
        workspace_id: String,
    },
    BedrockIam {
        caller_arn: String,
        account_id: String,
        assumed_role_session_arn: Option<String>,
    },
    /// Google Gemini calls are scoped to a Google Cloud project.
    GeminiProject {
        project_id: String,
    },
    /// Groq's OpenAI-compatible API scopes calls to a project.
    GroqProject {
        project_id: String,
    },
    /// Mistral's La Plateforme scopes calls to a project.
    MistralProject {
        project_id: String,
    },
    /// Cohere calls are scoped to an organization.
    CohereOrg {
        org_id: String,
    },
    /// Ollama runs as a local daemon with no upstream identity provider; the
    /// host (or instance label) is the only stable provenance handle.
    OllamaHost {
        host: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvenanceStamp {
    pub provider: ProviderId,
    pub request_id: String,
    pub api_version: String,
    pub principal: Principal,
    pub received_at: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolInvocation {
    pub provider: ProviderId,
    pub tool_name: String,
    /// Canonical-JSON bytes (RFC 8785). Stored as raw bytes so the kernel can
    /// hash without re-serializing.
    pub arguments: Vec<u8>,
    pub provenance: ProvenanceStamp,
}

impl ToolInvocation {
    /// Validate the fabric-level invariants that cannot be expressed by the
    /// public struct shape alone.
    ///
    /// This check is intentionally additive: public fields remain constructible
    /// for compatibility, while adapters and replay consumers can fail closed
    /// before trusting a value that crossed a boundary.
    pub fn validate(&self) -> Result<(), ToolInvocationValidationError> {
        if self.provider != self.provenance.provider {
            return Err(ToolInvocationValidationError::ProviderMismatch {
                invocation: self.provider,
                provenance: self.provenance.provider,
            });
        }
        validate_principal_provider(self.provenance.provider, &self.provenance.principal)?;
        validate_identity_field("tool_name", &self.tool_name)?;
        validate_identity_field("provenance.request_id", &self.provenance.request_id)?;
        validate_identity_field("provenance.api_version", &self.provenance.api_version)?;

        let arguments_value = serde_json::from_slice::<serde_json::Value>(&self.arguments)
            .map_err(|source| ToolInvocationValidationError::InvalidArgumentJson { source })?;
        let canonical = canonical_json_bytes(&arguments_value).map_err(|source| {
            ToolInvocationValidationError::ArgumentCanonicalization {
                message: source.to_string(),
            }
        })?;
        if canonical != self.arguments {
            return Err(ToolInvocationValidationError::NonCanonicalArguments);
        }

        Ok(())
    }
}

fn validate_principal_provider(
    provider: ProviderId,
    principal: &Principal,
) -> Result<(), ToolInvocationValidationError> {
    let matches_provider = matches!(
        (provider, principal),
        (ProviderId::OpenAi, Principal::OpenAiOrg { .. })
            | (ProviderId::Anthropic, Principal::AnthropicWorkspace { .. },)
            | (ProviderId::Bedrock, Principal::BedrockIam { .. })
            | (ProviderId::Gemini, Principal::GeminiProject { .. })
            | (ProviderId::Mistral, Principal::MistralProject { .. })
            | (ProviderId::Groq, Principal::GroqProject { .. })
            | (ProviderId::Ollama, Principal::OllamaHost { .. })
            | (ProviderId::Cohere, Principal::CohereOrg { .. })
    );
    if matches_provider {
        return validate_principal_fields(principal);
    }
    Err(ToolInvocationValidationError::InvalidIdentity {
        field: "provenance.principal",
        reason: "must match provenance.provider",
    })
}

fn validate_principal_fields(principal: &Principal) -> Result<(), ToolInvocationValidationError> {
    match principal {
        Principal::OpenAiOrg { org_id } => {
            validate_identity_field("provenance.principal.org_id", org_id)
        }
        Principal::AnthropicWorkspace { workspace_id } => {
            validate_identity_field("provenance.principal.workspace_id", workspace_id)
        }
        Principal::BedrockIam {
            caller_arn,
            account_id,
            assumed_role_session_arn,
        } => {
            validate_identity_field("provenance.principal.caller_arn", caller_arn)?;
            validate_identity_field("provenance.principal.account_id", account_id)?;
            if let Some(assumed_role_session_arn) = assumed_role_session_arn {
                validate_identity_field(
                    "provenance.principal.assumed_role_session_arn",
                    assumed_role_session_arn,
                )?;
            }
            Ok(())
        }
        Principal::GeminiProject { project_id }
        | Principal::GroqProject { project_id }
        | Principal::MistralProject { project_id } => {
            validate_identity_field("provenance.principal.project_id", project_id)
        }
        Principal::CohereOrg { org_id } => {
            validate_identity_field("provenance.principal.org_id", org_id)
        }
        Principal::OllamaHost { host } => {
            validate_identity_field("provenance.principal.host", host)
        }
    }
}

fn validate_identity_field(
    field: &'static str,
    value: &str,
) -> Result<(), ToolInvocationValidationError> {
    if value.trim().is_empty() {
        return Err(ToolInvocationValidationError::InvalidIdentity {
            field,
            reason: "must not be empty",
        });
    }
    if value.trim() != value {
        return Err(ToolInvocationValidationError::InvalidIdentity {
            field,
            reason: "must not contain surrounding whitespace",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ToolInvocationValidationError::InvalidIdentity {
            field,
            reason: "must not contain control characters",
        });
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum ToolInvocationValidationError {
    #[error(
        "tool invocation provider {invocation:?} did not match provenance provider {provenance:?}"
    )]
    ProviderMismatch {
        invocation: ProviderId,
        provenance: ProviderId,
    },
    #[error("tool invocation arguments were not JSON: {source}")]
    InvalidArgumentJson {
        #[source]
        source: serde_json::Error,
    },
    #[error("tool invocation arguments could not be canonicalized: {message}")]
    ArgumentCanonicalization { message: String },
    #[error("tool invocation arguments were not canonical JSON bytes")]
    NonCanonicalArguments,
    #[error("tool invocation {field} {reason}")]
    InvalidIdentity {
        field: &'static str,
        reason: &'static str,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Redaction {
    pub path: String,
    pub replacement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DenyReason {
    PolicyDeny { rule_id: String },
    GuardDeny { guard_id: String, detail: String },
    CapabilityExpired,
    PrincipalUnknown,
    BudgetExceeded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum VerdictResult {
    Allow {
        redactions: Vec<Redaction>,
        receipt_id: ReceiptId,
    },
    Deny {
        reason: DenyReason,
        receipt_id: ReceiptId,
    },
}
