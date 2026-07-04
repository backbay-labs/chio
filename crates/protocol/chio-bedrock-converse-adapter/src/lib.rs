//! Mediates Amazon Bedrock Runtime Converse and ConverseStream tool-use
//! traffic through the Chio kernel.
//!
//! The v1 region is restricted to [`transport::BEDROCK_REGION`] (`us-east-1`).
//! The live transport ([`transport::AwsSdkTransport`]) calls the Bedrock
//! Runtime Converse operation through the AWS SDK for Rust (SigV4-signed); a
//! recording [`transport::MockTransport`] replays scripted responses for
//! hermetic tests.

#![forbid(unsafe_code)]

pub mod adapter;
pub mod iam_principals;
pub mod loaded_weights;
pub mod native;
pub mod transport;

use std::sync::Arc;

use chio_attest_verify::{AttestVerifier, ExpectedIdentity};
use chio_tool_call_fabric::{Principal, ProviderId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use iam_principals::{
    AwsStsCallerIdentityProvider, BedrockCallerIdentity, IamPrincipalConfigError,
    IamPrincipalMapping, IamPrincipalsConfig, ResolvedBedrockPrincipal,
    DEFAULT_IAM_PRINCIPALS_CONFIG_PATH,
};
pub use native::{ToolConfig, ToolResultBlock, ToolResultStatus, ToolSpec, ToolUseBlock};
pub use transport::{
    AwsSdkTransport, BedrockOperation, ConverseRequest, MockTransport, Transport, TransportError,
    BEDROCK_CONVERSE_API_VERSION, BEDROCK_REGION,
};

/// Configuration for the Bedrock Converse adapter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BedrockAdapterConfig {
    /// Stable identifier for this adapter instance.
    pub server_id: String,
    /// Human-readable name surfaced in logs and manifests.
    pub server_name: String,
    /// Adapter version string, independent of the upstream SDK version.
    pub server_version: String,
    /// Hex-encoded Ed25519 public key for receipt provenance.
    pub public_key: String,
    /// Pinned upstream API surface, always [`BEDROCK_CONVERSE_API_VERSION`].
    pub api_version: String,
    /// AWS region this adapter is pinned to, always [`BEDROCK_REGION`].
    pub region: String,
    /// IAM caller ARN that will populate Bedrock provenance.
    pub caller_arn: String,
    /// AWS account id corresponding to [`Self::caller_arn`].
    pub account_id: String,
    /// Assumed-role session ARN when the caller is an STS session.
    pub assumed_role_session_arn: Option<String>,
}

impl BedrockAdapterConfig {
    /// Construct a configuration pinned to the v1 Bedrock region and API surface.
    pub fn new(
        server_id: impl Into<String>,
        server_name: impl Into<String>,
        server_version: impl Into<String>,
        public_key: impl Into<String>,
        caller_arn: impl Into<String>,
        account_id: impl Into<String>,
    ) -> Self {
        Self {
            server_id: server_id.into(),
            server_name: server_name.into(),
            server_version: server_version.into(),
            public_key: public_key.into(),
            api_version: BEDROCK_CONVERSE_API_VERSION.to_string(),
            region: BEDROCK_REGION.to_string(),
            caller_arn: caller_arn.into(),
            account_id: account_id.into(),
            assumed_role_session_arn: None,
        }
    }

    /// Attach an assumed-role session ARN to the configured Bedrock
    /// principal.
    pub fn with_assumed_role_session_arn(
        mut self,
        assumed_role_session_arn: impl Into<String>,
    ) -> Self {
        self.assumed_role_session_arn = Some(assumed_role_session_arn.into());
        self
    }

    /// Validate that an externally loaded config is still pinned to the
    /// single v1 region and API surface.
    pub fn validate(&self) -> Result<(), BedrockAdapterError> {
        if self.api_version != BEDROCK_CONVERSE_API_VERSION {
            return Err(BedrockAdapterError::UnsupportedApiVersion {
                requested: self.api_version.clone(),
            });
        }
        if self.region != BEDROCK_REGION {
            return Err(BedrockAdapterError::UnsupportedRegion {
                requested: self.region.clone(),
            });
        }
        Ok(())
    }

    /// Convert the configured caller fields into the shared fabric
    /// principal shape.
    pub fn principal(&self) -> Principal {
        Principal::BedrockIam {
            caller_arn: self.caller_arn.clone(),
            account_id: self.account_id.clone(),
            assumed_role_session_arn: self.assumed_role_session_arn.clone(),
        }
    }
}

/// Adapter handle for Bedrock Converse.
#[derive(Clone)]
pub struct BedrockAdapter {
    config: BedrockAdapterConfig,
    transport: Arc<dyn Transport>,
    principal_owner: Option<String>,
    matched_iam_principal_pattern: Option<String>,
}

impl BedrockAdapter {
    /// Build a new adapter from config and transport, rejecting configs that
    /// drift from the v1 `us-east-1` pin.
    pub fn new(
        config: BedrockAdapterConfig,
        transport: Arc<dyn Transport>,
    ) -> Result<Self, BedrockAdapterError> {
        config.validate()?;
        if transport.region() != BEDROCK_REGION {
            return Err(BedrockAdapterError::UnsupportedRegion {
                requested: transport.region().to_string(),
            });
        }
        Ok(Self {
            config,
            transport,
            principal_owner: None,
            matched_iam_principal_pattern: None,
        })
    }

    /// Build a new adapter by loading a signed IAM principal map and
    /// resolving the caller identity before any tool traffic can be lifted.
    pub fn new_with_signed_iam_principals_config(
        mut config: BedrockAdapterConfig,
        transport: Arc<dyn Transport>,
        caller_identity: BedrockCallerIdentity,
        iam_principals_path: impl AsRef<std::path::Path>,
        verifier: &dyn AttestVerifier,
        expected_identity: &ExpectedIdentity,
    ) -> Result<Self, BedrockAdapterError> {
        config.validate()?;
        if transport.region() != BEDROCK_REGION {
            return Err(BedrockAdapterError::UnsupportedRegion {
                requested: transport.region().to_string(),
            });
        }

        let iam_config = IamPrincipalsConfig::load_signed_from_path(
            iam_principals_path,
            verifier,
            expected_identity,
        )?;
        let resolved = iam_config.resolve(&caller_identity)?;

        config.caller_arn = resolved.caller_arn.clone();
        config.account_id = resolved.account_id.clone();
        config.assumed_role_session_arn = resolved.assumed_role_session_arn.clone();

        Ok(Self {
            config,
            transport,
            principal_owner: Some(resolved.owner),
            matched_iam_principal_pattern: Some(resolved.matched_pattern),
        })
    }

    /// Resolve STS identity once per process, then initialize from the
    /// signed IAM principal config.
    pub async fn new_with_signed_iam_principals_config_from_sts(
        config: BedrockAdapterConfig,
        transport: Arc<dyn Transport>,
        sts_provider: &AwsStsCallerIdentityProvider,
        iam_principals_path: impl AsRef<std::path::Path>,
        verifier: &dyn AttestVerifier,
        expected_identity: &ExpectedIdentity,
    ) -> Result<Self, BedrockAdapterError> {
        let caller_identity = sts_provider.get_caller_identity_once().await?;
        Self::new_with_signed_iam_principals_config(
            config,
            transport,
            caller_identity,
            iam_principals_path,
            verifier,
            expected_identity,
        )
    }

    /// Provider identifier for this adapter.
    pub fn provider(&self) -> ProviderId {
        ProviderId::Bedrock
    }

    /// Pinned upstream API surface.
    pub fn api_version(&self) -> &str {
        &self.config.api_version
    }

    /// Pinned AWS region.
    pub fn region(&self) -> &str {
        &self.config.region
    }

    /// Borrow the configuration.
    pub fn config(&self) -> &BedrockAdapterConfig {
        &self.config
    }

    /// Borrow the transport handle.
    pub fn transport(&self) -> &Arc<dyn Transport> {
        &self.transport
    }

    /// Run one batch Bedrock Runtime Converse turn through the transport and
    /// lift every `toolUse` block in the response into the shared fabric
    /// [`ToolInvocation`](chio_tool_call_fabric::ToolInvocation) shape.
    ///
    /// Transport-layer failures (throttling, upstream 5xx, timeout, rejected
    /// request) are mapped into the adapter-visible
    /// [`chio_tool_call_fabric::ProviderError`] taxonomy and fail closed before
    /// any invocation is produced.
    pub async fn converse(
        &self,
        request: transport::ConverseRequest,
    ) -> Result<Vec<chio_tool_call_fabric::ToolInvocation>, chio_tool_call_fabric::ProviderError>
    {
        let body = self
            .transport
            .converse(&request)
            .await
            .map_err(map_transport_error)?;
        self.lift_batch(chio_tool_call_fabric::ProviderRequest(body))
    }

    /// Chio owner/team label resolved from the signed IAM principal map.
    pub fn principal_owner(&self) -> Option<&str> {
        self.principal_owner.as_deref()
    }

    /// Mapping pattern that authorized the configured IAM principal.
    pub fn matched_iam_principal_pattern(&self) -> Option<&str> {
        self.matched_iam_principal_pattern.as_deref()
    }
}

impl chio_provider_adapter_core::Provider for BedrockAdapter {
    fn provider_id(&self) -> ProviderId {
        self.provider()
    }

    fn api_version(&self) -> &str {
        self.api_version()
    }
}

/// Adapter-local configuration and transport errors.
#[derive(Debug, Error)]
pub enum BedrockAdapterError {
    #[error("bedrock converse adapter supports only us-east-1 in v1; requested {requested}")]
    UnsupportedRegion { requested: String },
    #[error(
        "bedrock converse adapter supports only bedrock.converse.v1 in v1; requested {requested}"
    )]
    UnsupportedApiVersion { requested: String },
    #[error(transparent)]
    Transport(#[from] transport::TransportError),
    #[error(transparent)]
    IamPrincipals(#[from] iam_principals::IamPrincipalConfigError),
}

/// Map a wire-level [`transport::TransportError`] into the adapter-visible
/// fabric [`ProviderError`](chio_tool_call_fabric::ProviderError) taxonomy.
fn map_transport_error(error: transport::TransportError) -> chio_tool_call_fabric::ProviderError {
    use chio_tool_call_fabric::ProviderError;
    use transport::TransportError;

    match error {
        TransportError::RateLimited { retry_after_ms } => {
            ProviderError::RateLimited { retry_after_ms }
        }
        TransportError::Timeout { ms } => ProviderError::TransportTimeout { ms },
        TransportError::Upstream { status, message } => ProviderError::Upstream5xx {
            status,
            body: message,
        },
        TransportError::Rejected(detail)
        | TransportError::MalformedRequest(detail)
        | TransportError::DecodeResponse(detail) => ProviderError::Malformed(detail),
        other => ProviderError::Malformed(other.to_string()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn config() -> BedrockAdapterConfig {
        BedrockAdapterConfig::new(
            "bedrock-1",
            "Bedrock Converse",
            "0.1.0",
            "deadbeef",
            "arn:aws:iam::123456789012:role/ChioAgentRole",
            "123456789012",
        )
    }

    #[test]
    fn config_pins_region_and_api_version() {
        let cfg = config();
        assert_eq!(cfg.region, BEDROCK_REGION);
        assert_eq!(cfg.region, "us-east-1");
        assert_eq!(cfg.api_version, BEDROCK_CONVERSE_API_VERSION);
    }

    #[test]
    fn adapter_reports_provider_pin_and_region() {
        let cfg = config();
        let transport = transport::MockTransport::new();
        let adapter = BedrockAdapter::new(cfg, Arc::new(transport)).unwrap();
        assert_eq!(adapter.provider(), ProviderId::Bedrock);
        assert_eq!(adapter.api_version(), "bedrock.converse.v1");
        assert_eq!(adapter.region(), "us-east-1");
    }

    #[test]
    fn config_rejects_non_us_east_1() {
        let mut cfg = config();
        cfg.region = "us-west-2".to_string();
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, BedrockAdapterError::UnsupportedRegion { .. }));
    }

    #[test]
    fn config_rejects_unknown_api_version() {
        let mut cfg = config();
        cfg.api_version = "bedrock.converse.v2".to_string();
        let err = cfg.validate().unwrap_err();
        assert!(matches!(
            err,
            BedrockAdapterError::UnsupportedApiVersion { .. }
        ));
    }

    #[test]
    fn principal_uses_bedrock_iam_shape() {
        let cfg = config().with_assumed_role_session_arn(
            "arn:aws:sts::123456789012:assumed-role/ChioAgentRole/session-1",
        );
        let principal = cfg.principal();
        assert!(matches!(
            principal,
            Principal::BedrockIam {
                caller_arn,
                account_id,
                assumed_role_session_arn: Some(_),
            } if caller_arn == "arn:aws:iam::123456789012:role/ChioAgentRole"
                && account_id == "123456789012"
        ));
    }

    #[test]
    fn config_round_trips_json() {
        let cfg = config();
        let bytes = serde_json::to_vec(&cfg).unwrap();
        let back: BedrockAdapterConfig = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(cfg, back);
    }
    #[test]
    fn transport_error_maps_into_fabric_taxonomy() {
        use chio_tool_call_fabric::ProviderError;

        assert!(matches!(
            map_transport_error(transport::TransportError::RateLimited {
                retry_after_ms: 1000
            }),
            ProviderError::RateLimited {
                retry_after_ms: 1000
            }
        ));
        assert!(matches!(
            map_transport_error(transport::TransportError::Timeout { ms: 30000 }),
            ProviderError::TransportTimeout { ms: 30000 }
        ));
        assert!(matches!(
            map_transport_error(transport::TransportError::Upstream {
                status: 500,
                message: "boom".to_string(),
            }),
            ProviderError::Upstream5xx { status: 500, .. }
        ));
        assert!(matches!(
            map_transport_error(transport::TransportError::Rejected("bad".to_string())),
            ProviderError::Malformed(_)
        ));
    }
}
