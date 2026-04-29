//! Provider-native scaffold for mediating Amazon Bedrock Runtime Converse
//! and ConverseStream tool-use traffic through the Chio kernel.
//!
//! The v1 region is restricted to [`transport::BEDROCK_REGION`] (`us-east-1`).
//! No AWS client is constructed and no network call is made by normal builds.

#![forbid(unsafe_code)]

pub mod adapter;
pub mod iam_principals;
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
pub use transport::{BedrockOperation, Transport, BEDROCK_CONVERSE_API_VERSION, BEDROCK_REGION};

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
    /// AWS region allowed by this scaffold, always [`BEDROCK_REGION`].
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

    /// Chio owner/team label resolved from the signed IAM principal map.
    pub fn principal_owner(&self) -> Option<&str> {
        self.principal_owner.as_deref()
    }

    /// Mapping pattern that authorized the configured IAM principal.
    pub fn matched_iam_principal_pattern(&self) -> Option<&str> {
        self.matched_iam_principal_pattern.as_deref()
    }

    /// Name of the SDK client type pulled in by the workspace pin.
    ///
    /// This references the SDK crate without constructing a client, so the
    /// build proves the dependency resolves while remaining offline.
    pub fn sdk_client_type_name() -> &'static str {
        std::any::type_name::<aws_sdk_bedrockruntime::Client>()
    }
}

/// Adapter-local scaffold errors.
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
    #[error("bedrock converse adapter call site is not implemented: {0}")]
    NotImplemented(&'static str),
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
    fn sdk_pin_is_visible_without_constructing_client() {
        assert!(BedrockAdapter::sdk_client_type_name()
            .contains("aws_sdk_bedrockruntime::client::Client"));
    }

    #[test]
    fn error_display_is_em_dash_free() {
        let cases = vec![
            BedrockAdapterError::UnsupportedRegion {
                requested: "us-west-2".to_string(),
            },
            BedrockAdapterError::UnsupportedApiVersion {
                requested: "bedrock.converse.v2".to_string(),
            },
            BedrockAdapterError::NotImplemented("converse lift"),
        ];
        for err in cases {
            let s = err.to_string();
            assert!(!s.contains('\u{2014}'), "em dash in {s}");
        }
    }
}
