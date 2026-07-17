//! # chio-manifest
//!
//! Tool server manifest format for the Chio protocol. A manifest declares what
//! tools a server provides, what arguments they accept, and what permissions
//! they require. Manifests are signed by the tool server's Ed25519 key and
//! verified by the Runtime Kernel before the server is admitted.
//!
//! The manifest serves two purposes:
//!
//! 1. **Discovery**: the kernel learns what tools are available and their schemas.
//! 2. **Trust**: the kernel verifies the manifest signature against the server's
//!    registered public key, preventing a compromised server from advertising
//!    tools it should not expose.

#![forbid(unsafe_code)]

use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::{Keypair, PublicKey, Signature};
use serde::{Deserialize, Serialize};

mod validation;
pub use validation::validate_manifest;

/// Supported Chio tool-manifest schema identifier.
pub const TOOL_MANIFEST_SCHEMA: &str = "chio.manifest.v1";

/// A signed declaration of the tools a Chio tool server provides.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolManifest {
    /// Schema version. Must equal [`TOOL_MANIFEST_SCHEMA`].
    pub schema: String,

    /// The server's unique identifier.
    pub server_id: chio_core::ServerId,

    /// Human-readable server name.
    pub name: String,

    /// Server description.
    pub description: Option<String>,

    /// Semantic version of this tool server.
    pub version: String,

    /// The tools this server provides.
    pub tools: Vec<ToolDefinition>,

    /// Provider-native server tools this manifest explicitly allows.
    ///
    /// Anthropic server tools are larger trust-boundary surfaces than regular
    /// client-hosted tools. They default to deny unless the manifest lists the
    /// stable logical tool name here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub server_tools: Vec<ServerTool>,

    /// Permissions this server requires from the host environment
    /// (filesystem paths, network access, environment variables, etc.).
    pub required_permissions: Option<RequiredPermissions>,

    /// Hex-encoded Ed25519 public key of this tool server.
    pub public_key: String,
}

impl ToolManifest {
    /// Return whether a provider-native server tool is explicitly allowlisted.
    pub fn allows_server_tool(&self, server_tool: ServerTool) -> bool {
        self.server_tools.contains(&server_tool)
    }

    /// Whether the named tool is annotated as having no side effects. A tool
    /// absent from the manifest reads as NOT read-only: only a positive
    /// annotation may exempt a call from side-effect handling, so unknown
    /// tools keep the fail-safe side-effecting classification.
    pub fn tool_is_read_only(&self, tool_name: &str) -> bool {
        self.tools
            .iter()
            .find(|tool| tool.name == tool_name)
            .is_some_and(|tool| !tool.has_side_effects)
    }
}

/// Provider-native server tools that require manifest allowlisting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerTool {
    /// Anthropic `computer_use_*` server tool.
    ComputerUse,
    /// Anthropic `bash_*` server tool.
    Bash,
    /// Anthropic `text_editor_*` server tool.
    TextEditor,
}

impl ServerTool {
    /// Stable manifest spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            ServerTool::ComputerUse => "computer_use",
            ServerTool::Bash => "bash",
            ServerTool::TextEditor => "text_editor",
        }
    }

    /// Map Anthropic server-tool wire names to stable manifest entries.
    ///
    /// Anthropic versions server-tool names with a trailing date, for example
    /// `bash_20241022`. Treat known categories as server tools so version bumps
    /// stay fail-closed behind the same allowlist entry.
    pub fn from_anthropic_wire_name(name: &str) -> Option<Self> {
        if name == "computer_use" || has_anthropic_date_suffix(name, "computer_use_") {
            Some(ServerTool::ComputerUse)
        } else if name == "bash" || has_anthropic_date_suffix(name, "bash_") {
            Some(ServerTool::Bash)
        } else if name == "text_editor" || has_anthropic_date_suffix(name, "text_editor_") {
            Some(ServerTool::TextEditor)
        } else {
            None
        }
    }
}

fn has_anthropic_date_suffix(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .is_some_and(|suffix| suffix.len() == 8 && suffix.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Definition of a single tool within a manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolDefinition {
    /// Tool name (unique within this server).
    pub name: String,

    /// Human-readable description.
    pub description: String,

    /// JSON Schema for the tool's input arguments.
    pub input_schema: serde_json::Value,

    /// JSON Schema for the tool's output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,

    /// Optional advertised pricing metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pricing: Option<ToolPricing>,

    /// Whether this tool has side effects (writes files, sends network
    /// requests, modifies state). Read-only tools can be cached.
    pub has_side_effects: bool,

    /// Estimated execution time category.
    pub latency_hint: Option<LatencyHint>,
}

/// Optional pricing metadata advertised by a tool server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolPricing {
    pub pricing_model: PricingModel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_price: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit_price: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing_unit: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PricingModel {
    Flat,
    PerInvocation,
    PerUnit,
    Hybrid,
}

/// Permissions that a tool server requires from its sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredPermissions {
    /// Filesystem paths the server needs to read.
    pub read_paths: Option<Vec<String>>,

    /// Filesystem paths the server needs to write.
    pub write_paths: Option<Vec<String>>,

    /// Network hosts the server needs to reach.
    pub network_hosts: Option<Vec<String>>,

    /// Environment variables the server reads.
    pub environment_variables: Option<Vec<String>>,
}

/// Hint about how long a tool invocation typically takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LatencyHint {
    /// Sub-millisecond (in-memory computation).
    #[serde(rename = "instant")]
    Instant,

    /// Milliseconds (local I/O, database queries).
    #[serde(rename = "fast")]
    Fast,

    /// Seconds (network calls, API requests).
    #[serde(rename = "moderate")]
    Moderate,

    /// Minutes or more (long-running computation, large file operations).
    #[serde(rename = "slow")]
    Slow,
}

/// A manifest wrapped in its Ed25519 signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedManifest {
    /// The tool manifest.
    pub manifest: ToolManifest,

    /// Ed25519 signature over the canonical JSON encoding of `manifest`.
    pub signature: Signature,

    /// The signing key (for verification without out-of-band lookup).
    pub signer_key: PublicKey,
}

/// Errors specific to manifest operations.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("signing error: {0}")]
    Signing(#[from] chio_core::Error),

    #[error("manifest contains no tools")]
    EmptyManifest,

    #[error("duplicate tool name: {0}")]
    DuplicateToolName(String),

    #[error("invalid tool name: {0}")]
    InvalidToolName(String),

    #[error("invalid manifest field: {0}")]
    InvalidManifestField(&'static str),

    #[error("tool input schema is not a JSON object: {0}")]
    InvalidInputSchema(String),

    #[error("tool output schema is not a JSON object: {0}")]
    InvalidOutputSchema(String),

    #[error("duplicate server tool allowlist entry: {0}")]
    DuplicateServerTool(String),

    #[error("invalid required permission {field}: {value}")]
    InvalidRequiredPermission { field: &'static str, value: String },

    #[error("duplicate required permission {field}: {value}")]
    DuplicateRequiredPermission { field: &'static str, value: String },

    #[error("manifest schema version is not supported: {0}")]
    UnsupportedSchema(String),

    #[error("signature verification failed")]
    VerificationFailed,
}

/// Sign a manifest with an Ed25519 keypair.
pub fn sign_manifest(
    manifest: &ToolManifest,
    keypair: &Keypair,
) -> Result<SignedManifest, ManifestError> {
    validate_manifest(manifest)?;
    let signer_key = keypair.public_key();
    ensure_embedded_public_key_matches(manifest, &signer_key)?;
    let (signature, _bytes) = keypair.sign_canonical(manifest)?;
    Ok(SignedManifest {
        manifest: manifest.clone(),
        signature,
        signer_key,
    })
}

/// Verify a signed manifest against a known public key.
pub fn verify_manifest(
    signed: &SignedManifest,
    public_key: &PublicKey,
) -> Result<(), ManifestError> {
    validate_manifest(&signed.manifest)?;
    ensure_embedded_public_key_matches(&signed.manifest, &signed.signer_key)?;
    if signed.signer_key != *public_key {
        return Err(ManifestError::VerificationFailed);
    }
    let valid = public_key.verify_canonical(&signed.manifest, &signed.signature)?;
    if valid {
        Ok(())
    } else {
        Err(ManifestError::VerificationFailed)
    }
}

fn ensure_embedded_public_key_matches(
    manifest: &ToolManifest,
    signer_key: &PublicKey,
) -> Result<(), ManifestError> {
    let embedded_key = embedded_public_key(manifest)?;
    if embedded_key == *signer_key {
        Ok(())
    } else {
        Err(ManifestError::VerificationFailed)
    }
}

fn embedded_public_key(manifest: &ToolManifest) -> Result<PublicKey, ManifestError> {
    PublicKey::from_hex(&manifest.public_key).map_err(|_| ManifestError::VerificationFailed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_core::crypto::Keypair;

    fn sample_manifest() -> ToolManifest {
        ToolManifest {
            schema: TOOL_MANIFEST_SCHEMA.into(),
            server_id: "srv-hello".into(),
            name: "Hello Tool Server".into(),
            description: Some("A demo tool server".into()),
            version: "0.1.0".into(),
            tools: vec![ToolDefinition {
                name: "greet".into(),
                description: "Returns a greeting".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" }
                    },
                    "required": ["name"]
                }),
                output_schema: None,
                pricing: Some(ToolPricing {
                    pricing_model: PricingModel::PerInvocation,
                    base_price: None,
                    unit_price: Some(MonetaryAmount {
                        units: 50,
                        currency: "USD".to_string(),
                    }),
                    billing_unit: Some("invocation".into()),
                }),
                has_side_effects: false,
                latency_hint: Some(LatencyHint::Instant),
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: Keypair::from_seed(&[7u8; 32]).public_key().to_hex(),
        }
    }

    #[test]
    fn validate_valid_manifest() {
        let m = sample_manifest();
        validate_manifest(&m).unwrap_or_else(|e| panic!("validation: {e}"));
    }

    #[test]
    fn validate_empty_manifest() {
        let mut m = sample_manifest();
        m.tools.clear();
        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::EmptyManifest)
        ));
    }

    #[test]
    fn validate_duplicate_tool_name() {
        let mut m = sample_manifest();
        let tool = m.tools[0].clone();
        m.tools.push(tool);
        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::DuplicateToolName(_))
        ));
    }

    #[test]
    fn validate_rejects_padded_tool_name() {
        let mut m = sample_manifest();
        m.tools[0].name = " greet".into();

        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::InvalidToolName(_))
        ));
    }

    #[test]
    fn validate_allows_unsigned_demo_public_key() {
        let mut m = sample_manifest();
        m.public_key = "hello-a2a-manifest".into();

        validate_manifest(&m).unwrap_or_else(|e| panic!("validation: {e}"));
    }

    #[test]
    fn validate_rejects_blank_manifest_identity() {
        let mut m = sample_manifest();
        m.server_id = " ".into();

        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::InvalidManifestField("server_id"))
        ));
    }

    #[test]
    fn validate_rejects_padded_manifest_identity() {
        let mut m = sample_manifest();
        m.version = " 0.1.0".into();

        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::InvalidManifestField("version"))
        ));
    }

    #[test]
    fn validate_rejects_manifest_identity_control_characters() {
        let mut m = sample_manifest();
        m.server_id = "srv-hello\nbad".into();

        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::InvalidManifestField("server_id"))
        ));
    }

    #[test]
    fn validate_rejects_tool_name_control_characters() {
        let mut m = sample_manifest();
        m.tools[0].name = "greet\nbad".into();

        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::InvalidToolName(_))
        ));
    }

    #[test]
    fn validate_rejects_non_object_input_schema() {
        let mut m = sample_manifest();
        m.tools[0].input_schema = serde_json::json!(["not", "an", "object"]);

        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::InvalidInputSchema(tool)) if tool == "greet"
        ));
    }

    #[test]
    fn validate_rejects_non_object_output_schema() {
        let mut m = sample_manifest();
        m.tools[0].output_schema = Some(serde_json::json!("not an object"));

        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::InvalidOutputSchema(tool)) if tool == "greet"
        ));
    }

    #[test]
    fn validate_rejects_empty_required_permission_entry() {
        let mut m = sample_manifest();
        m.required_permissions = Some(RequiredPermissions {
            read_paths: Some(vec![String::new()]),
            write_paths: None,
            network_hosts: None,
            environment_variables: None,
        });

        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::InvalidRequiredPermission {
                field: "required_permissions.read_paths",
                ..
            })
        ));
    }

    #[test]
    fn validate_rejects_duplicate_required_permission_entry() {
        let mut m = sample_manifest();
        m.required_permissions = Some(RequiredPermissions {
            read_paths: None,
            write_paths: None,
            network_hosts: Some(vec!["api.example.com".into(), "api.example.com".into()]),
            environment_variables: None,
        });

        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::DuplicateRequiredPermission {
                field: "required_permissions.network_hosts",
                value,
            }) if value == "api.example.com"
        ));
    }

    #[test]
    fn validate_rejects_required_permission_control_characters() {
        let mut m = sample_manifest();
        m.required_permissions = Some(RequiredPermissions {
            read_paths: Some(vec!["/tmp/in\nbad".into()]),
            write_paths: None,
            network_hosts: None,
            environment_variables: None,
        });

        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::InvalidRequiredPermission {
                field: "required_permissions.read_paths",
                ..
            })
        ));
    }

    #[test]
    fn validate_rejects_per_invocation_pricing_without_unit_price() {
        let mut m = sample_manifest();
        m.tools[0].pricing.as_mut().unwrap().unit_price = None;

        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::InvalidManifestField(
                "tools.pricing.unit_price"
            ))
        ));
    }

    #[test]
    fn validate_rejects_hybrid_pricing_without_base_price() {
        let mut m = sample_manifest();
        let pricing = m.tools[0].pricing.as_mut().unwrap();
        pricing.pricing_model = PricingModel::Hybrid;
        pricing.base_price = None;
        pricing.unit_price = Some(MonetaryAmount {
            units: 10,
            currency: "USD".to_string(),
        });
        pricing.billing_unit = Some("document".to_string());

        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::InvalidManifestField(
                "tools.pricing.base_price"
            ))
        ));
    }

    #[test]
    fn validate_rejects_padded_pricing_billing_unit() {
        let mut m = sample_manifest();
        m.tools[0].pricing.as_mut().unwrap().billing_unit = Some(" invocation".to_string());

        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::InvalidManifestField(
                "tools.pricing.billing_unit"
            ))
        ));
    }

    #[test]
    fn validate_rejects_invalid_pricing_currency() {
        let mut m = sample_manifest();
        m.tools[0]
            .pricing
            .as_mut()
            .unwrap()
            .unit_price
            .as_mut()
            .unwrap()
            .currency = "usd".to_string();

        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::InvalidManifestField(
                "tools.pricing.currency"
            ))
        ));
    }

    #[test]
    fn sign_and_verify_manifest() {
        let kp = Keypair::generate();

        let mut m = sample_manifest();
        m.public_key = kp.public_key().to_hex();
        let signed = sign_manifest(&m, &kp).unwrap_or_else(|e| panic!("sign: {e}"));
        verify_manifest(&signed, &kp.public_key()).unwrap_or_else(|e| panic!("verify: {e}"));
    }

    #[test]
    fn sign_manifest_rejects_mismatched_embedded_public_key() {
        let signer = Keypair::generate();
        let other = Keypair::generate();
        let mut m = sample_manifest();
        m.public_key = other.public_key().to_hex();

        assert!(matches!(
            sign_manifest(&m, &signer),
            Err(ManifestError::VerificationFailed)
        ));
    }

    #[test]
    fn sign_manifest_rejects_invalid_embedded_public_key() {
        let signer = Keypair::generate();
        let mut m = sample_manifest();
        m.public_key = "not-a-public-key".into();

        assert!(matches!(
            sign_manifest(&m, &signer),
            Err(ManifestError::VerificationFailed)
        ));
    }

    #[test]
    fn verify_manifest_rejects_mismatched_embedded_public_key() {
        let trusted = Keypair::generate();
        let other = Keypair::generate();
        let mut m = sample_manifest();
        m.public_key = other.public_key().to_hex();
        let (signature, _bytes) = trusted
            .sign_canonical(&m)
            .unwrap_or_else(|e| panic!("sign: {e}"));
        let signed = SignedManifest {
            manifest: m,
            signature,
            signer_key: trusted.public_key(),
        };

        assert!(matches!(
            verify_manifest(&signed, &trusted.public_key()),
            Err(ManifestError::VerificationFailed)
        ));
    }

    #[test]
    fn verify_manifest_rejects_invalid_embedded_public_key() {
        let trusted = Keypair::generate();
        let mut m = sample_manifest();
        m.public_key = "not-a-public-key".into();
        let (signature, _bytes) = trusted
            .sign_canonical(&m)
            .unwrap_or_else(|e| panic!("sign: {e}"));
        let signed = SignedManifest {
            manifest: m,
            signature,
            signer_key: trusted.public_key(),
        };

        assert!(matches!(
            verify_manifest(&signed, &trusted.public_key()),
            Err(ManifestError::VerificationFailed)
        ));
    }

    #[test]
    fn verify_manifest_rejects_mismatched_signed_signer_key() {
        let trusted = Keypair::generate();
        let other = Keypair::generate();

        let mut m = sample_manifest();
        m.public_key = trusted.public_key().to_hex();
        let mut signed = sign_manifest(&m, &trusted).unwrap_or_else(|e| panic!("sign: {e}"));
        signed.signer_key = other.public_key();

        assert!(matches!(
            verify_manifest(&signed, &trusted.public_key()),
            Err(ManifestError::VerificationFailed)
        ));
    }

    #[test]
    fn signed_manifest_rejects_unknown_envelope_fields() {
        let kp = Keypair::generate();
        let mut m = sample_manifest();
        m.public_key = kp.public_key().to_hex();
        let signed = sign_manifest(&m, &kp).unwrap_or_else(|e| panic!("sign: {e}"));
        let mut encoded =
            serde_json::to_value(&signed).unwrap_or_else(|e| panic!("encode signed manifest: {e}"));
        encoded
            .as_object_mut()
            .unwrap_or_else(|| panic!("signed manifest encodes as object"))
            .insert("unsigned_policy_hint".to_string(), serde_json::json!(true));

        let error = serde_json::from_value::<SignedManifest>(encoded).unwrap_err();

        assert!(
            error.to_string().contains("unknown field"),
            "expected unknown-field parse error, got {error}"
        );
    }

    #[test]
    fn required_permissions_reject_unknown_fields() {
        let result = serde_json::from_value::<RequiredPermissions>(serde_json::json!({
            "read_paths": ["/tmp"],
            "extra_permission": true
        }));
        assert!(result.is_err());
    }

    #[test]
    fn event_permissions_reject_until_event_actions_land() {
        let result = serde_json::from_value::<RequiredPermissions>(serde_json::json!({
            "event_publish": [{"broker_kind": "kafka"}]
        }));
        assert!(result.is_err());
    }
}
