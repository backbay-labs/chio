//! Signed IAM principal mapping loader for the Bedrock Converse adapter.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use chio_attest_verify::{AttestVerifier, ExpectedIdentity};
use chio_tool_call_fabric::Principal;
use serde::Deserialize;
use thiserror::Error;

/// Default IAM principal map loaded by production adapter initialization.
pub const DEFAULT_IAM_PRINCIPALS_CONFIG_PATH: &str = "config/iam_principals.toml";

const SIGSTORE_BUNDLE_SUFFIX: &str = ".sigstore-bundle.json";
const SUPPORTED_CONFIG_VERSION: u8 = 1;
const DENY_ACTION: &str = "deny";
const ASSUMED_ROLE_PREFIX: &str = "assumed-role/";

static PROCESS_STS_IDENTITY: OnceLock<BedrockCallerIdentity> = OnceLock::new();

/// STS `GetCallerIdentity` material used to resolve a Bedrock caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BedrockCallerIdentity {
    /// ARN returned by STS. For assumed roles this is the session ARN.
    pub arn: String,
    /// AWS account id returned by STS.
    pub account_id: String,
}

impl BedrockCallerIdentity {
    /// Build a caller identity from STS output.
    pub fn new(arn: impl Into<String>, account_id: impl Into<String>) -> Self {
        Self {
            arn: arn.into(),
            account_id: account_id.into(),
        }
    }
}

/// AWS STS identity source. The resolved identity is cached process-wide.
#[derive(Debug, Clone)]
pub struct AwsStsCallerIdentityProvider {
    client: aws_sdk_sts::Client,
}

impl AwsStsCallerIdentityProvider {
    /// Wrap an AWS SDK STS client supplied by the caller.
    pub fn new(client: aws_sdk_sts::Client) -> Self {
        Self { client }
    }

    /// Resolve `GetCallerIdentity` once per process.
    pub async fn get_caller_identity_once(
        &self,
    ) -> Result<BedrockCallerIdentity, IamPrincipalConfigError> {
        if let Some(identity) = PROCESS_STS_IDENTITY.get() {
            return Ok(identity.clone());
        }

        let output = self
            .client
            .get_caller_identity()
            .send()
            .await
            .map_err(|source| IamPrincipalConfigError::CallerIdentity {
                detail: source.to_string(),
            })?;
        let arn = output
            .arn()
            .ok_or_else(|| IamPrincipalConfigError::CallerIdentity {
                detail: "STS GetCallerIdentity response omitted arn".to_string(),
            })?;
        let account_id =
            output
                .account()
                .ok_or_else(|| IamPrincipalConfigError::CallerIdentity {
                    detail: "STS GetCallerIdentity response omitted account".to_string(),
                })?;
        let identity = BedrockCallerIdentity::new(arn, account_id);

        match PROCESS_STS_IDENTITY.set(identity.clone()) {
            Ok(()) => Ok(identity),
            Err(candidate) => Ok(PROCESS_STS_IDENTITY.get().cloned().unwrap_or(candidate)),
        }
    }
}

/// Parsed signed `config/iam_principals.toml` contents.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IamPrincipalsConfig {
    /// Schema version. v1 is the only accepted schema.
    pub config_version: u8,
    /// Fail-closed default action. v1 accepts only `deny`.
    pub default_action: String,
    /// Ordered mapping list. First match wins.
    #[serde(default)]
    pub mapping: Vec<IamPrincipalMapping>,
}

/// One ordered IAM ARN mapping entry.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IamPrincipalMapping {
    /// Exact ARN or `*` wildcard pattern.
    #[serde(rename = "match")]
    pub match_pattern: String,
    /// Chio owner/team label for the matching caller.
    pub owner: String,
    /// Optional operator notes.
    #[serde(default)]
    pub notes: Option<String>,
}

/// Principal material resolved from a signed mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedBedrockPrincipal {
    /// Chio owner/team label from the matched mapping.
    pub owner: String,
    /// Canonical caller ARN used in fabric provenance.
    pub caller_arn: String,
    /// AWS account id.
    pub account_id: String,
    /// Original STS assumed-role session ARN, when present.
    pub assumed_role_session_arn: Option<String>,
    /// Mapping pattern that authorized this caller.
    pub matched_pattern: String,
}

impl ResolvedBedrockPrincipal {
    /// Convert to the shared fabric principal shape.
    pub fn principal(&self) -> Principal {
        Principal::BedrockIam {
            caller_arn: self.caller_arn.clone(),
            account_id: self.account_id.clone(),
            assumed_role_session_arn: self.assumed_role_session_arn.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct NormalizedCaller {
    caller_arn: String,
    account_id: String,
    assumed_role_session_arn: Option<String>,
    match_arns: Vec<String>,
}

/// Errors surfaced by signed IAM principal loading and resolution.
#[derive(Debug, Error)]
pub enum IamPrincipalConfigError {
    /// The required config file was absent.
    #[error("iam principals config missing: {path}")]
    MissingConfig { path: String },
    /// The required adjacent Sigstore bundle was absent.
    #[error("iam principals config unsigned: missing Sigstore bundle {path}")]
    Unsigned { path: String },
    /// Any non-not-found filesystem failure.
    #[error("iam principals config io error at {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    /// The Sigstore verifier rejected the config bytes.
    #[error("iam principals config signature rejected: {detail}")]
    SignatureRejected { detail: String },
    /// The TOML bytes were not UTF-8.
    #[error("iam principals config is not UTF-8: {source}")]
    Utf8 { source: std::str::Utf8Error },
    /// TOML syntax or type error.
    #[error("iam principals config TOML parse failed in {path}: {source}")]
    Toml {
        path: String,
        source: toml::de::Error,
    },
    /// Schema or semantic validation error.
    #[error("invalid iam principals config: {0}")]
    Invalid(String),
    /// STS identity lookup failed or returned incomplete data.
    #[error("bedrock STS caller identity failed: {detail}")]
    CallerIdentity { detail: String },
    /// The caller identity was malformed.
    #[error("invalid bedrock caller identity: {0}")]
    InvalidCallerIdentity(String),
    /// No mapping matched the resolved caller.
    #[error(
        "bedrock IAM principal is unmapped: caller {caller_arn}, assumed-role session {assumed_role_session_arn}"
    )]
    PrincipalUnknown {
        caller_arn: String,
        assumed_role_session_arn: String,
    },
}

impl IamPrincipalsConfig {
    /// Load and verify a signed IAM principal config from disk.
    ///
    /// The Sigstore bundle must live next to the TOML file as
    /// `<filename>.sigstore-bundle.json`. Verification runs before TOML
    /// parsing, so unsigned or rejected configs fail closed before any
    /// mapping is trusted.
    pub fn load_signed_from_path(
        path: impl AsRef<Path>,
        verifier: &dyn AttestVerifier,
        expected_identity: &ExpectedIdentity,
    ) -> Result<Self, IamPrincipalConfigError> {
        let path = path.as_ref();
        let config_bytes = read_required_file(path, MissingKind::Config)?;
        let bundle_path = sigstore_bundle_path(path);
        let bundle_bytes = read_required_file(&bundle_path, MissingKind::Bundle)?;

        verifier
            .verify_bundle(&config_bytes, &bundle_bytes, expected_identity)
            .map_err(|source| IamPrincipalConfigError::SignatureRejected {
                detail: source.to_string(),
            })?;

        let raw = std::str::from_utf8(&config_bytes)
            .map_err(|source| IamPrincipalConfigError::Utf8 { source })?;
        let config: Self = toml::from_str(raw).map_err(|source| IamPrincipalConfigError::Toml {
            path: display_path(path),
            source,
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Parse TOML after a caller has already performed signature
    /// verification. Tests use this for focused validation coverage.
    pub fn parse_verified_str(
        path_label: impl Into<String>,
        raw: &str,
    ) -> Result<Self, IamPrincipalConfigError> {
        let path = path_label.into();
        let config: Self =
            toml::from_str(raw).map_err(|source| IamPrincipalConfigError::Toml { path, source })?;
        config.validate()?;
        Ok(config)
    }

    /// Resolve a caller identity to a Bedrock fabric principal.
    pub fn resolve(
        &self,
        identity: &BedrockCallerIdentity,
    ) -> Result<ResolvedBedrockPrincipal, IamPrincipalConfigError> {
        let caller = normalize_caller_identity(identity)?;

        for mapping in &self.mapping {
            let matched = caller
                .match_arns
                .iter()
                .any(|arn| wildcard_match(&mapping.match_pattern, arn));
            if matched {
                return Ok(ResolvedBedrockPrincipal {
                    owner: mapping.owner.clone(),
                    caller_arn: caller.caller_arn,
                    account_id: caller.account_id,
                    assumed_role_session_arn: caller.assumed_role_session_arn,
                    matched_pattern: mapping.match_pattern.clone(),
                });
            }
        }

        Err(IamPrincipalConfigError::PrincipalUnknown {
            caller_arn: caller.caller_arn,
            assumed_role_session_arn: caller
                .assumed_role_session_arn
                .unwrap_or_else(|| "None".to_string()),
        })
    }

    fn validate(&self) -> Result<(), IamPrincipalConfigError> {
        if self.config_version != SUPPORTED_CONFIG_VERSION {
            return Err(IamPrincipalConfigError::Invalid(format!(
                "config_version must be {SUPPORTED_CONFIG_VERSION}"
            )));
        }
        if self.default_action != DENY_ACTION {
            return Err(IamPrincipalConfigError::Invalid(
                "default_action must be \"deny\"".to_string(),
            ));
        }
        if self.mapping.is_empty() {
            return Err(IamPrincipalConfigError::Invalid(
                "at least one mapping is required".to_string(),
            ));
        }
        for (index, mapping) in self.mapping.iter().enumerate() {
            if mapping.match_pattern.trim().is_empty() {
                return Err(IamPrincipalConfigError::Invalid(format!(
                    "mapping {index} has an empty match pattern"
                )));
            }
            if mapping.owner.trim().is_empty() {
                return Err(IamPrincipalConfigError::Invalid(format!(
                    "mapping {index} has an empty owner"
                )));
            }
        }
        Ok(())
    }
}

/// Return the required Sigstore bundle path for a TOML config path.
pub fn sigstore_bundle_path(config_path: &Path) -> PathBuf {
    let file_name = config_path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!("{name}{SIGSTORE_BUNDLE_SUFFIX}"))
        .unwrap_or_else(|| format!("iam_principals.toml{SIGSTORE_BUNDLE_SUFFIX}"));

    match config_path.parent() {
        Some(parent) => parent.join(file_name),
        None => PathBuf::from(file_name),
    }
}

enum MissingKind {
    Config,
    Bundle,
}

fn read_required_file(
    path: &Path,
    missing: MissingKind,
) -> Result<Vec<u8>, IamPrincipalConfigError> {
    fs::read(path).map_err(|source| match (source.kind(), missing) {
        (std::io::ErrorKind::NotFound, MissingKind::Config) => {
            IamPrincipalConfigError::MissingConfig {
                path: display_path(path),
            }
        }
        (std::io::ErrorKind::NotFound, MissingKind::Bundle) => IamPrincipalConfigError::Unsigned {
            path: display_path(path),
        },
        _ => IamPrincipalConfigError::Io {
            path: display_path(path),
            source,
        },
    })
}

fn normalize_caller_identity(
    identity: &BedrockCallerIdentity,
) -> Result<NormalizedCaller, IamPrincipalConfigError> {
    let arn = identity.arn.trim();
    let account_id = identity.account_id.trim();
    if arn.is_empty() {
        return Err(IamPrincipalConfigError::InvalidCallerIdentity(
            "arn is empty".to_string(),
        ));
    }
    if !is_valid_account_id(account_id) {
        return Err(IamPrincipalConfigError::InvalidCallerIdentity(
            "account_id must be 12 digits".to_string(),
        ));
    }

    let parsed = parse_arn(arn)?;
    if parsed.account_id != account_id {
        return Err(IamPrincipalConfigError::InvalidCallerIdentity(format!(
            "STS account {account_id} did not match ARN account {}",
            parsed.account_id
        )));
    }

    if parsed.service == "sts" && parsed.resource.starts_with(ASSUMED_ROLE_PREFIX) {
        let assumed_session_arn = arn.to_string();
        let role_session = &parsed.resource[ASSUMED_ROLE_PREFIX.len()..];
        let Some((role_name, session_name)) = role_session.split_once('/') else {
            return Err(IamPrincipalConfigError::InvalidCallerIdentity(
                "assumed-role ARN must include role name and session name".to_string(),
            ));
        };
        if role_name.is_empty() || session_name.is_empty() {
            return Err(IamPrincipalConfigError::InvalidCallerIdentity(
                "assumed-role ARN role name and session name must be non-empty".to_string(),
            ));
        }
        let caller_arn = format!(
            "arn:{}:iam::{}:role/{}",
            parsed.partition, parsed.account_id, role_name
        );
        return Ok(NormalizedCaller {
            match_arns: vec![assumed_session_arn.clone(), caller_arn.clone()],
            caller_arn,
            account_id: parsed.account_id,
            assumed_role_session_arn: Some(assumed_session_arn),
        });
    }

    Ok(NormalizedCaller {
        caller_arn: arn.to_string(),
        account_id: parsed.account_id,
        assumed_role_session_arn: None,
        match_arns: vec![arn.to_string()],
    })
}

#[derive(Debug, Clone)]
struct ParsedArn {
    partition: String,
    service: String,
    account_id: String,
    resource: String,
}

fn parse_arn(arn: &str) -> Result<ParsedArn, IamPrincipalConfigError> {
    let parts: Vec<&str> = arn.splitn(6, ':').collect();
    if parts.len() != 6 || parts[0] != "arn" {
        return Err(IamPrincipalConfigError::InvalidCallerIdentity(format!(
            "invalid ARN shape: {arn}"
        )));
    }
    if parts[1].is_empty() || parts[2].is_empty() || parts[4].is_empty() || parts[5].is_empty() {
        return Err(IamPrincipalConfigError::InvalidCallerIdentity(format!(
            "invalid ARN components: {arn}"
        )));
    }
    if !is_valid_account_id(parts[4]) {
        return Err(IamPrincipalConfigError::InvalidCallerIdentity(
            "ARN account id must be 12 digits".to_string(),
        ));
    }

    Ok(ParsedArn {
        partition: parts[1].to_string(),
        service: parts[2].to_string(),
        account_id: parts[4].to_string(),
        resource: parts[5].to_string(),
    })
}

fn is_valid_account_id(account_id: &str) -> bool {
    account_id.len() == 12 && account_id.bytes().all(|byte| byte.is_ascii_digit())
}

fn wildcard_match(pattern: &str, candidate: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == candidate;
    }

    let anchored_start = !pattern.starts_with('*');
    let anchored_end = !pattern.ends_with('*');
    let parts: Vec<&str> = pattern.split('*').filter(|part| !part.is_empty()).collect();
    if parts.is_empty() {
        return true;
    }

    let mut position = 0usize;
    for (index, part) in parts.iter().enumerate() {
        if index == 0 && anchored_start {
            if !candidate[position..].starts_with(part) {
                return false;
            }
            position += part.len();
            continue;
        }

        let Some(found) = candidate[position..].find(part) else {
            return false;
        };
        position += found + part.len();
    }

    if anchored_end {
        if let Some(last) = parts.last() {
            return candidate.ends_with(last);
        }
    }

    true
}

fn display_path(path: &Path) -> String {
    path.display().to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_match_supports_ordered_star_patterns() {
        assert!(wildcard_match(
            "arn:aws:iam::123456789012:*",
            "arn:aws:iam::123456789012:role/ChioAgentRole"
        ));
        assert!(wildcard_match(
            "arn:aws:sts::123456789012:assumed-role/ChioAgentRole/*",
            "arn:aws:sts::123456789012:assumed-role/ChioAgentRole/session-1"
        ));
        assert!(!wildcard_match(
            "arn:aws:iam::123456789012:role/Admin",
            "arn:aws:iam::123456789012:role/ChioAgentRole"
        ));
    }

    #[test]
    fn assumed_role_identity_preserves_session_arn() {
        let identity = BedrockCallerIdentity::new(
            "arn:aws:sts::123456789012:assumed-role/ChioAgentRole/session-1",
            "123456789012",
        );
        let caller = normalize_caller_identity(&identity).unwrap();

        assert_eq!(
            caller.caller_arn,
            "arn:aws:iam::123456789012:role/ChioAgentRole"
        );
        assert_eq!(
            caller.assumed_role_session_arn.as_deref(),
            Some("arn:aws:sts::123456789012:assumed-role/ChioAgentRole/session-1")
        );
        assert_eq!(
            caller.match_arns,
            vec![
                "arn:aws:sts::123456789012:assumed-role/ChioAgentRole/session-1".to_string(),
                "arn:aws:iam::123456789012:role/ChioAgentRole".to_string(),
            ]
        );
    }
}
