#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_attest_verify::{AttestError, AttestVerifier, ExpectedIdentity, VerifiedAttestation};
use chio_bedrock_converse_adapter::{
    iam_principals::sigstore_bundle_path, transport, BedrockAdapter, BedrockAdapterConfig,
    BedrockAdapterError, BedrockCallerIdentity, IamPrincipalConfigError, IamPrincipalsConfig,
};
use chio_tool_call_fabric::Principal;

struct AllowVerifier;

impl AttestVerifier for AllowVerifier {
    fn verify_blob(
        &self,
        _artifact: &Path,
        _signature: &Path,
        _certificate: &Path,
        _expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        Err(AttestError::Malformed("verify_blob unused".to_string()))
    }

    fn verify_bytes(
        &self,
        _artifact: &[u8],
        _signature: &[u8],
        _certificate_pem: &[u8],
        _expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        Err(AttestError::Malformed("verify_bytes unused".to_string()))
    }

    fn verify_bundle(
        &self,
        artifact: &[u8],
        bundle_json: &[u8],
        _expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        assert!(!artifact.is_empty());
        assert_eq!(bundle_json, b"verified-bundle");
        Ok(VerifiedAttestation {
            subject_digest_sha256: [7u8; 32],
            certificate_identity:
                "https://github.com/backbay/chio/.github/workflows/iam.yml@refs/heads/main"
                    .to_string(),
            certificate_oidc_issuer: "https://token.actions.githubusercontent.com".to_string(),
            rekor_log_index: 42,
            rekor_inclusion_verified: true,
            signed_at: UNIX_EPOCH,
        })
    }
}

struct DenyVerifier;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

impl AttestVerifier for DenyVerifier {
    fn verify_blob(
        &self,
        _artifact: &Path,
        _signature: &Path,
        _certificate: &Path,
        _expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        Err(AttestError::Malformed("verify_blob unused".to_string()))
    }

    fn verify_bytes(
        &self,
        _artifact: &[u8],
        _signature: &[u8],
        _certificate_pem: &[u8],
        _expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        Err(AttestError::Malformed("verify_bytes unused".to_string()))
    }

    fn verify_bundle(
        &self,
        _artifact: &[u8],
        _bundle_json: &[u8],
        _expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        Err(AttestError::SignatureMismatch)
    }
}

fn expected_identity() -> ExpectedIdentity {
    ExpectedIdentity {
        certificate_identity_regexp:
            "https://github\\.com/backbay/chio/\\.github/workflows/iam\\.yml@refs/heads/main"
                .to_string(),
        certificate_oidc_issuer: "https://token.actions.githubusercontent.com".to_string(),
    }
}

fn base_config() -> BedrockAdapterConfig {
    BedrockAdapterConfig::new(
        "bedrock-1",
        "Bedrock Converse",
        "0.1.0",
        "deadbeef",
        "arn:aws:iam::000000000000:role/placeholder",
        "000000000000",
    )
}

fn temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "chio-bedrock-principal-{name}-{}-{nanos}-{counter}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn write_signed_config(name: &str, raw: &str) -> PathBuf {
    let dir = temp_dir(name);
    let path = dir.join("iam_principals.toml");
    fs::write(&path, raw).unwrap();
    fs::write(sigstore_bundle_path(&path), b"verified-bundle").unwrap();
    path
}

fn adapter_from_identity(
    raw_config: &str,
    identity: BedrockCallerIdentity,
) -> Result<BedrockAdapter, BedrockAdapterError> {
    let path = write_signed_config("adapter", raw_config);
    BedrockAdapter::new_with_signed_iam_principals_config(
        base_config(),
        Arc::new(transport::MockTransport::new()),
        identity,
        path,
        &AllowVerifier,
        &expected_identity(),
    )
}

fn mapping_config(mapping: &str) -> String {
    format!(
        r#"
default_action = "deny"
config_version = 1

{mapping}
"#
    )
}

#[test]
fn exact_role_match_resolves_principal_owner() {
    let config = mapping_config(
        r#"
[[mapping]]
match = "arn:aws:iam::123456789012:role/ChioAgentRole"
owner = "team-alpha"
"#,
    );
    let adapter = adapter_from_identity(
        &config,
        BedrockCallerIdentity::new(
            "arn:aws:iam::123456789012:role/ChioAgentRole",
            "123456789012",
        ),
    )
    .unwrap();

    assert_eq!(adapter.principal_owner(), Some("team-alpha"));
    assert_eq!(
        adapter.matched_iam_principal_pattern(),
        Some("arn:aws:iam::123456789012:role/ChioAgentRole")
    );
    assert_eq!(
        adapter.config().principal(),
        Principal::BedrockIam {
            caller_arn: "arn:aws:iam::123456789012:role/ChioAgentRole".to_string(),
            account_id: "123456789012".to_string(),
            assumed_role_session_arn: None,
        }
    );
}

#[test]
fn account_wildcard_match_resolves_caller() {
    let config = mapping_config(
        r#"
[[mapping]]
match = "arn:aws:iam::987654321098:*"
owner = "team-providence"
"#,
    );
    let adapter = adapter_from_identity(
        &config,
        BedrockCallerIdentity::new("arn:aws:iam::987654321098:user/Alice", "987654321098"),
    )
    .unwrap();

    assert_eq!(adapter.principal_owner(), Some("team-providence"));
    assert_eq!(
        adapter.config().principal(),
        Principal::BedrockIam {
            caller_arn: "arn:aws:iam::987654321098:user/Alice".to_string(),
            account_id: "987654321098".to_string(),
            assumed_role_session_arn: None,
        }
    );
}

#[test]
fn assumed_role_session_match_preserves_role_and_session_arns() {
    let config = mapping_config(
        r#"
[[mapping]]
match = "arn:aws:sts::123456789012:assumed-role/ChioAgentRole/*"
owner = "team-alpha"
"#,
    );
    let adapter = adapter_from_identity(
        &config,
        BedrockCallerIdentity::new(
            "arn:aws:sts::123456789012:assumed-role/ChioAgentRole/session-1",
            "123456789012",
        ),
    )
    .unwrap();

    assert_eq!(adapter.principal_owner(), Some("team-alpha"));
    assert_eq!(
        adapter.config().principal(),
        Principal::BedrockIam {
            caller_arn: "arn:aws:iam::123456789012:role/ChioAgentRole".to_string(),
            account_id: "123456789012".to_string(),
            assumed_role_session_arn: Some(
                "arn:aws:sts::123456789012:assumed-role/ChioAgentRole/session-1".to_string()
            ),
        }
    );
}

#[test]
fn unmapped_caller_fails_closed() {
    let config = mapping_config(
        r#"
[[mapping]]
match = "arn:aws:iam::123456789012:role/ChioAgentRole"
owner = "team-alpha"
"#,
    );
    let err = adapter_from_identity(
        &config,
        BedrockCallerIdentity::new("arn:aws:iam::123456789012:role/OtherRole", "123456789012"),
    )
    .err()
    .unwrap();

    assert!(matches!(
        err,
        BedrockAdapterError::IamPrincipals(IamPrincipalConfigError::PrincipalUnknown { .. })
    ));
    assert!(err.to_string().contains("unmapped"));
}

#[test]
fn missing_config_fails_closed() {
    let path = temp_dir("missing").join("iam_principals.toml");
    let err =
        IamPrincipalsConfig::load_signed_from_path(&path, &AllowVerifier, &expected_identity())
            .expect_err("missing config should fail");

    assert!(matches!(err, IamPrincipalConfigError::MissingConfig { .. }));
}

#[test]
fn unsigned_config_fails_closed() {
    let dir = temp_dir("unsigned");
    let path = dir.join("iam_principals.toml");
    fs::write(
        &path,
        mapping_config(
            r#"
[[mapping]]
match = "arn:aws:iam::123456789012:role/ChioAgentRole"
owner = "team-alpha"
"#,
        ),
    )
    .unwrap();

    let err =
        IamPrincipalsConfig::load_signed_from_path(&path, &AllowVerifier, &expected_identity())
            .expect_err("unsigned config should fail");

    assert!(matches!(err, IamPrincipalConfigError::Unsigned { .. }));
}

#[test]
fn signature_rejection_fails_closed() {
    let path = write_signed_config(
        "signature-rejected",
        &mapping_config(
            r#"
[[mapping]]
match = "arn:aws:iam::123456789012:role/ChioAgentRole"
owner = "team-alpha"
"#,
        ),
    );
    let err =
        IamPrincipalsConfig::load_signed_from_path(&path, &DenyVerifier, &expected_identity())
            .expect_err("signature rejection should fail");

    assert!(matches!(
        err,
        IamPrincipalConfigError::SignatureRejected { .. }
    ));
}

#[test]
fn invalid_config_fails_closed() {
    let err = IamPrincipalsConfig::parse_verified_str(
        "invalid.toml",
        r#"
default_action = "allow"
config_version = 1

[[mapping]]
match = "arn:aws:iam::123456789012:role/ChioAgentRole"
owner = "team-alpha"
"#,
    )
    .expect_err("invalid default_action should fail");

    assert!(matches!(err, IamPrincipalConfigError::Invalid(_)));
}
