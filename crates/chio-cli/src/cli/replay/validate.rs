// Frame validation pipeline for `chio replay traffic`.
//
// Four independent passes applied to every frame:
// 1. Schema-version gate: rejects unknown `schema_version`.
// 2. Tenant-sig verifier: Ed25519 over canonical JSON of all fields
//    except `tenant_sig`.
// 3. Redaction-pass gate: rejects frames whose redaction pass this build
//    cannot replay.
// 4. M01 invocation validator: proves `frame.invocation` is RFC 8785
//    canonical by round-tripping through `ToolInvocation`.
//
// All passes fail-closed; errors map to canonical exit codes 20/30/40/50.

use base64::Engine;

/// Canonical exit code: schema mismatch (`schema_version` unknown or
/// `invocation` fails validation).
pub const EXIT_SCHEMA_MISMATCH: i32 = 40;

/// Canonical exit code: tenant-sig verification failed.
pub const EXIT_BAD_TENANT_SIG: i32 = 20;

/// Canonical exit code: redaction pass unavailable or mismatch.
pub const EXIT_REDACTION_MISMATCH: i32 = 50;

/// Redaction pass this binary can re-run for local traffic fixtures.
const SUPPORTED_REDACTION_PASS_ID: &str = "m06-redactors@1.4.0+default";

/// Categorized validation failure for a single frame.
#[derive(Debug, thiserror::Error)]
pub enum ValidateError {
    /// Frame `schema_version` is not the pinned literal `"1"`, or the
    /// pinned schema name does not match the caller-supplied
    /// `--schema` flag.
    #[error("schema-version gate failed: {0}")]
    SchemaVersion(String),

    /// Full schema invariants from `chio_tee_frame::validate` failed.
    #[error("frame schema violation: {0}")]
    Schema(#[from] chio_tee_frame::SchemaError),

    /// Tenant signature failed verification (mismatch, malformed
    /// signature bytes, or canonicalization error).
    #[error("tenant signature verification failed: {0}")]
    TenantSig(String),

    /// The captured redaction pass cannot be replayed by this binary.
    #[error("redaction mismatch: {0}")]
    Redaction(String),

    /// `invocation` does not deserialize into a
    /// `chio_tool_call_fabric::ToolInvocation` or is not RFC 8785
    /// canonical.
    #[error("M01 invocation validation failed: {0}")]
    Invocation(String),
}

impl ValidateError {
    /// Map this error to the canonical exit code.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::SchemaVersion(_) | Self::Schema(_) | Self::Invocation(_) => EXIT_SCHEMA_MISMATCH,
            Self::TenantSig(_) => EXIT_BAD_TENANT_SIG,
            Self::Redaction(_) => EXIT_REDACTION_MISMATCH,
        }
    }
}

/// Schema-version gate.
///
/// Rejects frames whose schema name or wire `schema_version` does not match
/// the pinned literals, then runs [`chio_tee_frame::validate`].
pub fn schema_version_gate(
    frame: &chio_tee_frame::Frame,
    expected_schema_name: &str,
) -> Result<(), ValidateError> {
    if expected_schema_name != chio_tee_frame::FRAME_VERSION {
        return Err(ValidateError::SchemaVersion(format!(
            "expected schema name {:?}, got {:?}",
            chio_tee_frame::FRAME_VERSION,
            expected_schema_name,
        )));
    }
    if frame.schema_version != chio_tee_frame::SCHEMA_VERSION {
        return Err(ValidateError::SchemaVersion(format!(
            "frame schema_version {:?} differs from pinned {:?}",
            frame.schema_version,
            chio_tee_frame::SCHEMA_VERSION,
        )));
    }
    chio_tee_frame::validate(frame).map_err(ValidateError::Schema)?;
    Ok(())
}

/// Build the byte slice the tenant-sig commits to: canonical JSON of
/// every frame field except `tenant_sig`.
pub fn signing_payload(frame: &chio_tee_frame::Frame) -> Result<Vec<u8>, ValidateError> {
    let mut value = serde_json::to_value(frame)
        .map_err(|e| ValidateError::TenantSig(format!("serialize frame: {e}")))?;
    if let Some(map) = value.as_object_mut() {
        map.remove("tenant_sig");
    } else {
        return Err(ValidateError::TenantSig(
            "frame did not serialize as a JSON object".to_string(),
        ));
    }
    let bytes = chio_core::canonical::canonical_json_bytes(&value)
        .map_err(|e| ValidateError::TenantSig(format!("canonicalize frame: {e}")))?;
    Ok(bytes)
}

/// Decode the embedded `tenant_sig: ed25519:<base64>` field into a raw
/// 64-byte Ed25519 signature. Returns the `ValidateError::TenantSig`
/// variant on prefix or base64 errors.
fn decode_tenant_sig(value: &str) -> Result<[u8; 64], ValidateError> {
    let payload = value.strip_prefix("ed25519:").ok_or_else(|| {
        ValidateError::TenantSig("tenant_sig missing required `ed25519:` prefix".to_string())
    })?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(payload)
        .map_err(|e| ValidateError::TenantSig(format!("base64 decode: {e}")))?;
    if raw.len() != 64 {
        return Err(ValidateError::TenantSig(format!(
            "ed25519 signature must be 64 bytes, got {}",
            raw.len()
        )));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// Tenant-sig verifier.
///
/// `public_key_bytes` is the raw 32-byte Ed25519 public key the caller
/// resolved (via `--tenant-pubkey`). Errors fail closed; a tampered
/// body or mismatched key produces [`ValidateError::TenantSig`].
pub fn verify_tenant_sig(
    frame: &chio_tee_frame::Frame,
    public_key_bytes: &[u8; 32],
) -> Result<(), ValidateError> {
    let payload = signing_payload(frame)?;
    let sig_bytes = decode_tenant_sig(&frame.tenant_sig)?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(public_key_bytes)
        .map_err(|e| ValidateError::TenantSig(format!("invalid tenant public key: {e}")))?;
    use ed25519_dalek::Verifier;
    verifying_key
        .verify(&payload, &signature)
        .map_err(|e| ValidateError::TenantSig(format!("signature verify failed: {e}")))?;
    Ok(())
}

/// Parse a tenant-public-key file into a 32-byte Ed25519 key.
///
/// The file may contain either:
/// - 32 raw bytes, or
/// - 64 lowercase hexadecimal characters (with optional surrounding
///   whitespace and a single trailing newline).
///
/// Other shapes fail closed with `ValidateError::TenantSig` to match
/// the rest of the validation pipeline's error surface.
pub fn load_tenant_pubkey(path: &std::path::Path) -> Result<[u8; 32], ValidateError> {
    let bytes = std::fs::read(path).map_err(|e| {
        ValidateError::TenantSig(format!(
            "failed to read tenant pubkey file {}: {e}",
            path.display()
        ))
    })?;
    if bytes.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }
    // Trim ASCII whitespace (handles trailing newline, leading
    // whitespace) and try hex.
    let text = std::str::from_utf8(&bytes)
        .map_err(|e| ValidateError::TenantSig(format!("non-utf8 tenant pubkey: {e}")))?
        .trim();
    if text.len() == 64 {
        let mut out = [0u8; 32];
        hex::decode_to_slice(text, &mut out)
            .map_err(|e| ValidateError::TenantSig(format!("hex decode tenant pubkey: {e}")))?;
        return Ok(out);
    }
    Err(ValidateError::TenantSig(format!(
        "tenant pubkey file {} must be 32 raw bytes or 64 hex chars (got {} bytes)",
        path.display(),
        bytes.len(),
    )))
}

/// Parse a trusted kernel public-key file for receipt replay.
///
/// The file may contain raw 32-byte Ed25519 key material, bare Ed25519 hex,
/// or an algorithm-aware `PublicKey::to_hex()` string such as `p256:<hex>`.
pub fn load_trusted_kernel_pubkey(
    path: &std::path::Path,
) -> Result<chio_core::PublicKey, ValidateError> {
    let bytes = std::fs::read(path).map_err(|e| {
        ValidateError::TenantSig(format!(
            "failed to read trusted kernel pubkey file {}: {e}",
            path.display()
        ))
    })?;
    if bytes.len() == 32 {
        return chio_core::PublicKey::from_hex(&hex::encode(bytes)).map_err(|e| {
            ValidateError::TenantSig(format!("invalid trusted kernel pubkey: {e}"))
        });
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|e| ValidateError::TenantSig(format!("non-utf8 trusted kernel pubkey: {e}")))?
        .trim();
    chio_core::PublicKey::from_hex(text).map_err(|e| {
        ValidateError::TenantSig(format!("invalid trusted kernel pubkey {}: {e}", path.display()))
    })
}

/// Assert that `frame.invocation` deserializes into a
/// `chio_tool_call_fabric::ToolInvocation` and that re-canonicalizing the
/// round-tripped value produces byte-identical RFC 8785 bytes.
pub fn validate_m01_invocation(frame: &chio_tee_frame::Frame) -> Result<(), ValidateError> {
    let invocation: chio_tool_call_fabric::ToolInvocation =
        serde_json::from_value(frame.invocation.clone())
            .map_err(|e| ValidateError::Invocation(format!("deserialize ToolInvocation: {e}")))?;

    // Canonical-JSON round-trip stability proof. Re-encoding the
    // typed value yields the canonical bytes; re-encoding the original
    // `serde_json::Value` MUST match. Mismatch implies the wire bytes
    // were not in canonical form to begin with.
    let typed_bytes = chio_core::canonical::canonical_json_bytes(&invocation).map_err(|e| {
        ValidateError::Invocation(format!("canonicalize typed invocation: {e}"))
    })?;
    let raw_bytes = chio_core::canonical::canonical_json_bytes(&frame.invocation).map_err(|e| {
        ValidateError::Invocation(format!("canonicalize raw invocation value: {e}"))
    })?;
    if typed_bytes != raw_bytes {
        return Err(ValidateError::Invocation(
            "invocation is not RFC 8785 canonical (typed/raw byte mismatch)".to_string(),
        ));
    }
    let arguments: serde_json::Value =
        serde_json::from_slice(&invocation.arguments).map_err(|e| {
            ValidateError::Invocation(format!("invocation.arguments not valid JSON: {e}"))
        })?;
    let canonical_arguments =
        chio_core::canonical::canonical_json_bytes(&arguments).map_err(|e| {
            ValidateError::Invocation(format!("canonicalize invocation.arguments: {e}"))
        })?;
    if canonical_arguments != invocation.arguments {
        return Err(ValidateError::Invocation(
            "invocation.arguments is not RFC 8785 canonical JSON".to_string(),
        ));
    }
    Ok(())
}

/// Redaction-pass availability gate.
///
/// Fails closed for captures whose `redaction_pass_id` this build cannot
/// replay (exit code 50).
pub fn validate_redaction_pass(frame: &chio_tee_frame::Frame) -> Result<(), ValidateError> {
    if frame.redaction_pass_id == SUPPORTED_REDACTION_PASS_ID {
        return Ok(());
    }
    Err(ValidateError::Redaction(format!(
        "redaction_pass_id {:?} is unavailable in this build",
        frame.redaction_pass_id,
    )))
}

/// Per-frame validation report suitable for human and `--json` rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameValidation {
    /// 1-based source line.
    pub line: u64,
    /// Whether all enabled validators passed.
    pub ok: bool,
    /// Human-readable failure detail, when `!ok`.
    pub error: Option<String>,
    /// Canonical M04 exit code corresponding to `error`, when `!ok`.
    pub exit_code: Option<i32>,
}

impl FrameValidation {
    /// Build a passing report.
    pub fn pass(line: u64) -> Self {
        Self {
            line,
            ok: true,
            error: None,
            exit_code: None,
        }
    }

    /// Build a failing report from a `ValidateError`.
    pub fn fail(line: u64, err: &ValidateError) -> Self {
        Self {
            line,
            ok: false,
            error: Some(err.to_string()),
            exit_code: Some(err.exit_code()),
        }
    }
}

/// Run the full validation pipeline against a single frame.
/// Skips tenant-sig verification when `tenant_pubkey` is `None`.
pub fn validate_frame(
    frame: &chio_tee_frame::Frame,
    expected_schema_name: &str,
    tenant_pubkey: Option<&[u8; 32]>,
) -> Result<(), ValidateError> {
    schema_version_gate(frame, expected_schema_name)?;
    validate_redaction_pass(frame)?;
    if let Some(pk) = tenant_pubkey {
        verify_tenant_sig(frame, pk)?;
    }
    validate_m01_invocation(frame)?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod replay_validate_tests {
    use super::*;
    use chio_tool_call_fabric::{Principal, ProviderId, ProvenanceStamp, ToolInvocation};
    use ed25519_dalek::{Signer, SigningKey};
    use std::time::SystemTime;

    fn signing_keypair() -> SigningKey {
        // Deterministic fixed seed so test fixtures are reproducible
        // across runs without depending on `OsRng`.
        let seed: [u8; 32] = [7u8; 32];
        SigningKey::from_bytes(&seed)
    }

    fn canonical_invocation() -> serde_json::Value {
        let invocation = ToolInvocation {
            provider: ProviderId::OpenAi,
            tool_name: "search".to_string(),
            arguments: br#"{"q":"hello"}"#.to_vec(),
            provenance: ProvenanceStamp {
                provider: ProviderId::OpenAi,
                request_id: "req_abc".to_string(),
                api_version: "2025-10-01".to_string(),
                principal: Principal::OpenAiOrg {
                    org_id: "org_42".to_string(),
                },
                received_at: SystemTime::UNIX_EPOCH,
            },
        };
        // Round-trip through canonical JSON so the embedded value is
        // byte-for-byte canonical.
        let bytes = chio_core::canonical::canonical_json_bytes(&invocation).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn good_frame_with_invocation(invocation: serde_json::Value) -> chio_tee_frame::Frame {
        chio_tee_frame::Frame {
            schema_version: chio_tee_frame::SCHEMA_VERSION.to_string(),
            event_id: "01H7ZZZZZZZZZZZZZZZZZZZZZZ".to_string(),
            ts: "2026-04-25T18:02:11.418Z".to_string(),
            tee_id: "tee-prod-1".to_string(),
            upstream: chio_tee_frame::Upstream {
                system: chio_tee_frame::UpstreamSystem::Openai,
                operation: "responses.create".to_string(),
                api_version: "2025-10-01".to_string(),
            },
            invocation,
            provenance: chio_tee_frame::Provenance {
                otel: chio_tee_frame::Otel {
                    trace_id: "0".repeat(32),
                    span_id: "0".repeat(16),
                },
                supply_chain: None,
            },
            request_blob_sha256: "a".repeat(64),
            response_blob_sha256: "b".repeat(64),
            redaction_pass_id: "m06-redactors@1.4.0+default".to_string(),
            verdict: chio_tee_frame::Verdict::Allow,
            deny_reason: None,
            would_have_blocked: false,
            // A valid base64 placeholder matching the schema regex.
            // Tests that exercise the verifier sign their own frames
            // and overwrite this field with a real signature.
            tenant_sig: format!("ed25519:{}", "A".repeat(86)),
        }
    }

    fn signed_frame(kp: &SigningKey) -> chio_tee_frame::Frame {
        let mut frame = good_frame_with_invocation(canonical_invocation());
        let payload = signing_payload(&frame).unwrap();
        let sig = kp.sign(&payload);
        let encoded = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
        frame.tenant_sig = format!("ed25519:{encoded}");
        frame
    }

    #[test]
    fn schema_version_gate_accepts_pinned_v1() {
        let frame = good_frame_with_invocation(canonical_invocation());
        schema_version_gate(&frame, "chio-tee-frame.v1").unwrap();
    }

    #[test]
    fn schema_version_gate_rejects_unknown_schema_name() {
        let frame = good_frame_with_invocation(canonical_invocation());
        let err = schema_version_gate(&frame, "chio-tee-frame.v2").unwrap_err();
        assert!(matches!(err, ValidateError::SchemaVersion(_)));
        assert_eq!(err.exit_code(), EXIT_SCHEMA_MISMATCH);
    }

    #[test]
    fn schema_version_gate_rejects_wrong_wire_version() {
        let mut frame = good_frame_with_invocation(canonical_invocation());
        frame.schema_version = "2".to_string();
        let err = schema_version_gate(&frame, "chio-tee-frame.v1").unwrap_err();
        assert!(matches!(err, ValidateError::SchemaVersion(_)));
    }

    #[test]
    fn schema_version_gate_rejects_invalid_inner_invariant() {
        let mut frame = good_frame_with_invocation(canonical_invocation());
        // Lowercase ULID violates the Crockford-base32-upper rule the
        // chio-tee-frame schema enforces.
        frame.event_id = "abcdefghijklmnopqrstuvwxyz".to_string();
        let err = schema_version_gate(&frame, "chio-tee-frame.v1").unwrap_err();
        assert!(matches!(err, ValidateError::Schema(_)));
    }

    #[test]
    fn tenant_sig_verifier_accepts_valid_signature() {
        let kp = signing_keypair();
        let frame = signed_frame(&kp);
        let pk = kp.verifying_key().to_bytes();
        verify_tenant_sig(&frame, &pk).unwrap();
    }

    #[test]
    fn tenant_sig_verifier_rejects_tampered_body() {
        let kp = signing_keypair();
        let mut frame = signed_frame(&kp);
        // Mutate a frame field after signing; the recomputed canonical
        // payload no longer matches the signature.
        frame.tee_id = "tee-prod-2".to_string();
        let pk = kp.verifying_key().to_bytes();
        let err = verify_tenant_sig(&frame, &pk).unwrap_err();
        assert!(matches!(err, ValidateError::TenantSig(_)));
        assert_eq!(err.exit_code(), EXIT_BAD_TENANT_SIG);
    }

    #[test]
    fn tenant_sig_verifier_rejects_wrong_key() {
        let kp = signing_keypair();
        let frame = signed_frame(&kp);
        let other_kp = SigningKey::from_bytes(&[8u8; 32]);
        let err = verify_tenant_sig(&frame, &other_kp.verifying_key().to_bytes()).unwrap_err();
        assert!(matches!(err, ValidateError::TenantSig(_)));
    }

    #[test]
    fn tenant_sig_verifier_rejects_missing_prefix() {
        let kp = signing_keypair();
        let mut frame = signed_frame(&kp);
        frame.tenant_sig = frame.tenant_sig.replace("ed25519:", "");
        let err = verify_tenant_sig(&frame, &kp.verifying_key().to_bytes()).unwrap_err();
        match err {
            ValidateError::TenantSig(msg) => assert!(msg.contains("prefix"), "msg: {msg}"),
            other => panic!("expected TenantSig, got {other:?}"),
        }
    }

    #[test]
    fn m01_invocation_validator_accepts_canonical() {
        let frame = good_frame_with_invocation(canonical_invocation());
        validate_m01_invocation(&frame).unwrap();
    }

    #[test]
    fn m01_invocation_validator_rejects_noncanonical_argument_bytes() {
        let invocation = ToolInvocation {
            provider: ProviderId::OpenAi,
            tool_name: "search".to_string(),
            arguments: br#"{"z":1,"a":2}"#.to_vec(),
            provenance: ProvenanceStamp {
                provider: ProviderId::OpenAi,
                request_id: "req_abc".to_string(),
                api_version: "2025-10-01".to_string(),
                principal: Principal::OpenAiOrg {
                    org_id: "org_42".to_string(),
                },
                received_at: SystemTime::UNIX_EPOCH,
            },
        };
        let bytes = chio_core::canonical::canonical_json_bytes(&invocation).unwrap();
        let frame = good_frame_with_invocation(serde_json::from_slice(&bytes).unwrap());

        let err = validate_m01_invocation(&frame).unwrap_err();
        assert!(matches!(err, ValidateError::Invocation(_)));
        assert!(err.to_string().contains("arguments"));
    }

    #[test]
    fn m01_invocation_validator_rejects_non_toolinvocation_value() {
        // An empty object cannot deserialize into ToolInvocation: the
        // `provider`, `tool_name`, `arguments`, and `provenance` fields
        // are required.
        let frame = good_frame_with_invocation(serde_json::json!({}));
        let err = validate_m01_invocation(&frame).unwrap_err();
        assert!(matches!(err, ValidateError::Invocation(_)));
        assert_eq!(err.exit_code(), EXIT_SCHEMA_MISMATCH);
    }

    #[test]
    fn validate_frame_runs_full_pipeline() {
        let kp = signing_keypair();
        let frame = signed_frame(&kp);
        let pk = kp.verifying_key().to_bytes();
        validate_frame(&frame, "chio-tee-frame.v1", Some(&pk)).unwrap();
    }

    #[test]
    fn validate_frame_skips_sig_when_pubkey_absent() {
        // A frame with an unsigned (placeholder) tenant_sig still
        // passes when the verifier is skipped.
        let frame = good_frame_with_invocation(canonical_invocation());
        validate_frame(&frame, "chio-tee-frame.v1", None).unwrap();
    }

    #[test]
    fn frame_validation_pass_and_fail_constructors() {
        let pass = FrameValidation::pass(7);
        assert_eq!(pass.line, 7);
        assert!(pass.ok);
        assert!(pass.error.is_none());
        assert!(pass.exit_code.is_none());

        let err = ValidateError::SchemaVersion("nope".to_string());
        let fail = FrameValidation::fail(9, &err);
        assert_eq!(fail.line, 9);
        assert!(!fail.ok);
        assert_eq!(fail.exit_code, Some(EXIT_SCHEMA_MISMATCH));
        assert!(fail.error.unwrap().contains("nope"));
    }

    #[test]
    fn exit_code_constants_match_m04_registry() {
        assert_eq!(EXIT_SCHEMA_MISMATCH, 40);
        assert_eq!(EXIT_BAD_TENANT_SIG, 20);
        assert_eq!(EXIT_REDACTION_MISMATCH, 50);
    }

    #[test]
    fn load_tenant_pubkey_reads_raw_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pk.bin");
        std::fs::write(&path, [9u8; 32]).unwrap();
        let pk = load_tenant_pubkey(&path).unwrap();
        assert_eq!(pk, [9u8; 32]);
    }

    #[test]
    fn load_tenant_pubkey_reads_hex() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pk.hex");
        let kp = signing_keypair();
        let hex_str = hex::encode(kp.verifying_key().to_bytes());
        std::fs::write(&path, format!("{hex_str}\n")).unwrap();
        let pk = load_tenant_pubkey(&path).unwrap();
        assert_eq!(pk, kp.verifying_key().to_bytes());
    }

    #[test]
    fn load_tenant_pubkey_rejects_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pk.bad");
        std::fs::write(&path, b"not 32 bytes and not 64 hex chars").unwrap();
        let err = load_tenant_pubkey(&path).unwrap_err();
        assert!(matches!(err, ValidateError::TenantSig(_)));
    }
}
