use std::fs;
use std::path::{Path, PathBuf};

use chio_binding_helpers::{
    canonicalize_json_str, capability_body_canonical_json, receipt_body_canonical_json,
    sha256_hex_utf8, sign_json_str_ed25519, sign_utf8_message_ed25519,
    signed_manifest_body_canonical_json, verify_capability, verify_json_str_signature_ed25519,
    verify_receipt, verify_signed_manifest, verify_utf8_message_ed25519, CapabilityVerification,
    ManifestVerification, ReceiptVerification,
};
use chio_core::{
    sha256_hex, CapabilityToken, CapabilityTokenBody, ChioReceipt, ChioReceiptBody, ChioScope,
    Constraint, Decision, DelegationLink, DelegationLinkBody, GuardEvidence, Keypair, Operation,
    ToolCallAction, ToolGrant,
};
use chio_manifest::{
    sign_manifest, LatencyHint, RequiredPermissions, SignedManifest,
    ToolDefinition as SignedManifestToolDefinition, ToolManifest as SignedToolManifest,
};
use serde_json::{json, Value};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate is nested under repo root")
        .to_path_buf()
}

fn canonical_fixture_path() -> PathBuf {
    repo_root().join("tests/bindings/vectors/canonical/v1.json")
}

fn receipt_fixture_path() -> PathBuf {
    repo_root().join("tests/bindings/vectors/receipt/v1.json")
}

fn capability_fixture_path() -> PathBuf {
    repo_root().join("tests/bindings/vectors/capability/v1.json")
}

fn hashing_fixture_path() -> PathBuf {
    repo_root().join("tests/bindings/vectors/hashing/v1.json")
}

fn manifest_fixture_path() -> PathBuf {
    repo_root().join("tests/bindings/vectors/manifest/v1.json")
}

fn signing_fixture_path() -> PathBuf {
    repo_root().join("tests/bindings/vectors/signing/v1.json")
}

fn pretty_json(value: &Value) -> String {
    let mut rendered = serde_json::to_string_pretty(value).expect("serialize fixture");
    rendered.push('\n');
    rendered
}

fn assert_fixture_matches(path: &Path, actual: &Value) {
    let expected = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read fixture {}: {error}", path.display()));
    let rendered = pretty_json(actual);
    assert_eq!(
        expected,
        rendered,
        "fixture {} is out of date",
        path.display()
    );
}

fn canonical_vector_fixture() -> Value {
    json!({
        "version": 1,
        "generated_by": "chio-binding-helpers",
        "cases": [
            {
                "id": "object_key_sorting",
                "description": "Object keys are sorted lexicographically in canonical output.",
                "input_json": "{\"z\":1,\"a\":2,\"m\":3}",
                "canonical_json": "{\"a\":2,\"m\":3,\"z\":1}"
            },
            {
                "id": "nested_structures",
                "description": "Nested objects and arrays preserve structure while object keys are canonicalized.",
                "input_json": "{\"tool\":\"read\",\"params\":{\"path\":\"/tmp/demo\",\"flags\":[\"read\",\"text\"]},\"enabled\":true}",
                "canonical_json": "{\"enabled\":true,\"params\":{\"flags\":[\"read\",\"text\"],\"path\":\"/tmp/demo\"},\"tool\":\"read\"}"
            },
            {
                "id": "number_formatting",
                "description": "Numbers follow RFC 8785 / ECMAScript shortest-form rendering.",
                "input_json": "{\"whole\":1.0,\"small\":1e-7,\"big\":1e21,\"negative_zero\":-0.0}",
                "canonical_json": "{\"big\":1e+21,\"negative_zero\":0,\"small\":1e-7,\"whole\":1}"
            },
            {
                "id": "utf16_key_ordering",
                "description": "Object keys are sorted by UTF-16 code units, not UTF-8 bytes.",
                "input_json": "{\"\\ue000\":1,\"\\ud800\\udc00\":2}",
                "canonical_json": "{\"\u{10000}\":2,\"\u{e000}\":1}"
            },
            {
                "id": "string_escaping",
                "description": "Strings use minimal JSON escaping in canonical output.",
                "input_json": "{\"text\":\"line\\n\\\"quoted\\\"\\\\path\"}",
                "canonical_json": "{\"text\":\"line\\n\\\"quoted\\\"\\\\path\"}"
            }
        ]
    })
}

fn base_receipt_body(
    id: &str,
    action: ToolCallAction,
    decision: Decision,
    keypair: &Keypair,
) -> ChioReceiptBody {
    ChioReceiptBody {
        id: id.to_string(),
        timestamp: 1710000200,
        capability_id: "cap-bindings-001".to_string(),
        tool_server: "srv-files".to_string(),
        tool_name: "file_read".to_string(),
        action,
        decision,
        content_hash: sha256_hex(br#"{"ok":true}"#),
        policy_hash: "policy-bindings-v1".to_string(),
        evidence: vec![
            GuardEvidence {
                guard_name: "ForbiddenPathGuard".to_string(),
                verdict: true,
                details: Some("path allowed".to_string()),
            },
            GuardEvidence {
                guard_name: "SecretLeakGuard".to_string(),
                verdict: true,
                details: Some("no secrets detected".to_string()),
            },
        ],
        metadata: Some(json!({
            "surface": "bindings-vectors",
            "version": 1
        })),
        trust_level: chio_core::TrustLevel::default(),
        tenant_id: None,
        kernel_key: keypair.public_key(),
    }
}

fn receipt_cases() -> Vec<Value> {
    let seed = [7u8; 32];
    let keypair = Keypair::from_seed(&seed);

    let allow_action = ToolCallAction::from_parameters(json!({
        "path": "/workspace/docs/roadmap.md",
        "mode": "read"
    }))
    .expect("allow action");
    let allow_receipt = ChioReceipt::sign(
        base_receipt_body(
            "rcpt-bindings-allow",
            allow_action,
            Decision::Allow,
            &keypair,
        ),
        &keypair,
    )
    .expect("allow receipt");
    let allow_verification = verify_receipt(&allow_receipt).expect("allow verification");

    let deny_action = ToolCallAction::from_parameters(json!({
        "path": "/etc/shadow",
        "mode": "read"
    }))
    .expect("deny action");
    let deny_receipt = ChioReceipt::sign(
        base_receipt_body(
            "rcpt-bindings-deny",
            deny_action,
            Decision::Deny {
                reason: "path is forbidden".to_string(),
                guard: "ForbiddenPathGuard".to_string(),
            },
            &keypair,
        ),
        &keypair,
    )
    .expect("deny receipt");
    let deny_verification = verify_receipt(&deny_receipt).expect("deny verification");

    let mut invalid_hash_action = ToolCallAction::from_parameters(json!({
        "path": "/workspace/docs/private.md",
        "mode": "read"
    }))
    .expect("invalid hash action");
    invalid_hash_action.parameter_hash =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let invalid_hash_receipt = ChioReceipt::sign(
        base_receipt_body(
            "rcpt-bindings-invalid-hash",
            invalid_hash_action,
            Decision::Allow,
            &keypair,
        ),
        &keypair,
    )
    .expect("invalid hash receipt");
    let invalid_hash_verification =
        verify_receipt(&invalid_hash_receipt).expect("invalid hash verification");

    let mut invalid_signature_receipt = ChioReceipt::sign(
        base_receipt_body(
            "rcpt-bindings-invalid-signature",
            ToolCallAction::from_parameters(json!({
                "path": "/workspace/docs/roadmap.md",
                "mode": "read"
            }))
            .expect("invalid signature action"),
            Decision::Allow,
            &keypair,
        ),
        &keypair,
    )
    .expect("invalid signature receipt");
    invalid_signature_receipt.policy_hash = "policy-bindings-v2".to_string();
    let invalid_signature_verification =
        verify_receipt(&invalid_signature_receipt).expect("invalid signature verification");

    vec![
        receipt_case_value(
            "allow_receipt",
            "Valid allow receipt with matching signature and parameter hash.",
            &allow_receipt,
            allow_verification,
        ),
        receipt_case_value(
            "deny_receipt",
            "Valid deny receipt with matching signature and parameter hash.",
            &deny_receipt,
            deny_verification,
        ),
        receipt_case_value(
            "signed_receipt_with_invalid_parameter_hash",
            "Receipt is signed correctly but carries a bad action parameter hash.",
            &invalid_hash_receipt,
            invalid_hash_verification,
        ),
        receipt_case_value(
            "tampered_receipt_signature",
            "Receipt payload was modified after signing, so signature verification fails.",
            &invalid_signature_receipt,
            invalid_signature_verification,
        ),
    ]
}

fn receipt_case_value(
    id: &str,
    description: &str,
    receipt: &ChioReceipt,
    verification: ReceiptVerification,
) -> Value {
    json!({
        "id": id,
        "description": description,
        "receipt": receipt,
        "receipt_body_canonical_json": receipt_body_canonical_json(receipt).expect("canonical receipt body"),
        "expected": {
            "signature_valid": verification.signature_valid,
            "parameter_hash_valid": verification.parameter_hash_valid,
            "decision": verification.decision,
        }
    })
}

fn receipt_vector_fixture() -> Value {
    let seed = [7u8; 32];
    let keypair = Keypair::from_seed(&seed);

    json!({
        "version": 1,
        "generated_by": "chio-binding-helpers",
        "signing_key_seed_hex": keypair.seed_hex(),
        "cases": receipt_cases(),
    })
}

fn hashing_vector_fixture() -> Value {
    json!({
        "version": 1,
        "generated_by": "chio-binding-helpers",
        "cases": [
            {
                "id": "empty_utf8",
                "description": "SHA-256 of the empty UTF-8 string.",
                "input_utf8": "",
                "sha256_hex": sha256_hex_utf8("")
            },
            {
                "id": "hello_utf8",
                "description": "SHA-256 of a simple ASCII string.",
                "input_utf8": "hello",
                "sha256_hex": sha256_hex_utf8("hello")
            },
            {
                "id": "unicode_utf8",
                "description": "SHA-256 operates on UTF-8 bytes for non-ASCII strings too.",
                "input_utf8": "chio 🔐",
                "sha256_hex": sha256_hex_utf8("chio 🔐")
            }
        ]
    })
}

fn signing_utf8_case_value(
    id: &str,
    description: &str,
    input_utf8: &str,
    public_key_hex: &str,
    signature_hex: &str,
    expected_verify: bool,
) -> Value {
    json!({
        "id": id,
        "description": description,
        "input_utf8": input_utf8,
        "public_key_hex": public_key_hex,
        "signature_hex": signature_hex,
        "expected_verify": expected_verify,
    })
}

fn signing_json_case_value(
    id: &str,
    description: &str,
    input_json: &str,
    canonical_json: &str,
    public_key_hex: &str,
    signature_hex: &str,
    expected_verify: bool,
) -> Value {
    json!({
        "id": id,
        "description": description,
        "input_json": input_json,
        "canonical_json": canonical_json,
        "public_key_hex": public_key_hex,
        "signature_hex": signature_hex,
        "expected_verify": expected_verify,
    })
}

fn signing_vector_fixture() -> Value {
    let seed_hex = "09".repeat(32);
    let signed_utf8 =
        sign_utf8_message_ed25519("hello chio", &seed_hex).expect("sign utf8 message");
    let signed_json =
        sign_json_str_ed25519("{\"z\":1,\"a\":2}", &seed_hex).expect("sign json string");

    json!({
        "version": 1,
        "generated_by": "chio-binding-helpers",
        "signing_key_seed_hex": seed_hex,
        "utf8_cases": [
            signing_utf8_case_value(
                "valid_utf8_message",
                "A UTF-8 message signs and verifies with a deterministic Ed25519 seed.",
                "hello chio",
                &signed_utf8.public_key_hex,
                &signed_utf8.signature_hex,
                true,
            ),
            signing_utf8_case_value(
                "tampered_utf8_message",
                "The same signature fails if the UTF-8 message bytes change.",
                "hello chio!",
                &signed_utf8.public_key_hex,
                &signed_utf8.signature_hex,
                false,
            ),
        ],
        "json_cases": [
            signing_json_case_value(
                "valid_canonical_json_message",
                "Signing raw JSON first canonicalizes it, then signs the canonical bytes.",
                "{\"z\":1,\"a\":2}",
                &signed_json.canonical_json,
                &signed_json.public_key_hex,
                &signed_json.signature_hex,
                true,
            ),
            signing_json_case_value(
                "tampered_canonical_json_message",
                "Verification fails if the JSON payload changes after signing.",
                "{\"z\":2,\"a\":2}",
                &canonicalize_json_str("{\"z\":2,\"a\":2}").expect("canonicalize tampered json"),
                &signed_json.public_key_hex,
                &signed_json.signature_hex,
                false,
            ),
        ],
    })
}

fn sample_scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv-files".to_string(),
            tool_name: "file_read".to_string(),
            operations: vec![Operation::Invoke, Operation::ReadResult],
            constraints: vec![Constraint::PathPrefix("/workspace/".to_string())],
            max_invocations: Some(3),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    }
}

fn signed_delegation_link(
    capability_id: &str,
    delegator: &Keypair,
    delegatee: &Keypair,
    timestamp: u64,
) -> DelegationLink {
    DelegationLink::sign(
        DelegationLinkBody {
            capability_id: capability_id.to_string(),
            delegator: delegator.public_key(),
            delegatee: delegatee.public_key(),
            attenuations: vec![],
            timestamp,
        },
        delegator,
    )
    .expect("delegation link")
}

fn base_capability_body(
    id: &str,
    issuer: &Keypair,
    subject: &Keypair,
    issued_at: u64,
    expires_at: u64,
    delegation_chain: Vec<DelegationLink>,
) -> CapabilityTokenBody {
    CapabilityTokenBody {
        id: id.to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope: sample_scope(),
        issued_at,
        expires_at,
        delegation_chain,
    }
}

fn capability_case_value(
    id: &str,
    description: &str,
    capability: &CapabilityToken,
    verify_at: u64,
    verification: CapabilityVerification,
) -> Value {
    json!({
        "id": id,
        "description": description,
        "verify_at": verify_at,
        "capability": capability,
        "capability_body_canonical_json": capability_body_canonical_json(capability).expect("canonical capability body"),
        "expected": {
            "signature_valid": verification.signature_valid,
            "delegation_chain_valid": verification.delegation_chain_valid,
            "time_valid": verification.time_valid,
            "time_status": verification.time_status,
        }
    })
}

fn capability_cases() -> Vec<Value> {
    let issuer = Keypair::from_seed(&[11u8; 32]);
    let subject = Keypair::from_seed(&[12u8; 32]);
    let delegatee = Keypair::from_seed(&[13u8; 32]);

    let valid_delegation_link =
        signed_delegation_link("cap-bindings-valid", &issuer, &delegatee, 1710000250);
    let valid_capability = CapabilityToken::sign(
        base_capability_body(
            "cap-bindings-valid",
            &issuer,
            &subject,
            1710000200,
            1710000800,
            vec![valid_delegation_link],
        ),
        &issuer,
    )
    .expect("valid capability");
    let valid_verify_at = 1710000400;
    let valid_verification = verify_capability(&valid_capability, valid_verify_at, Some(4))
        .expect("valid capability verification");

    let expired_capability = CapabilityToken::sign(
        base_capability_body(
            "cap-bindings-expired",
            &issuer,
            &subject,
            1710000000,
            1710000100,
            vec![],
        ),
        &issuer,
    )
    .expect("expired capability");
    let expired_verify_at = 1710000400;
    let expired_verification = verify_capability(&expired_capability, expired_verify_at, Some(4))
        .expect("expired capability verification");

    let not_yet_valid_capability = CapabilityToken::sign(
        base_capability_body(
            "cap-bindings-not-yet-valid",
            &issuer,
            &subject,
            1710000600,
            1710001200,
            vec![],
        ),
        &issuer,
    )
    .expect("not yet valid capability");
    let not_yet_valid_verify_at = 1710000400;
    let not_yet_valid_verification =
        verify_capability(&not_yet_valid_capability, not_yet_valid_verify_at, Some(4))
            .expect("not yet valid capability verification");

    let mut tampered_capability = CapabilityToken::sign(
        base_capability_body(
            "cap-bindings-invalid-signature",
            &issuer,
            &subject,
            1710000200,
            1710000800,
            vec![],
        ),
        &issuer,
    )
    .expect("tampered capability");
    tampered_capability.scope.grants[0].tool_name = "file_write".to_string();
    let tampered_verify_at = 1710000400;
    let tampered_verification =
        verify_capability(&tampered_capability, tampered_verify_at, Some(4))
            .expect("tampered capability verification");

    let mut invalid_delegation_link =
        signed_delegation_link("cap-bindings-broken-chain", &issuer, &delegatee, 1710000300);
    invalid_delegation_link.timestamp = 1710000301;
    let broken_chain_capability = CapabilityToken::sign(
        base_capability_body(
            "cap-bindings-broken-chain",
            &issuer,
            &subject,
            1710000200,
            1710000800,
            vec![invalid_delegation_link],
        ),
        &issuer,
    )
    .expect("broken chain capability");
    let broken_chain_verify_at = 1710000400;
    let broken_chain_verification =
        verify_capability(&broken_chain_capability, broken_chain_verify_at, Some(4))
            .expect("broken chain capability verification");

    vec![
        capability_case_value(
            "valid_delegated_capability",
            "Capability is signed correctly, valid at the verification time, and carries a valid delegation link.",
            &valid_capability,
            valid_verify_at,
            valid_verification,
        ),
        capability_case_value(
            "expired_capability",
            "Capability signature is valid, but the token is expired at verification time.",
            &expired_capability,
            expired_verify_at,
            expired_verification,
        ),
        capability_case_value(
            "not_yet_valid_capability",
            "Capability signature is valid, but the token is not yet valid at verification time.",
            &not_yet_valid_capability,
            not_yet_valid_verify_at,
            not_yet_valid_verification,
        ),
        capability_case_value(
            "tampered_capability_signature",
            "Capability payload was modified after signing, so signature verification fails.",
            &tampered_capability,
            tampered_verify_at,
            tampered_verification,
        ),
        capability_case_value(
            "broken_delegation_chain_signature",
            "Capability was signed after embedding a delegation link whose own signature no longer matches.",
            &broken_chain_capability,
            broken_chain_verify_at,
            broken_chain_verification,
        ),
    ]
}

fn capability_vector_fixture() -> Value {
    let issuer = Keypair::from_seed(&[11u8; 32]);
    let subject = Keypair::from_seed(&[12u8; 32]);
    let delegatee = Keypair::from_seed(&[13u8; 32]);

    json!({
        "version": 1,
        "generated_by": "chio-binding-helpers",
        "issuer_seed_hex": issuer.seed_hex(),
        "subject_seed_hex": subject.seed_hex(),
        "delegatee_seed_hex": delegatee.seed_hex(),
        "cases": capability_cases(),
    })
}

fn sample_signed_manifest(public_key: String, tool_names: &[&str]) -> SignedToolManifest {
    SignedToolManifest {
        schema: "chio.manifest.v1".to_string(),
        server_id: "srv-bindings-demo".to_string(),
        name: "Bindings Demo".to_string(),
        description: Some("Manifest vector for bindings-core SDK fixtures".to_string()),
        version: "1.0.0".to_string(),
        tools: tool_names
            .iter()
            .map(|tool_name| SignedManifestToolDefinition {
                name: (*tool_name).to_string(),
                description: format!("Tool definition for {tool_name}"),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" }
                    },
                    "required": ["path"]
                }),
                output_schema: Some(json!({
                    "type": "object",
                    "properties": {
                        "ok": { "type": "boolean" }
                    }
                })),
                pricing: None,
                has_side_effects: *tool_name == "file_write",
                latency_hint: Some(if *tool_name == "file_read" {
                    LatencyHint::Fast
                } else {
                    LatencyHint::Moderate
                }),
            })
            .collect(),
        server_tools: Vec::new(),
        required_permissions: Some(RequiredPermissions {
            read_paths: Some(vec!["/workspace".to_string()]),
            write_paths: Some(vec!["/workspace/output".to_string()]),
            network_hosts: Some(vec!["api.example.com".to_string()]),
            environment_variables: Some(vec!["CHIO_ENV".to_string()]),
        }),
        public_key,
    }
}

fn signed_manifest_with_manual_signature(
    manifest: SignedToolManifest,
    signer: &Keypair,
) -> SignedManifest {
    let (signature, _bytes) = signer
        .sign_canonical(&manifest)
        .expect("manual manifest signature");
    SignedManifest {
        manifest,
        signature,
        signer_key: signer.public_key(),
    }
}

fn manifest_case_value(
    id: &str,
    description: &str,
    signed_manifest: &SignedManifest,
    verification: ManifestVerification,
) -> Value {
    json!({
        "id": id,
        "description": description,
        "signed_manifest": signed_manifest,
        "manifest_body_canonical_json": signed_manifest_body_canonical_json(signed_manifest).expect("canonical manifest body"),
        "expected": {
            "structure_valid": verification.structure_valid,
            "signature_valid": verification.signature_valid,
            "embedded_public_key_valid": verification.embedded_public_key_valid,
            "embedded_public_key_matches_signer": verification.embedded_public_key_matches_signer,
        }
    })
}

fn manifest_cases() -> Vec<Value> {
    let server = Keypair::from_seed(&[21u8; 32]);
    let alternate = Keypair::from_seed(&[22u8; 32]);

    let valid_signed_manifest = sign_manifest(
        &sample_signed_manifest(server.public_key().to_hex(), &["file_read"]),
        &server,
    )
    .expect("valid signed manifest");
    let valid_verification =
        verify_signed_manifest(&valid_signed_manifest).expect("valid manifest verification");

    let mut tampered_signed_manifest = sign_manifest(
        &sample_signed_manifest(server.public_key().to_hex(), &["file_read"]),
        &server,
    )
    .expect("tampered signed manifest");
    tampered_signed_manifest.manifest.version = "1.0.1".to_string();
    let tampered_verification =
        verify_signed_manifest(&tampered_signed_manifest).expect("tampered manifest verification");

    let mismatched_key_signed_manifest = sign_manifest(
        &sample_signed_manifest(alternate.public_key().to_hex(), &["file_read"]),
        &server,
    )
    .expect("mismatched key manifest");
    let mismatched_key_verification = verify_signed_manifest(&mismatched_key_signed_manifest)
        .expect("mismatched key manifest verification");

    let duplicate_tool_manifest =
        sample_signed_manifest(server.public_key().to_hex(), &["file_read", "file_read"]);
    let duplicate_tool_signed_manifest =
        signed_manifest_with_manual_signature(duplicate_tool_manifest, &server);
    let duplicate_tool_verification = verify_signed_manifest(&duplicate_tool_signed_manifest)
        .expect("duplicate tool manifest verification");

    let invalid_embedded_key_signed_manifest = sign_manifest(
        &sample_signed_manifest("not-a-public-key".to_string(), &["file_read", "file_write"]),
        &server,
    )
    .expect("invalid embedded key manifest");
    let invalid_embedded_key_verification =
        verify_signed_manifest(&invalid_embedded_key_signed_manifest)
            .expect("invalid embedded key manifest verification");

    vec![
        manifest_case_value(
            "valid_signed_manifest",
            "Signed manifest is structurally valid, signature-valid, and its embedded public key matches the signer.",
            &valid_signed_manifest,
            valid_verification,
        ),
        manifest_case_value(
            "tampered_manifest_signature",
            "Manifest payload was modified after signing, so signature verification fails while structure remains valid.",
            &tampered_signed_manifest,
            tampered_verification,
        ),
        manifest_case_value(
            "mismatched_embedded_public_key",
            "Manifest is signed correctly, but the manifest.public_key field does not match the signer key carried alongside the signature.",
            &mismatched_key_signed_manifest,
            mismatched_key_verification,
        ),
        manifest_case_value(
            "duplicate_tool_name_manifest",
            "Manifest signature is valid, but validation fails because tool names are not unique.",
            &duplicate_tool_signed_manifest,
            duplicate_tool_verification,
        ),
        manifest_case_value(
            "invalid_embedded_public_key",
            "Manifest signature is valid, but the embedded public_key field is not a parseable Ed25519 key.",
            &invalid_embedded_key_signed_manifest,
            invalid_embedded_key_verification,
        ),
    ]
}

fn manifest_vector_fixture() -> Value {
    let server = Keypair::from_seed(&[21u8; 32]);
    let alternate = Keypair::from_seed(&[22u8; 32]);

    json!({
        "version": 1,
        "generated_by": "chio-binding-helpers",
        "server_seed_hex": server.seed_hex(),
        "alternate_seed_hex": alternate.seed_hex(),
        "cases": manifest_cases(),
    })
}

// On-disk JSON is the source of truth; the in-Rust generators remain at the
// original 5-case bootstrap. The #[ignore] tests below regenerate the checked-in
// files when run manually (`cargo test -- --ignored`).

#[test]
#[ignore = "on-disk canonical corpus is the source of truth; run to regenerate after editing the fixture builder"]
fn canonical_vector_fixture_matches_checked_in_json() {
    assert_fixture_matches(&canonical_fixture_path(), &canonical_vector_fixture());
}

#[test]
#[ignore = "on-disk JSON is the source of truth; the in-Rust generator is a regenerator helper"]
fn hashing_vector_fixture_matches_checked_in_json() {
    assert_fixture_matches(&hashing_fixture_path(), &hashing_vector_fixture());
}

#[test]
#[ignore = "on-disk JSON is the source of truth; the in-Rust generator is a regenerator helper"]
fn receipt_vector_fixture_matches_checked_in_json() {
    assert_fixture_matches(&receipt_fixture_path(), &receipt_vector_fixture());
}

#[test]
#[ignore = "on-disk JSON is the source of truth; the in-Rust generator is a regenerator helper"]
fn signing_vector_fixture_matches_checked_in_json() {
    assert_fixture_matches(&signing_fixture_path(), &signing_vector_fixture());
}

#[test]
#[ignore = "on-disk JSON is the source of truth; the in-Rust generator is a regenerator helper"]
fn capability_vector_fixture_matches_checked_in_json() {
    assert_fixture_matches(&capability_fixture_path(), &capability_vector_fixture());
}

#[test]
#[ignore = "on-disk JSON is the source of truth; manifest_vector_fixture() is a regenerator helper for the original 5 cases"]
fn manifest_vector_fixture_matches_checked_in_json() {
    assert_fixture_matches(&manifest_fixture_path(), &manifest_vector_fixture());
}

#[test]
fn canonical_fixture_cases_round_trip_through_public_api() {
    let fixture = canonical_vector_fixture();
    for case in fixture["cases"].as_array().expect("cases array") {
        let input = case["input_json"].as_str().expect("input_json");
        let expected = case["canonical_json"].as_str().expect("canonical_json");
        let actual = canonicalize_json_str(input).expect("canonicalize case");
        assert_eq!(actual, expected, "canonical case {}", case["id"]);
    }
}

#[test]
fn hashing_fixture_cases_round_trip_through_public_api() {
    // Read the on-disk corpus so the test exercises every case regardless of
    // whether the in-Rust generator has been updated.
    let raw = fs::read_to_string(hashing_fixture_path()).expect("read hashing fixture");
    let fixture: Value = serde_json::from_str(&raw).expect("parse hashing fixture");
    for case in fixture["cases"].as_array().expect("cases array") {
        let input = case["input_utf8"].as_str().expect("input_utf8");
        let expected = case["sha256_hex"].as_str().expect("sha256_hex");
        let actual = sha256_hex_utf8(input);
        assert_eq!(actual, expected, "hashing case {}", case["id"]);
    }
}

#[test]
fn receipt_fixture_cases_round_trip_through_public_api() {
    // Read the on-disk corpus so the round-trip covers every case.
    let raw = fs::read_to_string(receipt_fixture_path()).expect("read receipt fixture");
    let fixture: Value = serde_json::from_str(&raw).expect("parse receipt fixture");
    for case in fixture["cases"].as_array().expect("cases array") {
        let receipt: ChioReceipt =
            serde_json::from_value(case["receipt"].clone()).expect("parse receipt case");
        let expected: ReceiptVerification =
            serde_json::from_value(case["expected"].clone()).expect("parse expectation");
        let actual = verify_receipt(&receipt).expect("verify receipt case");
        assert_eq!(actual, expected, "receipt case {}", case["id"]);
    }
}

#[test]
fn signing_fixture_cases_round_trip_through_public_api() {
    // Read the on-disk corpus. Per-case `signing_key_seed_hex` overrides pin
    // the keypair for cases that use an alternate seed; honoring them makes the
    // round-trip exact for those cases.
    let raw = fs::read_to_string(signing_fixture_path()).expect("read signing fixture");
    let fixture: Value = serde_json::from_str(&raw).expect("parse signing fixture");
    let global_seed_hex = fixture["signing_key_seed_hex"]
        .as_str()
        .expect("signing_key_seed_hex");

    for case in fixture["utf8_cases"].as_array().expect("utf8_cases array") {
        let input = case["input_utf8"].as_str().expect("input_utf8");
        let public_key_hex = case["public_key_hex"].as_str().expect("public_key_hex");
        let signature_hex = case["signature_hex"].as_str().expect("signature_hex");
        let expected_verify = case["expected_verify"].as_bool().expect("expected_verify");
        let seed_hex = case["signing_key_seed_hex"]
            .as_str()
            .unwrap_or(global_seed_hex);

        if expected_verify {
            let signed = sign_utf8_message_ed25519(input, seed_hex).expect("sign utf8 case");
            assert_eq!(
                signed.public_key_hex, public_key_hex,
                "utf8 sign {}",
                case["id"]
            );
            assert_eq!(
                signed.signature_hex, signature_hex,
                "utf8 sign {}",
                case["id"]
            );
        }

        let actual = verify_utf8_message_ed25519(input, public_key_hex, signature_hex)
            .expect("verify utf8 case");
        assert_eq!(actual, expected_verify, "utf8 verify {}", case["id"]);
    }

    for case in fixture["json_cases"].as_array().expect("json_cases array") {
        let input = case["input_json"].as_str().expect("input_json");
        let canonical_json = case["canonical_json"].as_str().expect("canonical_json");
        let public_key_hex = case["public_key_hex"].as_str().expect("public_key_hex");
        let signature_hex = case["signature_hex"].as_str().expect("signature_hex");
        let expected_verify = case["expected_verify"].as_bool().expect("expected_verify");
        let seed_hex = case["signing_key_seed_hex"]
            .as_str()
            .unwrap_or(global_seed_hex);

        assert_eq!(
            canonicalize_json_str(input).expect("canonicalize json case"),
            canonical_json,
            "json canonical {}",
            case["id"]
        );

        if expected_verify {
            let signed = sign_json_str_ed25519(input, seed_hex).expect("sign json case");
            assert_eq!(
                signed.canonical_json, canonical_json,
                "json sign {}",
                case["id"]
            );
            assert_eq!(
                signed.public_key_hex, public_key_hex,
                "json sign {}",
                case["id"]
            );
            assert_eq!(
                signed.signature_hex, signature_hex,
                "json sign {}",
                case["id"]
            );
        }

        let actual = verify_json_str_signature_ed25519(input, public_key_hex, signature_hex)
            .expect("verify json case");
        assert_eq!(actual, expected_verify, "json verify {}", case["id"]);
    }
}

#[test]
fn capability_fixture_cases_round_trip_through_public_api() {
    // Read the on-disk corpus. The shared `expected` field is depth-agnostic so
    // cross-language consumers can compare against the same vectors. Cases with
    // depth-aware behavior carry an optional `max_delegation_depth` plus
    // `expected_with_max_delegation_depth` pair; this test asserts both branches when present.
    let raw = fs::read_to_string(capability_fixture_path()).expect("read capability fixture");
    let fixture: Value = serde_json::from_str(&raw).expect("parse capability fixture");
    for case in fixture["cases"].as_array().expect("cases array") {
        let capability: CapabilityToken =
            serde_json::from_value(case["capability"].clone()).expect("parse capability case");
        let verify_at = case["verify_at"].as_u64().expect("verify_at");
        let expected: CapabilityVerification =
            serde_json::from_value(case["expected"].clone()).expect("parse capability expectation");

        // Depth-agnostic verification: every consumer in the cross-language
        // matrix (chio-go, chio-py, chio-ts) runs this exact assertion.
        let actual_no_depth =
            verify_capability(&capability, verify_at, None).expect("verify capability case");
        assert_eq!(
            actual_no_depth, expected,
            "capability case {} (no max depth)",
            case["id"]
        );

        // Optional depth-aware branch: only Rust currently parameterizes
        // max_delegation_depth, so we gate on the presence of the per-case
        // override fields.
        if let Some(max_depth) = case
            .get("max_delegation_depth")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
        {
            let depth_expected_value = case
                .get("expected_with_max_delegation_depth")
                .cloned()
                .unwrap_or_else(|| case["expected"].clone());
            let depth_expected: CapabilityVerification =
                serde_json::from_value(depth_expected_value)
                    .expect("parse depth-aware capability expectation");
            let actual_with_depth = verify_capability(&capability, verify_at, Some(max_depth))
                .expect("verify capability case (max depth)");
            assert_eq!(
                actual_with_depth, depth_expected,
                "capability case {} (max_delegation_depth={})",
                case["id"], max_depth
            );
        }
    }
}

#[test]
fn manifest_fixture_cases_round_trip_through_public_api() {
    // Read the on-disk corpus as ground truth.
    let raw = std::fs::read_to_string(manifest_fixture_path()).expect("read manifest fixture");
    let fixture: Value = serde_json::from_str(&raw).expect("parse manifest fixture");
    for case in fixture["cases"].as_array().expect("cases array") {
        let signed_manifest: SignedManifest =
            serde_json::from_value(case["signed_manifest"].clone())
                .expect("parse signed manifest case");
        let expected: ManifestVerification =
            serde_json::from_value(case["expected"].clone()).expect("parse manifest expectation");
        let actual = verify_signed_manifest(&signed_manifest).expect("verify signed manifest case");
        assert_eq!(actual, expected, "manifest case {}", case["id"]);
    }
}

#[test]
#[ignore = "helper for regenerating checked-in vector fixtures during development"]
fn print_vector_fixtures_for_bootstrap() {
    println!("--- canonical fixture ---");
    println!("{}", pretty_json(&canonical_vector_fixture()));
    println!("--- hashing fixture ---");
    println!("{}", pretty_json(&hashing_vector_fixture()));
    println!("--- receipt fixture ---");
    println!("{}", pretty_json(&receipt_vector_fixture()));
    println!("--- signing fixture ---");
    println!("{}", pretty_json(&signing_vector_fixture()));
    println!("--- capability fixture ---");
    println!("{}", pretty_json(&capability_vector_fixture()));
    println!("--- manifest fixture ---");
    println!("{}", pretty_json(&manifest_vector_fixture()));
}
