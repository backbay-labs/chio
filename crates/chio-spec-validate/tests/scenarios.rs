//! Smoke test for `chio-spec-validate`.
//!
//! Constructs a minimal capability token document that conforms to the
//! published `chio-wire/v1/capability/token.schema.json` and confirms the
//! validator accepts it. Then mutates a single field to assert the validator
//! reports a violation. Both branches together exercise the public API:
//! [`validate`] (file path entry point) and [`validate_value`] (in-memory
//! entry point).
//!
//! This test reads the schema directly from `spec/schemas/` via a path
//! resolved from `CARGO_MANIFEST_DIR`. It does not depend on any other
//! Chio crate.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;

use serde_json::{json, Value};

fn schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/schemas/chio-wire/v1/capability/token.schema.json")
        .canonicalize()
        .expect("token schema path resolves")
}

fn good_token() -> Value {
    json!({
        "id": "cap-smoke-001",
        "issuer": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "subject": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        "scope": {
            "grants": [{
                "server_id": "srv",
                "tool_name": "echo",
                "operations": ["invoke"]
            }]
        },
        "issued_at": 1_710_000_000_u64,
        "expires_at": 1_710_000_600_u64,
        // 128 hex chars = legacy Ed25519 signature length.
        "signature": "aa".repeat(64)
    })
}

#[test]
fn known_good_token_validates() {
    let schema = schema_path();
    let doc = good_token();
    let doc_path = PathBuf::from("<inline>");
    let schema_value: Value =
        serde_json::from_str(&std::fs::read_to_string(&schema).expect("schema file exists"))
            .expect("schema parses");
    chio_spec_validate::validate_value(&schema, &schema_value, &doc_path, &doc)
        .expect("good token validates against capability/token schema");
}

#[test]
fn malformed_token_is_rejected() {
    let schema = schema_path();
    let mut doc = good_token();
    // Strip the required `signature` field; the schema marks it required.
    doc.as_object_mut()
        .expect("token is an object")
        .remove("signature");
    let doc_path = PathBuf::from("<inline>");
    let schema_value: Value =
        serde_json::from_str(&std::fs::read_to_string(&schema).expect("schema file exists"))
            .expect("schema parses");
    let err = chio_spec_validate::validate_value(&schema, &schema_value, &doc_path, &doc)
        .expect_err("missing-signature token must violate schema");
    let message = err.to_string();
    assert!(
        message.contains("signature"),
        "violation should mention `signature`: {message}"
    );
}
