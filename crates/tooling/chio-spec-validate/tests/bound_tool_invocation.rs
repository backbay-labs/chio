//! Published schema checks for exact-capability and exact-argument approvals.

use std::path::PathBuf;

use serde_json::{json, Value};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-wire/v1/agent/governed-transaction-intent.schema.json")
}

fn bound_intent() -> Value {
    json!({
        "id": "intent-reviewed-1",
        "server_id": "files",
        "tool_name": "write_file",
        "purpose": "write the reviewed file",
        "body": {
            "kind": "bound_tool_invocation",
            "value": {
                "capability_id": "cap-reviewed-1",
                "parameters_hash": format!("0x{}", "ab".repeat(32))
            }
        }
    })
}

#[test]
fn bound_tool_invocation_schema_accepts_bound_and_legacy_intents() -> TestResult {
    let path = schema_path();
    let schema = chio_spec_validate::load_json(&path)?;
    let mut legacy = bound_intent();
    legacy
        .as_object_mut()
        .ok_or("intent is not an object")?
        .remove("body");
    let mut explicit_legacy = legacy.clone();
    explicit_legacy["body"] = json!({"kind": "tool_invocation"});
    for doc in [bound_intent(), legacy, explicit_legacy] {
        chio_spec_validate::validate_value(&path, &schema, &PathBuf::from("<inline>"), &doc)?;
    }
    Ok(())
}

#[test]
fn bound_tool_invocation_schema_rejects_missing_malformed_or_extra_bindings() -> TestResult {
    let path = schema_path();
    let schema = chio_spec_validate::load_json(&path)?;
    let good = bound_intent();
    let value = good["body"]["value"].clone();
    let invalid_values = [
        json!({"parameters_hash": value["parameters_hash"]}),
        json!({"capability_id": "cap-reviewed-1"}),
        json!({"capability_id": "", "parameters_hash": value["parameters_hash"]}),
        json!({"capability_id": 7, "parameters_hash": value["parameters_hash"]}),
        json!({"capability_id": "cap-reviewed-1", "parameters_hash": "0xabcd"}),
        json!({"capability_id": "cap-reviewed-1", "parameters_hash": "ab".repeat(32)}),
        json!({"capability_id": "cap-reviewed-1", "parameters_hash": format!("0x{}", "AB".repeat(32))}),
        json!({"capability_id": "cap-reviewed-1", "parameters_hash": value["parameters_hash"], "ignored": true}),
    ];
    for invalid_value in invalid_values {
        let mut doc = good.clone();
        doc["body"]["value"] = invalid_value;
        assert!(
            chio_spec_validate::validate_value(&path, &schema, &PathBuf::from("<inline>"), &doc)
                .is_err(),
            "accepted invalid bound intent: {doc}"
        );
    }
    Ok(())
}
