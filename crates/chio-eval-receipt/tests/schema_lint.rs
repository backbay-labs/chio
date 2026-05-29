use std::error::Error;
use std::fs;
use std::path::PathBuf;

use chio_eval_receipt::verify_fixture_bundle;
use serde_json::Value;

#[test]
fn eval_receipt_schema_is_pinned() -> Result<(), Box<dyn Error>> {
    let schema_bytes =
        fs::read_to_string(workspace_root().join("spec/eval/receipt-format.v1.json"))?;
    let schema: Value = serde_json::from_str(&schema_bytes)?;

    assert_eq!(
        schema.get("$id").and_then(Value::as_str),
        Some("https://chio.world/spec/eval/receipt-format.v1.json")
    );
    assert_eq!(
        schema
            .get("properties")
            .and_then(Value::as_object)
            .and_then(|properties| properties.get("schema"))
            .and_then(|schema_property| schema_property.get("const"))
            .and_then(Value::as_str),
        Some("chio.eval-report.bundle.v1")
    );
    assert!(schema_bytes.contains("rfc8785"));
    Ok(())
}

#[test]
fn golden_eval_vector_verifies() -> Result<(), Box<dyn Error>> {
    let bundle_json =
        fs::read_to_string(workspace_root().join("tests/bindings/vectors/eval/v1.json"))?;
    let verified = verify_fixture_bundle(&bundle_json)?;

    assert_eq!(verified.bundle_id, "urn:chio:eval-bundle:metr:golden-v1");
    assert_eq!(verified.receipt_count, 3);
    assert_eq!(verified.signature_count, 1);
    Ok(())
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
